"""
Unified model runner for the SOC ML Lab.

Dispatches to one of three backends via --model:
  if       — Isolation Forest (implemented; Phase 3/7)
  ae       — Autoencoder      (stub; planned for Phase 8)
  ensemble — IF + AE ensemble (stub; planned for Phase 9)

Subsumes isolation_forest.py. All public functions and CLI flags are
identical to isolation_forest.py so existing callers need only change
the import path.

New output fields added vs the old isolation_forest.py:
  ml.anomaly_percentile  — percentile rank within the scored batch (0–100)
  ml.top_features        — top 3 IF feature contributors (feature name + z-score)
  ml.routing_decision    — coarse triage routing: tier-1 | tier-2 | auto-close

Usage:
  python src/models/model_runner.py --model if               # full retrain
  python src/models/model_runner.py --model if --dry-run
  python src/models/model_runner.py --model if --score-only
  python src/models/model_runner.py --model if --score-only --since 2020-09-21T00:00:00Z
  python src/models/model_runner.py --model ae               # logs "not yet implemented"
  python src/models/model_runner.py --model ensemble         # logs "not yet implemented"
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import pickle
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

import numpy as np
import pandas as pd
from elasticsearch import Elasticsearch, helpers
from scipy.stats import rankdata
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from src.models.feature_engineering import build_feature_matrix, FEATURE_NAMES

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)

ES_URL          = os.getenv("ELASTIC_URL", "http://localhost:9200")
MLFLOW_URI      = os.getenv("MLFLOW_TRACKING_URI", "http://localhost:5000")
SOURCE_INDEX    = "security-events-mordor"
SCORES_INDEX    = "security-scores-if"
MODELS_DIR      = Path(__file__).resolve().parents[2] / "data" / "models"
PROCESSED_DIR   = Path(__file__).resolve().parents[2] / "data" / "processed"
RUNS_DIR        = Path(__file__).resolve().parents[2] / "data" / "runs"
BULK_SIZE       = 500
MAX_EVENTS      = 50_000
MLFLOW_EXPERIMENT = "soc_ml_lab"


# ── Index management ──────────────────────────────────────────────────────────

SCORES_MAPPING = {
    "mappings": {
        "properties": {
            "@timestamp":     {"type": "date"},
            "host":           {"properties": {"name": {"type": "keyword"}}},
            "user":           {"properties": {"name": {"type": "keyword"}}},
            "process": {
                "properties": {
                    "name":         {"type": "keyword"},
                    "command_line": {
                        "type": "text",
                        "fields": {"keyword": {"type": "keyword", "ignore_above": 2048}},
                    },
                    "parent": {"properties": {"name": {"type": "keyword"}}},
                }
            },
            "event": {
                "properties": {
                    "category": {"type": "keyword"},
                    "id":       {"type": "keyword"},
                    "channel":  {"type": "keyword"},
                }
            },
            "source_dataset": {"type": "keyword"},
            "ml": {
                "properties": {
                    "anomaly_score":       {"type": "float"},
                    "anomaly_percentile":  {"type": "float"},
                    "is_anomaly":          {"type": "boolean"},
                    "routing_decision":    {"type": "keyword"},
                    "model":               {"type": "keyword"},
                    "scored_at":           {"type": "date"},
                    "enriched":            {"type": "boolean"},
                    # Combined enrichment fields (written by alert_explainer.py)
                    "combined_confidence": {"type": "float"},
                    "llm_confidence":      {"type": "float"},
                    "if_llm_disagreement": {"type": "boolean"},
                    # stored but not indexed — use ml.enriched for queries
                    "llm_triage":          {"type": "object", "enabled": False},
                    # stored but not indexed — top feature list per event
                    "top_features":        {"type": "object", "enabled": False},
                }
            },
        }
    }
}


def ensure_source_exists(client: Elasticsearch) -> None:
    """
    Guard rail: refuse to train if the source index is missing.
    Per CLAUDE.md: never run model training without confirming the source
    index exists. Training on an empty index produces silently broken scores.
    """
    if not client.indices.exists(index=SOURCE_INDEX):
        raise RuntimeError(
            f"Source index '{SOURCE_INDEX}' does not exist. "
            "Run src/ingest/load_mordor.py first."
        )


def ensure_scores_index(client: Elasticsearch) -> None:
    """Create the scores index with ECS + ml field mappings if absent."""
    if not client.indices.exists(index=SCORES_INDEX):
        client.indices.create(index=SCORES_INDEX, body=SCORES_MAPPING)
        log.info("Created index: %s", SCORES_INDEX)


# ── Data fetching ─────────────────────────────────────────────────────────────

def fetch_events(client: Elasticsearch, max_events: int = MAX_EVENTS) -> list[dict]:
    """Stream all documents from the source index, excluding the large _raw field."""
    log.info("Fetching events from %s (max=%d)...", SOURCE_INDEX, max_events)
    events = []
    for hit in helpers.scan(
        client, index=SOURCE_INDEX, _source_excludes=["_raw"], size=1000,
    ):
        events.append(hit)
        if len(events) >= max_events:
            break
    log.info("Fetched %d events", len(events))
    return events


def fetch_new_events(
    client: Elasticsearch, since_iso: str, max_events: int = MAX_EVENTS,
) -> list[dict]:
    """
    Fetch only events with @timestamp strictly after since_iso.

    Security intuition: incremental scoring lets the pipeline process only
    the day's new telemetry without re-scoring the entire historical corpus.
    On a live stream this is what makes sub-minute scoring latency viable.
    """
    log.info("Fetching events newer than %s ...", since_iso)
    events = []
    for hit in helpers.scan(
        client,
        index=SOURCE_INDEX,
        query={"query": {"range": {"@timestamp": {"gt": since_iso}}}},
        _source_excludes=["_raw"],
        size=1000,
    ):
        events.append(hit)
        if len(events) >= max_events:
            break
    log.info("Fetched %d new events since %s", len(events), since_iso)
    return events


def get_last_retrain_time() -> Optional[str]:
    """
    Return completed_at from the most recent non-dry-run, error-free retrain audit file.

    Security intuition: the audit trail is the authoritative boundary for
    incremental scoring — it's tamper-evident at the filesystem level and
    skipping bad runs ensures we never advance the boundary past a failed retrain.
    """
    if not RUNS_DIR.exists():
        return None
    for f in sorted(RUNS_DIR.glob("retrain_*.json"), reverse=True):
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
            if not data.get("dry_run") and not data.get("errors") and data.get("completed_at"):
                return data["completed_at"]
        except Exception:
            continue
    return None


# ── MLflow helpers ────────────────────────────────────────────────────────────

def _feature_importance_plot(X_scaled: np.ndarray, feature_names: List[str]) -> Path:
    import matplotlib
    matplotlib.use("Agg")   # non-interactive; must precede pyplot import
    import matplotlib.pyplot as plt  # noqa: PLC0415
    """
    Save a horizontal bar chart of mean |z-score| per feature.

    Security intuition: mean |z-score| in the StandardScaler-transformed space
    indicates which features have the widest spread across events — i.e., which
    dimensions the IF trees use most for splitting. A feature with high mean
    |z-score| is a strong discriminator between normal and anomalous events.
    Tracking this plot across retrain runs in MLflow makes feature drift visible
    at a glance: if proc_rarity suddenly loses discriminative power, the corpus
    distribution has shifted and the model may need recalibration.
    """
    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    mean_abs_z = np.abs(X_scaled).mean(axis=0)
    order = np.argsort(mean_abs_z)

    fig, ax = plt.subplots(figsize=(8, 6))
    ax.barh(
        [feature_names[i] for i in order],
        mean_abs_z[order],
        color="steelblue",
        edgecolor="white",
    )
    ax.set_xlabel("Mean |z-score| across training events")
    ax.set_title("Feature Discriminative Power (IsolationForest training set)")
    fig.tight_layout()

    path = PROCESSED_DIR / "feature_importance.png"
    fig.savefig(path, dpi=100, bbox_inches="tight")
    plt.close(fig)
    return path


def _log_to_mlflow(
    params: dict,
    metrics: dict,
    tags: dict,
    model_path: Optional[Path],
    X_scaled: np.ndarray,
    dry_run: bool,
) -> None:
    """
    Best-effort MLflow logging — silently skips if the server is unreachable.

    All MLflow calls are wrapped in a single try/except so a down tracking
    server never blocks a retrain. The run is logged atomically inside
    mlflow.start_run() so a crash mid-log leaves a partial run (visible in
    the UI as 'FAILED') rather than corrupting the metric store.
    """
    try:
        import mlflow  # noqa: PLC0415 — lazy to keep module importable without mlflow
        mlflow.set_tracking_uri(MLFLOW_URI)
        mlflow.set_experiment(MLFLOW_EXPERIMENT)
        with mlflow.start_run():
            mlflow.log_params(params)
            mlflow.log_metrics(metrics)
            mlflow.set_tags(tags)
            if not dry_run and model_path and model_path.exists():
                mlflow.log_artifact(str(model_path), artifact_path="model")
                plot_path = _feature_importance_plot(X_scaled, FEATURE_NAMES)
                mlflow.log_artifact(str(plot_path), artifact_path="plots")
        log.info("MLflow run logged to %s (experiment: %s)", MLFLOW_URI, MLFLOW_EXPERIMENT)
    except Exception as exc:
        log.warning("MLflow logging skipped — server unreachable or error: %s", exc)


# ── IF-specific scoring helpers ───────────────────────────────────────────────

def _top_features_for_batch(
    X_scaled: np.ndarray,
    feature_names: List[str],
    k: int = 3,
) -> List[List[dict]]:
    """
    For each event return the k features with the largest absolute z-score.

    Security intuition: in a StandardScaler-transformed space, a feature's
    absolute z-score indicates how far it is from the training-set mean. For
    Isolation Forest, features with high absolute z-scores are the ones that
    cause early isolation — i.e., the primary drivers of the anomaly score.
    This is not SHAP but it's fast, interpretable, and directionally correct
    for tree-based isolation models.

    The signed z-score is preserved so analysts can see direction:
    positive = higher than baseline (e.g. unusually rare process),
    negative = lower than baseline (e.g. suspiciously short command line).
    """
    result = []
    for row in X_scaled:
        top_k_idx = np.argsort(np.abs(row))[-k:][::-1]
        result.append([
            {"feature": feature_names[i], "z_score": round(float(row[i]), 3)}
            for i in top_k_idx
        ])
    return result


def _routing_decision(score: float, is_anomaly: bool) -> str:
    """
    Map a score + anomaly flag to a coarse triage routing label.

    Security intuition: routing gives the dashboard and future automation a
    pre-computed field to filter on without re-applying the threshold at query
    time. Tier-1 = highest-confidence anomalies that warrant immediate analyst
    attention; tier-2 = worth reviewing but lower urgency; auto-close = scored
    below the anomaly threshold so no action needed.
    """
    if not is_anomaly:
        return "auto-close"
    return "tier-1" if score >= 0.8 else "tier-2"


# ── IF training and scoring ───────────────────────────────────────────────────

def train(
    X: np.ndarray,
    contamination: float = 0.05,
    n_estimators: int = 200,
    random_state: int = 42,
) -> tuple[IsolationForest, StandardScaler]:
    """
    Fit StandardScaler + IsolationForest on the feature matrix.

    Scaling is mandatory before IF: without it, high-magnitude features
    (cmd_len 0–4096) dominate random axis selection inside the trees, muting
    the lower-magnitude rarity signals (0–10) that carry the strongest security
    signal.
    """
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    model = IsolationForest(
        n_estimators=n_estimators,
        contamination=contamination,
        random_state=random_state,
        n_jobs=-1,
    )
    model.fit(X_scaled)
    log.info("Trained IsolationForest: %d trees, contamination=%.2f", n_estimators, contamination)
    return model, scaler


def compute_scores(
    model: IsolationForest,
    scaler: StandardScaler,
    X: np.ndarray,
) -> tuple[np.ndarray, np.ndarray, np.ndarray, List[List[dict]]]:
    """
    Return (anomaly_score, is_anomaly, anomaly_percentile, top_features).

    anomaly_score: min-max normalised to [0,1]; higher = more suspicious.
    anomaly_percentile: percentile rank within the scored batch (0–100).
      A percentile of 99 means this event is more anomalous than 99% of the batch.
    top_features: per-event list of top-3 feature z-scores driving the score.
    """
    X_scaled   = scaler.transform(X)
    raw        = model.score_samples(X_scaled)
    lo, hi     = raw.min(), raw.max()
    scores     = (1.0 - (raw - lo) / (hi - lo + 1e-9)).astype(np.float32)
    is_anomaly = model.predict(X_scaled) == -1

    percentiles  = (rankdata(scores, method="average") / len(scores) * 100).astype(np.float32)
    top_features = _top_features_for_batch(X_scaled, FEATURE_NAMES)

    return scores, is_anomaly, percentiles, top_features


# ── Model persistence ─────────────────────────────────────────────────────────

def save_model(
    model: IsolationForest, scaler: StandardScaler, feature_names: List[str],
) -> Path:
    """
    Save model + scaler as a bundle. They must always be loaded together —
    a scaler fitted on different data produces nonsense transformed features.
    """
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    path = MODELS_DIR / "isolation_forest.pkl"
    with open(path, "wb") as f:
        pickle.dump({"model": model, "scaler": scaler, "feature_names": feature_names}, f)
    log.info("Model saved to %s", path)
    return path


def load_model(path: Optional[Path] = None) -> tuple[IsolationForest, StandardScaler, List[str]]:
    """Load a previously saved model bundle."""
    if path is None:
        path = MODELS_DIR / "isolation_forest.pkl"
    with open(path, "rb") as f:
        bundle = pickle.load(f)
    return bundle["model"], bundle["scaler"], bundle["feature_names"]


# ── ES write ──────────────────────────────────────────────────────────────────

def _score_doc(
    event: dict,
    score: float,
    is_anom: bool,
    scored_at: str,
    percentile: Optional[float] = None,
    top_feats: Optional[List[dict]] = None,
) -> dict:
    """Assemble the document to write to the scores index."""
    src = event.get("_source", {})
    doc = {k: v for k, v in src.items() if k != "_raw"}
    ml: dict = {
        "anomaly_score":    round(float(score), 6),
        "is_anomaly":       bool(is_anom),
        "routing_decision": _routing_decision(float(score), bool(is_anom)),
        "model":            "isolation_forest_v1",
        "scored_at":        scored_at,
    }
    if percentile is not None:
        ml["anomaly_percentile"] = round(float(percentile), 2)
    if top_feats is not None:
        ml["top_features"] = top_feats
    doc["ml"] = ml
    return doc


def write_scores(
    client: Elasticsearch,
    events: list[dict],
    scores: np.ndarray,
    is_anomaly: np.ndarray,
    dry_run: bool,
    verbose: bool,
    percentiles: Optional[np.ndarray] = None,
    top_features: Optional[List[List[dict]]] = None,
) -> int:
    """
    Bulk-index scored events into the scores index.
    Creates new documents so the immutable source index is never touched.
    Returns count of successfully written documents (0 in dry-run).
    """
    scored_at = datetime.now(timezone.utc).isoformat()

    if dry_run:
        ranked = sorted(
            zip(scores, is_anomaly, events), key=lambda t: t[0], reverse=True,
        )
        log.info("[DRY-RUN] Top 10 anomalies (not written to ES):")
        for rank, (sc, ia, ev) in enumerate(ranked[:10], 1):
            src = ev.get("_source", {})
            print(
                f"  #{rank:2d}  score={sc:.4f}  is_anomaly={ia}"
                f"  category={src.get('event', {}).get('category','?')}"
                f"  proc={src.get('process', {}).get('name','?')}"
                f"  dataset={src.get('source_dataset','?')}"
            )
        return 0   # dry-run wrote nothing

    _pcts = percentiles if percentiles is not None else [None] * len(events)
    _tops = top_features if top_features is not None else [None] * len(events)

    def _actions():
        for ev, sc, ia, pct, tf in zip(events, scores, is_anomaly, _pcts, _tops):
            yield {
                "_index":  SCORES_INDEX,
                "_source": _score_doc(ev, sc, ia, scored_at, pct, tf),
            }

    total = 0
    for ok, info in helpers.streaming_bulk(
        client, _actions(), chunk_size=BULK_SIZE, raise_on_error=False,
    ):
        if not ok:
            log.warning("Write error: %s", info)
        else:
            total += 1
            if verbose and total % 5000 == 0:
                log.info("  … %d documents written", total)

    log.info("Wrote %d scored documents to %s", total, SCORES_INDEX)
    return total


# ── Model backends ────────────────────────────────────────────────────────────

def _run_if(
    dry_run: bool,
    verbose: bool,
    contamination: float,
    max_events: int,
    score_only: bool,
    since: Optional[str],
) -> dict:
    """
    Isolation Forest pipeline — full retrain or incremental score-only mode.

    score_only=True: load saved model, fetch events after `since`, score without
    retraining. Completes in seconds vs minutes for a full retrain.
    score_only=False: full fetch → feature engineering → train → score → save.
    """
    # ── Score-only path ──────────────────────────────────────────────────────
    if score_only:
        model_path = MODELS_DIR / "isolation_forest.pkl"
        if not model_path.exists():
            raise RuntimeError(
                f"No saved model at {model_path}. "
                "Run without --score-only first to train and save a model."
            )
        model, scaler, _ = load_model(model_path)

        effective_since = since or get_last_retrain_time()
        if not effective_since:
            raise RuntimeError(
                "Cannot determine the scoring window: no --since provided and "
                "no successful retrain found in data/runs/. "
                "Run a full retrain first, or pass --since ISO_TIMESTAMP."
            )

        client = Elasticsearch(ES_URL)
        ensure_source_exists(client)
        if not dry_run:
            ensure_scores_index(client)

        events = fetch_new_events(client, effective_since, max_events=max_events)
        if not events:
            log.info("No new events since %s — nothing to score.", effective_since)
            return {"events_scored": 0, "anomalies_found": 0,
                    "since": effective_since, "score_only": True, "dry_run": dry_run}

        df = build_feature_matrix(events)
        X  = df.values.astype(np.float32)
        scores, is_anomaly, percentiles, top_features = compute_scores(model, scaler, X)
        n_flagged = int(is_anomaly.sum())
        log.info("Score-only: %d events, %d anomalies (%.1f%%)",
                 len(events), n_flagged, 100 * n_flagged / max(len(events), 1))
        written = write_scores(client, events, scores, is_anomaly, dry_run, verbose,
                               percentiles, top_features)
        return {"events_scored": len(events), "anomalies_found": n_flagged,
                "since": effective_since, "written": written,
                "score_only": True, "dry_run": dry_run}

    # ── Full retrain path ────────────────────────────────────────────────────
    client = Elasticsearch(ES_URL)
    ensure_source_exists(client)
    if not dry_run:
        ensure_scores_index(client)

    events = fetch_events(client, max_events=max_events)
    if not events:
        log.error("No events fetched — aborting.")
        return {}

    log.info("Building feature matrix...")
    df = build_feature_matrix(events)
    X  = df.values.astype(np.float32)
    log.info("Feature matrix shape: %s", X.shape)

    # Persist reference feature matrix for Evidently drift monitoring.
    # Evidently compares this training snapshot against future event windows
    # to detect when the feature distribution shifts away from the training baseline.
    if not dry_run:
        PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
        with open(PROCESSED_DIR / "train_features.pkl", "wb") as f:
            pickle.dump(df, f)
        log.info("Training feature matrix saved to data/processed/train_features.pkl")

    n_estimators = 200
    model, scaler = train(X, contamination=contamination, n_estimators=n_estimators)
    scores, is_anomaly, percentiles, top_features = compute_scores(model, scaler, X)
    X_scaled = scaler.transform(X)   # needed for feature importance plot
    n_flagged = int(is_anomaly.sum())
    log.info("Scored %d events: %d anomalies (%.1f%%)",
             len(events), n_flagged, 100 * n_flagged / len(events))

    written = write_scores(client, events, scores, is_anomaly, dry_run, verbose,
                           percentiles, top_features)
    model_path = None
    if not dry_run:
        model_path = save_model(model, scaler, FEATURE_NAMES)

    # Log run to MLflow. Best-effort — does not block or fail the pipeline.
    _log_to_mlflow(
        params={
            "model_type":    "isolation_forest",
            "contamination": contamination,
            "n_estimators":  n_estimators,
            "feature_names": json.dumps(FEATURE_NAMES),
        },
        metrics={
            "anomaly_count": n_flagged,
            "anomaly_rate":  round(n_flagged / len(events), 4),
            "top_score":     float(scores.max()),
            "score_p95":     float(np.percentile(scores, 95)),
        },
        tags={
            "dataset":         SOURCE_INDEX,
            "event_count":     str(len(events)),
            "score_threshold": str(contamination),
        },
        model_path=model_path,
        X_scaled=X_scaled,
        dry_run=dry_run,
    )

    return {"events_scored": len(events), "anomalies_found": n_flagged,
            "contamination": contamination, "written": written,
            "score_only": False, "dry_run": dry_run}


def _run_ae(**kwargs) -> dict:
    """Autoencoder anomaly detector — planned for Phase 8."""
    log.info("AE model not yet implemented — exiting cleanly.")
    return {"status": "not_implemented", "model": "ae"}


def _run_ensemble(**kwargs) -> dict:
    """IF + AE ensemble scorer — planned for Phase 9."""
    log.info("Ensemble model not yet implemented — exiting cleanly.")
    return {"status": "not_implemented", "model": "ensemble"}


# ── Public dispatcher ─────────────────────────────────────────────────────────

def run(
    model: str = "if",
    dry_run: bool = False,
    verbose: bool = False,
    contamination: float = 0.05,
    max_events: int = MAX_EVENTS,
    score_only: bool = False,
    since: Optional[str] = None,
) -> dict:
    """
    Dispatch to the requested model backend. Importable by the scheduler
    and notebooks without triggering CLI argument parsing.
    """
    backends = {"if": _run_if, "ae": _run_ae, "ensemble": _run_ensemble}
    if model not in backends:
        raise ValueError(f"Unknown model '{model}'. Choose from: {list(backends)}")

    if model == "if":
        return _run_if(
            dry_run=dry_run, verbose=verbose, contamination=contamination,
            max_events=max_events, score_only=score_only, since=since,
        )
    return backends[model](dry_run=dry_run, verbose=verbose)


# ── CLI ────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="SOC ML Lab model runner — train and score anomaly detectors."
    )
    parser.add_argument(
        "--model", choices=["if", "ae", "ensemble"], default="if",
        help="Model backend: if (Isolation Forest), ae (Autoencoder stub), "
             "ensemble (IF+AE stub). Default: if.",
    )
    parser.add_argument("--dry-run", action="store_true",
                        help="Preview without writing to Elasticsearch.")
    parser.add_argument("--verbose", action="store_true",
                        help="Log progress every 5,000 documents.")
    parser.add_argument("--contamination", type=float, default=0.05, metavar="FLOAT",
                        help="Expected anomaly fraction (IF only, default 0.05).")
    parser.add_argument("--max-events", type=int, default=MAX_EVENTS, metavar="N",
                        help=f"Max events to fetch (default {MAX_EVENTS}).")
    parser.add_argument("--score-only", action="store_true",
                        help="Load saved IF model and score new events only — no retraining.")
    parser.add_argument("--since", metavar="ISO_TIMESTAMP",
                        help="Score only events after this timestamp (score-only mode).")
    args = parser.parse_args()

    summary = run(
        model=args.model,
        dry_run=args.dry_run,
        verbose=args.verbose,
        contamination=args.contamination,
        max_events=args.max_events,
        score_only=args.score_only,
        since=args.since,
    )
    if summary:
        print("\nSummary:")
        for k, v in summary.items():
            print(f"  {k}: {v}")
    sys.exit(0)


if __name__ == "__main__":
    main()
