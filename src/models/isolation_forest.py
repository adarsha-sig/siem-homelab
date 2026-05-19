"""
Isolation Forest anomaly detector for Windows security events.

Security intuition: Isolation Forest works by randomly partitioning the feature
space with axis-aligned cuts. Normal events — which cluster together and share
common feature values — require many cuts to isolate. Attack events — which are
rare in one or more feature dimensions — are isolated in very few cuts. The
anomaly score is inversely proportional to the average path length across many
trees. This makes IF ideal for security data because it requires *no labels*
and handles high-dimensional, sparse feature spaces well.

Expected data flow:
  security-events-mordor  →  feature_engineering.py  →  IsolationForest
                                                      →  security-scores-if

Usage:
  python src/models/isolation_forest.py               # train and score all events
  python src/models/isolation_forest.py --dry-run     # score without ES writes
  python src/models/isolation_forest.py --verbose     # log top anomalies
  python src/models/isolation_forest.py --contamination 0.05
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

import numpy as np
import pandas as pd
from elasticsearch import Elasticsearch, helpers
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

# Make src/ importable when running from project root or inside the container.
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from src.models.feature_engineering import build_feature_matrix, FEATURE_NAMES

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)

ES_URL        = os.getenv("ELASTIC_URL", "http://localhost:9200")
SOURCE_INDEX  = "security-events-mordor"
SCORES_INDEX  = "security-scores-if"
MODELS_DIR    = Path(__file__).resolve().parents[2] / "data" / "models"
BULK_SIZE     = 500
MAX_EVENTS    = 50_000


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
                    "anomaly_score": {"type": "float"},
                    "is_anomaly":    {"type": "boolean"},
                    "model":         {"type": "keyword"},
                    "scored_at":     {"type": "date"},
                    "llm_triage":    {"type": "object", "enabled": False},
                }
            },
        }
    }
}


def ensure_source_exists(client: Elasticsearch) -> None:
    """
    Guard rail: refuse to train if the source index is missing.

    Per CLAUDE.md: never run model training without confirming the source index
    exists. Training on an empty or partial index produces a silently broken
    model whose anomaly scores have no meaning.
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
    """
    Stream all documents from the source index via the scan helper.

    We exclude '_raw' (the full NXLog event, stored but not indexed) from the
    fetch to keep network payload small — we only need the ECS fields for
    feature engineering.
    """
    log.info("Fetching events from %s (max=%d)...", SOURCE_INDEX, max_events)
    events = []
    for hit in helpers.scan(
        client,
        index=SOURCE_INDEX,
        _source_excludes=["_raw"],
        size=1000,
    ):
        events.append(hit)
        if len(events) >= max_events:
            break
    log.info("Fetched %d events", len(events))
    return events


# ── Model training ────────────────────────────────────────────────────────────

def train(
    X: np.ndarray,
    contamination: float = 0.05,
    n_estimators: int = 200,
    random_state: int = 42,
) -> tuple[IsolationForest, StandardScaler]:
    """
    Fit a StandardScaler then an IsolationForest on the feature matrix.

    Security intuition: StandardScaler centres and scales each feature to unit
    variance. Without it, high-magnitude features like cmd_len (0–4096) would
    dominate the random axis selection inside IF trees, effectively ignoring
    lower-magnitude signals like rarity scores (0–10). Scaling gives every
    feature an equal opportunity to drive splits.

    n_estimators=200 (vs sklearn default of 100) improves score stability for
    datasets with many near-duplicate events (e.g. repeated Sysmon EventID 10
    records from a single Mimikatz run).
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
    log.info(
        "Trained IsolationForest: %d trees, contamination=%.2f",
        n_estimators, contamination,
    )
    return model, scaler


def compute_scores(
    model: IsolationForest,
    scaler: StandardScaler,
    X: np.ndarray,
) -> tuple[np.ndarray, np.ndarray]:
    """
    Return (anomaly_score [0,1], is_anomaly bool array).

    score_samples() returns the mean path-length-based score; more negative
    means shorter path = easier to isolate = more anomalous. We flip and
    min-max normalise to [0,1] so higher = more suspicious, which is the
    intuitive direction for a SOC analyst.
    """
    X_scaled = scaler.transform(X)
    raw      = model.score_samples(X_scaled)
    lo, hi   = raw.min(), raw.max()
    scores   = 1.0 - (raw - lo) / (hi - lo + 1e-9)

    is_anomaly = model.predict(X_scaled) == -1
    return scores.astype(np.float32), is_anomaly


# ── Model persistence ─────────────────────────────────────────────────────────

def save_model(
    model: IsolationForest,
    scaler: StandardScaler,
    feature_names: list[str],
) -> Path:
    """
    Persist the fitted model and scaler to data/models/.

    Saving the scaler alongside the model is mandatory: applying a model to
    new data with a different scaler produces nonsense scores. They must be
    saved and loaded as a unit.
    """
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    path = MODELS_DIR / "isolation_forest.pkl"
    with open(path, "wb") as f:
        pickle.dump(
            {"model": model, "scaler": scaler, "feature_names": feature_names},
            f,
        )
    log.info("Model saved to %s", path)
    return path


def load_model(path: Path | None = None) -> tuple[IsolationForest, StandardScaler, list[str]]:
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
) -> dict:
    """Build the document to write to the scores index."""
    src = event.get("_source", {})
    # Copy ECS fields; drop _raw (large, already in source index).
    doc = {k: v for k, v in src.items() if k != "_raw"}
    doc["ml"] = {
        "anomaly_score": round(float(score), 6),
        "is_anomaly":    bool(is_anom),
        "model":         "isolation_forest_v1",
        "scored_at":     scored_at,
    }
    return doc


def write_scores(
    client: Elasticsearch,
    events: list[dict],
    scores: np.ndarray,
    is_anomaly: np.ndarray,
    dry_run: bool,
    verbose: bool,
) -> int:
    """
    Bulk-index scored events into the scores index.

    Design: we create new documents in security-scores-if rather than updating
    security-events-mordor. This preserves the immutability of the source index
    and lets multiple models write independent score sets simultaneously.
    """
    scored_at = datetime.now(timezone.utc).isoformat()
    total = 0

    if dry_run:
        # Print top 10 anomalies to stdout for inspection.
        ranked = sorted(
            zip(scores, is_anomaly, events),
            key=lambda t: t[0],
            reverse=True,
        )
        log.info("[DRY-RUN] Top 10 anomalies (not written to ES):")
        for rank, (sc, ia, ev) in enumerate(ranked[:10], 1):
            src = ev.get("_source", {})
            print(
                f"  #{rank:2d}  score={sc:.4f}  is_anomaly={ia}"
                f"  category={src.get('event', {}).get('category','?')}"
                f"  channel={src.get('event', {}).get('channel','?')}"
                f"  proc={src.get('process', {}).get('name','?')}"
                f"  dataset={src.get('source_dataset','?')}"
            )
        return len(events)

    def _actions():
        for ev, sc, ia in zip(events, scores, is_anomaly):
            yield {
                "_index":  SCORES_INDEX,
                "_source": _score_doc(ev, sc, ia, scored_at),
            }

    for ok, info in helpers.streaming_bulk(
        client, _actions(), chunk_size=BULK_SIZE, raise_on_error=False
    ):
        if not ok:
            log.warning("Write error: %s", info)
        else:
            total += 1
            if verbose and total % 5000 == 0:
                log.info("  … %d documents written", total)

    log.info("Wrote %d scored documents to %s", total, SCORES_INDEX)
    return total


# ── Main pipeline ─────────────────────────────────────────────────────────────

def run(
    dry_run: bool = False,
    verbose: bool = False,
    contamination: float = 0.05,
    max_events: int = MAX_EVENTS,
) -> dict:
    """
    Full training and scoring pipeline. Returns a summary dict.

    Importable by the scheduler and notebooks without triggering CLI parsing.
    """
    client = Elasticsearch(ES_URL)
    ensure_source_exists(client)

    if not dry_run:
        ensure_scores_index(client)

    # 1. Fetch
    events = fetch_events(client, max_events=max_events)
    if not events:
        log.error("No events fetched — aborting.")
        return {}

    # 2. Feature engineering
    log.info("Building feature matrix...")
    df = build_feature_matrix(events)
    X  = df.values.astype(np.float32)
    log.info("Feature matrix shape: %s", X.shape)

    # 3. Train
    model, scaler = train(X, contamination=contamination)

    # 4. Score
    scores, is_anomaly = compute_scores(model, scaler, X)
    n_flagged = int(is_anomaly.sum())
    log.info(
        "Scored %d events: %d flagged as anomalies (%.1f%%)",
        len(events), n_flagged, 100 * n_flagged / len(events),
    )

    # 5. Write or print
    written = write_scores(client, events, scores, is_anomaly, dry_run, verbose)

    # 6. Persist model (skip in dry-run)
    if not dry_run:
        save_model(model, scaler, FEATURE_NAMES)

    return {
        "events_scored":  len(events),
        "anomalies_found": n_flagged,
        "contamination":   contamination,
        "written":         written,
        "dry_run":         dry_run,
    }


# ── CLI ────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Train Isolation Forest on security events and write anomaly scores."
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Score events and print top anomalies; do not write to Elasticsearch.",
    )
    parser.add_argument(
        "--verbose", action="store_true",
        help="Log progress every 5,000 documents during ES writes.",
    )
    parser.add_argument(
        "--contamination", type=float, default=0.05, metavar="FLOAT",
        help="Fraction of events expected to be anomalous (default: 0.05).",
    )
    parser.add_argument(
        "--max-events", type=int, default=MAX_EVENTS, metavar="N",
        help=f"Maximum events to fetch from ES (default: {MAX_EVENTS}).",
    )
    args = parser.parse_args()

    summary = run(
        dry_run=args.dry_run,
        verbose=args.verbose,
        contamination=args.contamination,
        max_events=args.max_events,
    )
    if summary:
        print("\nSummary:")
        for k, v in summary.items():
            print(f"  {k}: {v}")
    sys.exit(0)


if __name__ == "__main__":
    main()
