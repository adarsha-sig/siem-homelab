"""
Nightly retrain and enrichment jobs for the SOC ML Lab.

This script runs ONE job then exits. Scheduling is handled externally by the
soc_cron container (mcuadros/ofelia) defined in docker-compose.yml — no
APScheduler or long-running daemon here. Each invocation is a clean process
with no persistent state, which makes it trivial to test, restart, and audit.

Jobs:
  retrain  — Retrain the Isolation Forest on all indexed events, score, save
             model, and write a JSON audit record to data/runs/.
  enrich   — LLM enrichment sweep: enrich up to N unenriched anomalies.

Usage:
  python src/scheduler/nightly_retrain.py --run-now retrain
  python src/scheduler/nightly_retrain.py --run-now enrich
  python src/scheduler/nightly_retrain.py --run-now all
  python src/scheduler/nightly_retrain.py --run-now retrain --dry-run
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import traceback
from datetime import datetime, timezone
from pathlib import Path

# Configure logging before any src/ imports so that model_runner.py's
# module-level logging.basicConfig() call is a no-op (handlers already set).
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

RUNS_DIR     = Path(__file__).resolve().parents[2] / "data" / "runs"
ENRICH_LIMIT = 100        # alerts enriched per weekly sweep
ENRICH_MODEL = os.getenv("ENRICH_MODEL", "llama3.2:3b")


# ── Audit trail ───────────────────────────────────────────────────────────────

def write_run_summary(summary: dict) -> Path:
    """
    Persist a run summary dict to data/runs/ as a timestamped JSON file.

    Security intuition: the audit trail answers the questions a security
    manager will ask after an incident: "When did the model last retrain?
    What data did it train on? Were there any errors?" Each file is
    immutable once written — never updated in place — so the trail is
    tamper-evident at the filesystem level.
    """
    RUNS_DIR.mkdir(parents=True, exist_ok=True)
    run_id   = summary.get("run_id", datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S"))
    job_type = summary.get("job_type", "unknown")
    path     = RUNS_DIR / f"{job_type}_{run_id}.json"
    with open(path, "w") as f:
        json.dump(summary, f, indent=2, default=str)
    log.info("Run summary written to %s", path)
    return path


def _build_summary(
    job_type: str,
    started_at: datetime,
    result: dict,
    errors: list[str],
    dry_run: bool,
) -> dict:
    """Assemble a run summary dict with timing, result, and metadata."""
    completed_at = datetime.now(timezone.utc)
    return {
        "run_id":           started_at.strftime("%Y%m%d_%H%M%S"),
        "job_type":         job_type,
        "started_at":       started_at.isoformat(),
        "completed_at":     completed_at.isoformat(),
        "duration_seconds": round((completed_at - started_at).total_seconds(), 2),
        "dry_run":          dry_run,
        "result":           result,
        "errors":           errors,
    }


# ── Job: nightly retrain ──────────────────────────────────────────────────────

def run_retrain(dry_run: bool = False, verbose: bool = False) -> dict:
    """
    Retrain the Isolation Forest on all indexed events and re-score.

    Security intuition: retraining daily means the frequency tables that
    drive rarity scores reflect the current event distribution. A process
    that was rare last week may become common after a software deployment,
    and the model needs to learn that to avoid alert fatigue.

    Note on window_days: SPEC says 'fetch 7-day window'. For the Mordor
    historical dataset all events are from 2020, so a time filter would
    return nothing. model_runner.run() fetches all indexed events.
    In a production deployment with a live log stream, add a date-range
    filter to fetch_events() here.
    """
    log.info("=== Retrain job started (dry_run=%s) ===", dry_run)
    started_at = datetime.now(timezone.utc)
    errors: list[str] = []
    result: dict = {}

    try:
        from src.models.model_runner import run as model_run
        result = model_run(model="if", dry_run=dry_run, verbose=verbose)
    except Exception:
        msg = traceback.format_exc()
        log.error("Retrain failed:\n%s", msg)
        errors.append(msg)

    summary = _build_summary("retrain", started_at, result, errors, dry_run)
    path    = write_run_summary(summary)
    summary["summary_path"] = str(path)

    log.info(
        "=== Retrain job complete — %d events, %d anomalies, %d errors ===",
        result.get("events_scored", 0),
        result.get("anomalies_found", 0),
        len(errors),
    )
    return summary


# ── Job: weekly enrichment sweep ──────────────────────────────────────────────

def run_enrichment_sweep(
    dry_run: bool = False,
    verbose: bool = False,
    limit: int = ENRICH_LIMIT,
    model: str = ENRICH_MODEL,
) -> dict:
    """
    Enrich up to `limit` unenriched anomalies with LLM triage.

    Security intuition: CPU-bound LLM inference on a home-lab VM is slow
    (~6 min/alert without GPU). Running a capped sweep weekly rather than
    nightly ensures the enrichment never blocks the faster retrain job and
    gives the Ollama service time to process each alert at full quality.
    Anomalies are sorted by ml.anomaly_score descending, so the highest-
    confidence findings are always enriched first regardless of sweep size.
    """
    log.info(
        "=== Enrichment sweep started (dry_run=%s, limit=%d, model=%s) ===",
        dry_run, limit, model,
    )
    started_at = datetime.now(timezone.utc)
    errors: list[str] = []
    result: dict = {}

    try:
        from src.enrichment.alert_explainer import run as enrich_run
        result = enrich_run(dry_run=dry_run, verbose=verbose, limit=limit, model=model)
    except Exception:
        msg = traceback.format_exc()
        log.error("Enrichment sweep failed:\n%s", msg)
        errors.append(msg)

    summary = _build_summary("enrichment", started_at, result, errors, dry_run)
    path    = write_run_summary(summary)
    summary["summary_path"] = str(path)

    log.info(
        "=== Enrichment sweep complete — %d processed, %d succeeded, %d errors ===",
        result.get("processed", 0),
        result.get("succeeded", 0),
        len(errors),
    )
    return summary


# ── CLI ────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Run a single SOC ML Lab job then exit. "
            "Scheduling is handled by the soc_cron container (ofelia) in docker-compose.yml."
        )
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Run the pipeline but skip ES writes and model saves. "
             "The JSON audit file IS written so you can verify the format.",
    )
    parser.add_argument(
        "--verbose", action="store_true",
        help="Pass --verbose to sub-jobs.",
    )
    parser.add_argument(
        "--run-now",
        choices=["retrain", "enrich", "all"],
        default="retrain",
        metavar="JOB",
        help="Job to run: retrain, enrich, or all (default: retrain).",
    )
    parser.add_argument(
        "--enrich-limit", type=int, default=ENRICH_LIMIT, metavar="N",
        help=f"Max alerts to enrich per sweep (default: {ENRICH_LIMIT}).",
    )
    parser.add_argument(
        "--enrich-model", default=ENRICH_MODEL, metavar="NAME",
        help=f"Ollama model for enrichment (default: {ENRICH_MODEL}).",
    )
    args = parser.parse_args()

    if args.run_now in ("retrain", "all"):
        summary = run_retrain(dry_run=args.dry_run, verbose=args.verbose)
        print(json.dumps(summary, indent=2, default=str))
    if args.run_now in ("enrich", "all"):
        summary = run_enrichment_sweep(
            dry_run=args.dry_run,
            verbose=args.verbose,
            limit=args.enrich_limit,
            model=args.enrich_model,
        )
        print(json.dumps(summary, indent=2, default=str))

    sys.exit(0)


if __name__ == "__main__":
    main()
