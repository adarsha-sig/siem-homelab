"""
Nightly retrain scheduler for the SOC ML Lab.

Runs two recurring jobs:
  • Daily at 02:00 UTC   — retrain the Isolation Forest, re-score all events,
                           save the model, write a JSON audit record.
  • Weekly on Sunday 03:00 UTC — LLM enrichment sweep (enrich any anomaly
                           that does not yet have ml.llm_triage).

Security intuition: retraining nightly keeps the anomaly baseline current.
As new log sources are ingested the feature frequency tables shift, so a model
trained last week may score today's events incorrectly. The weekly enrichment
sweep ensures that every flagged alert eventually gets an ATT&CK mapping and
investigation steps, even when the CPU-bound LLM inference lags behind
real-time alert volume.

Usage:
  python src/scheduler/nightly_retrain.py                    # start scheduler (blocking)
  python src/scheduler/nightly_retrain.py --dry-run          # scheduler + dry-run jobs
  python src/scheduler/nightly_retrain.py --run-now retrain  # fire retrain immediately
  python src/scheduler/nightly_retrain.py --run-now enrich   # fire enrichment immediately
  python src/scheduler/nightly_retrain.py --run-now all      # fire both immediately
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

# Configure logging before any src/ imports so that isolation_forest.py's
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
    return nothing. isolation_forest.run() fetches all indexed events.
    In a production deployment with a live log stream, add a date-range
    filter to fetch_events() here.
    """
    log.info("=== Retrain job started (dry_run=%s) ===", dry_run)
    started_at = datetime.now(timezone.utc)
    errors: list[str] = []
    result: dict = {}

    try:
        from src.models.isolation_forest import run as if_run
        result = if_run(dry_run=dry_run, verbose=verbose)
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


# ── Scheduler setup ───────────────────────────────────────────────────────────

def start_scheduler(dry_run: bool = False, verbose: bool = False) -> None:
    """
    Start the blocking APScheduler with cron triggers for both jobs.

    The scheduler runs in the foreground so Docker can manage it as a
    container process and capture all log output via docker compose logs.
    Both jobs are also fired once at startup so the operator can verify
    they work without waiting until 02:00 UTC.
    """
    from apscheduler.schedulers.blocking import BlockingScheduler
    from apscheduler.triggers.cron import CronTrigger

    scheduler = BlockingScheduler(timezone="UTC")

    scheduler.add_job(
        run_retrain,
        trigger=CronTrigger(hour=2, minute=0),
        kwargs={"dry_run": dry_run, "verbose": verbose},
        id="nightly_retrain",
        name="Nightly IF retrain + scoring",
        replace_existing=True,
        misfire_grace_time=3600,    # tolerate up to 1 h clock drift
    )
    scheduler.add_job(
        run_enrichment_sweep,
        trigger=CronTrigger(day_of_week="sun", hour=3, minute=0),
        kwargs={"dry_run": dry_run, "verbose": verbose,
                "limit": ENRICH_LIMIT, "model": ENRICH_MODEL},
        id="weekly_enrichment",
        name="Weekly LLM enrichment sweep",
        replace_existing=True,
        misfire_grace_time=7200,
    )

    log.info(
        "Scheduler started — retrain daily@02:00 UTC, "
        "enrichment weekly Sun@03:00 UTC (dry_run=%s)",
        dry_run,
    )
    try:
        scheduler.start()
    except (KeyboardInterrupt, SystemExit):
        log.info("Scheduler stopped.")


# ── CLI ────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="SOC ML Lab nightly retrain and enrichment scheduler."
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Run the full pipeline but skip ES writes and model saves. "
             "The JSON audit file IS written so you can verify the format.",
    )
    parser.add_argument(
        "--verbose", action="store_true",
        help="Pass --verbose to retrain and enrichment sub-jobs.",
    )
    parser.add_argument(
        "--run-now",
        choices=["retrain", "enrich", "all"],
        metavar="JOB",
        help="Fire a job immediately instead of waiting for the cron schedule. "
             "Choices: retrain, enrich, all.",
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

    if args.run_now:
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
    else:
        start_scheduler(dry_run=args.dry_run, verbose=args.verbose)

    sys.exit(0)


if __name__ == "__main__":
    main()
