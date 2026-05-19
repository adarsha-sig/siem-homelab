"""
Background scheduler — runs ingest and scoring jobs on fixed intervals.
Start with: python src/scheduler/scheduler.py
"""

import sys
from pathlib import Path

from apscheduler.schedulers.blocking import BlockingScheduler
from apscheduler.triggers.interval import IntervalTrigger
from loguru import logger

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

DATA_DIR = Path(__file__).resolve().parents[2] / "data"
LOG_GLOB = "*.log"


def job_ingest():
    from src.ingest.ingest import ingest_file
    files = list(DATA_DIR.glob(LOG_GLOB))
    if not files:
        logger.info("No log files found in data/ — skipping ingest")
        return
    for f in files:
        try:
            ingest_file(f)
        except Exception as exc:
            logger.error(f"Ingest failed for {f.name}: {exc}")


def job_score():
    from src.models.anomaly import run as score_run
    try:
        score_run(hours=1)
    except Exception as exc:
        logger.error(f"Scoring job failed: {exc}")


def main():
    scheduler = BlockingScheduler(timezone="UTC")

    scheduler.add_job(
        job_ingest,
        trigger=IntervalTrigger(minutes=5),
        id="ingest",
        name="Log ingest sweep",
        replace_existing=True,
    )
    scheduler.add_job(
        job_score,
        trigger=IntervalTrigger(minutes=15),
        id="score",
        name="Anomaly scoring",
        replace_existing=True,
    )

    logger.info("Scheduler started — ingest every 5 min, scoring every 15 min")
    try:
        scheduler.start()
    except (KeyboardInterrupt, SystemExit):
        logger.info("Scheduler stopped")


if __name__ == "__main__":
    main()
