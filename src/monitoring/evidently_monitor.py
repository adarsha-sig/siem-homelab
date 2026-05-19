"""
Data drift and quality monitor for the SOC ML Lab feature matrix.

Security intuition: ML anomaly detectors trained on historical data silently
degrade when the event distribution shifts — new software deployments introduce
process names that were rare in training but are now common, making them look
anomalous when they are actually benign. This monitor detects that shift before
it causes analyst fatigue (too many false positives) or silent misses (the model
stops flagging real attacks because the baseline has drifted).

Two checks:
  1. DataDriftPreset — did any feature's distribution shift vs the training set?
  2. DataQualityPreset — are there missing values, constant columns, or outliers?

Test suite (exits 1 on failure):
  - FAIL if more than 3 features drift simultaneously (likely a corpus shift)
  - FAIL if current event volume is <70% of the training set volume (possible
    data loss or pipeline interruption masking as normal behaviour)

Usage:
  python src/monitoring/evidently_monitor.py                    # last 7 days vs training
  python src/monitoring/evidently_monitor.py --dry-run          # report without saving HTML
  python src/monitoring/evidently_monitor.py --since 2020-09-20T00:00:00Z
  python src/monitoring/evidently_monitor.py --verbose
"""

from __future__ import annotations

import argparse
import logging
import os
import pickle
import sys
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
from elasticsearch import Elasticsearch, helpers

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from src.models.feature_engineering import build_feature_matrix, FEATURE_NAMES

ES_URL         = os.getenv("ELASTIC_URL", "http://localhost:9200")
SOURCE_INDEX   = "security-events-mordor"
PROCESSED_DIR  = Path(__file__).resolve().parents[2] / "data" / "processed"
RUNS_DIR       = Path(__file__).resolve().parents[2] / "data" / "runs"

# Drift test thresholds
MAX_DRIFTED_FEATURES  = 3     # fail if more than this many features drift
MIN_VOLUME_FRACTION   = 0.70  # fail if current volume < 70% of reference


# ── Data loading ──────────────────────────────────────────────────────────────

def load_reference() -> pd.DataFrame:
    """
    Load the training feature matrix saved by model_runner.py.

    This is the reference distribution — what 'normal' looked like when the
    model was trained. Evidently compares the current feature distribution
    against this baseline to detect drift.
    """
    ref_path = PROCESSED_DIR / "train_features.pkl"
    if not ref_path.exists():
        raise FileNotFoundError(
            f"Reference features not found at {ref_path}. "
            "Run model_runner.py --model if first to generate the training snapshot."
        )
    with open(ref_path, "rb") as f:
        df = pickle.load(f)
    log.info("Loaded reference: %d rows × %d features", len(df), len(df.columns))
    return df


def fetch_current_events(since_iso: str, max_events: int = 50_000) -> list[dict]:
    """
    Fetch events from ES after since_iso as the 'current' distribution window.

    Security intuition: 7-day windows are the standard operational cadence —
    long enough to smooth daily noise, short enough to catch a deployment that
    changed the event mix last Tuesday. The since_iso boundary makes this
    testable with historical datasets (e.g. Mordor) by passing an explicit date.
    """
    client = Elasticsearch(ES_URL)
    log.info("Fetching current events since %s ...", since_iso)
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
    log.info("Fetched %d current events", len(events))
    return events


# ── Report and tests ──────────────────────────────────────────────────────────

def run_evidently(
    reference_df: pd.DataFrame,
    current_df: pd.DataFrame,
    dry_run: bool,
    verbose: bool,
) -> bool:
    """
    Run DataDriftPreset + DataQualityPreset and the failure-condition TestSuite.

    Returns True if all tests pass, False if any test fails.
    Saves an HTML report to data/runs/drift_YYYY-MM-DD.html (skipped in dry-run).
    """
    try:
        from evidently import ColumnMapping
        from evidently.metric_preset import DataDriftPreset, DataQualityPreset
        from evidently.report import Report
        from evidently.test_suite import TestSuite
        from evidently.tests import TestNumberOfDriftedColumns, TestNumberOfRows
    except ImportError:
        log.error("Evidently is not installed. Run: pip install evidently")
        sys.exit(1)

    # All features are numerical — no target, no categorical columns.
    column_mapping = ColumnMapping(
        numerical_features=FEATURE_NAMES,
        categorical_features=[],
        target=None,
    )

    # ── Full visual report ────────────────────────────────────────────────────
    report = Report(metrics=[DataDriftPreset(), DataQualityPreset()])
    report.run(
        reference_data=reference_df[FEATURE_NAMES],
        current_data=current_df[FEATURE_NAMES],
        column_mapping=column_mapping,
    )

    if not dry_run:
        RUNS_DIR.mkdir(parents=True, exist_ok=True)
        html_path = RUNS_DIR / f"drift_{datetime.now().strftime('%Y-%m-%d')}.html"
        report.save_html(str(html_path))
        log.info("HTML report saved to %s", html_path)
    else:
        log.info("[DRY-RUN] HTML report not saved.")

    if verbose:
        summary = report.as_dict()
        drift_metrics = [
            m for m in summary.get("metrics", [])
            if "drift" in m.get("metric", "").lower()
        ]
        log.info("Drift metrics summary:")
        for m in drift_metrics[:10]:
            log.info("  %s", m)

    # ── Test suite — failure conditions ───────────────────────────────────────
    min_rows = int(len(reference_df) * MIN_VOLUME_FRACTION)

    test_suite = TestSuite(tests=[
        # Security intuition: >3 drifting features simultaneously suggests a
        # corpus shift (e.g. new logging infrastructure, OS upgrade) rather than
        # isolated noise. Single-feature drift is expected and acceptable.
        TestNumberOfDriftedColumns(lte=MAX_DRIFTED_FEATURES),

        # Volume drop > 30% suggests the ingest pipeline is broken or a data
        # source went silent — a silent failure that the anomaly model would
        # mistake for "nothing interesting happened today".
        TestNumberOfRows(gte=min_rows),
    ])
    test_suite.run(
        reference_data=reference_df[FEATURE_NAMES],
        current_data=current_df[FEATURE_NAMES],
        column_mapping=column_mapping,
    )

    results  = test_suite.as_dict()
    passed   = results["summary"]["all_passed"]
    n_pass   = results["summary"]["success_tests"]
    n_fail   = results["summary"]["failed_tests"]

    log.info(
        "TestSuite: %d passed, %d failed — overall %s",
        n_pass, n_fail, "PASS ✓" if passed else "FAIL ✗",
    )
    if not passed:
        for test in results.get("tests", []):
            if test.get("status") == "FAIL":
                log.warning("  FAIL: %s — %s", test.get("name"), test.get("description"))

    return passed


# ── CLI ────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Data drift and quality monitor for the SOC ML Lab feature matrix."
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Run analysis but do not save the HTML report.",
    )
    parser.add_argument(
        "--verbose", action="store_true",
        help="Print detailed drift metric summaries.",
    )
    parser.add_argument(
        "--since", metavar="ISO_TIMESTAMP",
        default=None,
        help=(
            "Fetch current events after this timestamp (default: now-7d). "
            "For Mordor historical data, pass e.g. --since 2020-09-20T00:00:00Z."
        ),
    )
    parser.add_argument(
        "--all-events", action="store_true",
        help="Use all indexed events as current data (ignores --since). "
             "Useful for validating the pipeline on historical datasets.",
    )
    args = parser.parse_args()

    # Load reference (training snapshot)
    reference_df = load_reference()

    # Build current feature matrix
    if args.all_events:
        # Fetch everything — useful for Mordor where all timestamps are from 2020
        client = Elasticsearch(ES_URL)
        log.info("Fetching ALL events from %s as current data...", SOURCE_INDEX)
        all_events = list(helpers.scan(
            client, index=SOURCE_INDEX, _source_excludes=["_raw"], size=1000,
        ))
        log.info("Fetched %d events", len(all_events))
        if not all_events:
            log.error("No events found — run src/ingest/load_mordor.py first.")
            sys.exit(1)
        current_df = build_feature_matrix(all_events)
    else:
        since = args.since or "now-7d"
        events = fetch_current_events(since)
        if not events:
            log.warning(
                "No events found since %s. "
                "For historical Mordor data, pass --since 2020-09-20T00:00:00Z "
                "or use --all-events.",
                since,
            )
            # Non-zero exit — empty current window is itself a data quality failure
            sys.exit(1)
        current_df = build_feature_matrix(events)

    log.info(
        "Reference: %d rows | Current: %d rows | Features: %d",
        len(reference_df), len(current_df), len(FEATURE_NAMES),
    )

    passed = run_evidently(reference_df, current_df, dry_run=args.dry_run, verbose=args.verbose)
    sys.exit(0 if passed else 1)


if __name__ == "__main__":
    main()
