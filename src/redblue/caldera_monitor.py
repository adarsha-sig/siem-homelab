"""
CALDERA live operation monitor — correlates red-team technique execution with
ML detection events to produce a per-technique detection scorecard.

Security intuition: the only honest way to measure detection coverage is to
actually run an adversary and check whether your model fires. This script
creates a closed loop: for every ATT&CK technique CALDERA executes, it opens
a 90-second window on Elasticsearch and asks "did the Isolation Forest see
anything unusual on that host?" The scorecard that comes out tells you exactly
which techniques are invisible to your current model — the coverage gap.

Design choices:
- Polls /api/v2/operations/{id}/links every --poll-interval seconds rather than
  streaming, because CALDERA has no push/webhook for link completion.
- Uses a seen-link-id set to process each link exactly once even across polls.
- Detection window is 90 s (configurable) — wide enough to capture slow sensors
  like Wazuh's 5-minute bridge cycle, narrow enough to avoid false attribution
  from unrelated host activity.
- All ES/CALDERA URLs from env vars; nothing hardcoded.
- --demo flag runs without any live infrastructure for CI/offline testing.

Usage:
  python src/redblue/caldera_monitor.py --operation-id <UUID>
  python src/redblue/caldera_monitor.py --operation-id <UUID> --dry-run
  python src/redblue/caldera_monitor.py --demo
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional

import requests
from elasticsearch import Elasticsearch

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)

# ── Environment defaults ──────────────────────────────────────────────────────

ES_URL         = os.getenv("ELASTIC_URL",    "http://localhost:9200")
CALDERA_URL    = os.getenv("CALDERA_URL",    "http://localhost:8889")
CALDERA_KEY    = os.getenv("CALDERA_API_KEY", "")
SCORES_INDEX   = "security-scores-if"
RUNS_DIR       = Path(__file__).resolve().parents[2] / "data" / "runs"

DEFAULT_POLL   = 30      # seconds between CALDERA API polls
DETECT_WINDOW  = 90      # seconds after link completion to search for detections
MIN_SCORE      = 0.5     # minimum ml.anomaly_score to count as "detected"


# ── CALDERA API helpers ───────────────────────────────────────────────────────

def _caldera_headers() -> dict:
    """Return auth headers for the CALDERA REST API."""
    return {"KEY": CALDERA_KEY, "Content-Type": "application/json"}


def fetch_operation(caldera_url: str, operation_id: str) -> dict:
    """
    Fetch top-level operation metadata from CALDERA.

    The name and state fields let the monitor report when an operation
    completes so the caller knows to do a final poll and write the scorecard.
    """
    url  = f"{caldera_url}/api/v2/operations/{operation_id}"
    resp = requests.get(url, headers=_caldera_headers(), timeout=10, verify=False)
    resp.raise_for_status()
    return resp.json()


def fetch_links(caldera_url: str, operation_id: str) -> list[dict]:
    """
    Fetch all execution links for an operation.

    A "link" is one step (ability) in the operation. Links have a status:
      -3 = discarded  -2 = untrusted  -1 = blocked  0 = queued
       1 = executing   2 = success    3 = failed
    We care about status=2 (success) and status=3 (failed but executed).
    Status codes from CALDERA source: app/objects/c_link.py.
    """
    url  = f"{caldera_url}/api/v2/operations/{operation_id}/links"
    resp = requests.get(url, headers=_caldera_headers(), timeout=10, verify=False)
    resp.raise_for_status()
    return resp.json()


# ── Elasticsearch detection query ─────────────────────────────────────────────

def query_detections(
    es: Elasticsearch,
    hostname: str,
    after: datetime,
    window_seconds: int,
    min_score: float,
) -> list[dict]:
    """
    Search for anomalous events on `hostname` within `window_seconds` after `after`.

    This is the core measurement: given that CALDERA ran a technique on a host
    at time T, did the Isolation Forest flag anything on that host between T and
    T + window_seconds? The 90-second default accounts for Wazuh's 5-minute
    bridge batch plus scoring pipeline latency — events ingested shortly before
    the technique also qualify because the model may have already scored them.

    Returns a list of hit source dicts (with ml fields) for all matching events.
    """
    before = after + timedelta(seconds=window_seconds)
    resp = es.search(
        index=SCORES_INDEX,
        body={
            "query": {
                "bool": {
                    "must": [
                        {"term":  {"host.name": hostname}},
                        {"term":  {"ml.is_anomaly": True}},
                        {"range": {"ml.anomaly_score": {"gte": min_score}}},
                        {"range": {"@timestamp": {
                            "gte": after.isoformat(),
                            "lte": before.isoformat(),
                        }}},
                    ]
                }
            },
            "sort": [{"ml.anomaly_score": "desc"}],
            "size": 10,
            "_source": [
                "@timestamp", "host.name", "process.name",
                "ml.anomaly_score", "ml.anomaly_percentile",
                "ml.llm_triage", "ml.routing_decision",
            ],
        },
    )
    return [h["_source"] for h in resp["hits"]["hits"]]


# ── Scorecard helpers ─────────────────────────────────────────────────────────

def _technique_from_link(link: dict) -> str:
    """
    Extract the ATT&CK technique ID from a CALDERA link.

    CALDERA embeds technique IDs in the ability's technique_id field.
    Falls back to the ability name prefixed with "unknown:" when absent so the
    scorecard always has a human-readable label.
    """
    ability = link.get("ability") or {}
    tech    = ability.get("technique_id") or ""
    if not tech:
        tech = "unknown:" + (ability.get("name") or link.get("id", "?"))
    return tech


def _link_timestamp(link: dict) -> Optional[datetime]:
    """
    Parse the link's finish timestamp. Returns None if unparseable.

    CALDERA stores timestamps as ISO-8601 strings with a trailing 'Z'.
    """
    ts = link.get("finish") or link.get("create")
    if not ts:
        return None
    try:
        # Python <3.11 does not handle trailing 'Z' in fromisoformat
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None


def _hostname_from_link(link: dict) -> str:
    """Extract the paw (agent hostname / group identifier) from a link."""
    return (link.get("host") or link.get("paw") or "unknown").lower()


# ── Demo mode ─────────────────────────────────────────────────────────────────

def _demo_scorecard() -> dict:
    """
    Generate a realistic synthetic scorecard without live infrastructure.

    Used by --demo flag and CI.  Simulates a 3-technique operation where two
    techniques were detected and one was missed.
    """
    now = datetime.now(timezone.utc).isoformat()
    return {
        "operation":    "demo-operation-00000000-0000-0000-0000-000000000000",
        "operation_name": "Demo — Super Thief",
        "generated_at": now,
        "demo": True,
        "techniques_executed": 3,
        "detected":     2,
        "missed":       1,
        "detection_rate": 0.6667,
        "avg_detection_latency_seconds": 18.4,
        "technique_results": [
            {
                "technique_id": "T1087.001",
                "ability_name": "Enumerate local users",
                "hostname":     "VICTIM-WIN10",
                "executed_at":  now,
                "detected":     True,
                "max_score":    0.874,
                "max_percentile": 96.2,
                "detection_latency_seconds": 12.1,
                "detecting_events": 2,
            },
            {
                "technique_id": "T1082",
                "ability_name": "System information discovery",
                "hostname":     "VICTIM-WIN10",
                "executed_at":  now,
                "detected":     True,
                "max_score":    0.761,
                "max_percentile": 88.5,
                "detection_latency_seconds": 24.7,
                "detecting_events": 1,
            },
            {
                "technique_id": "T1070.004",
                "ability_name": "Delete file",
                "hostname":     "VICTIM-WIN10",
                "executed_at":  now,
                "detected":     False,
                "max_score":    0.0,
                "max_percentile": None,
                "detection_latency_seconds": None,
                "detecting_events": 0,
            },
        ],
        "missed_techniques": ["T1070.004"],
    }


# ── Core monitor loop ─────────────────────────────────────────────────────────

def monitor(
    operation_id: str,
    caldera_url: str,
    poll_interval: int,
    detect_window: int,
    min_score: float,
    dry_run: bool,
    verbose: bool,
) -> dict:
    """
    Poll a running CALDERA operation until it finishes, correlating each
    completed technique link with ES anomaly detections.

    Returns the completed scorecard dict.

    Security intuition: polling every 30 seconds gives near-real-time feedback
    on which techniques are triggering detections as the operation runs. An
    analyst watching the Streamlit dashboard can see the red/blue score evolve
    live, not just as a post-hoc report.
    """
    es             = Elasticsearch(ES_URL)
    seen_link_ids: set[str] = set()
    technique_results: list[dict] = []

    log.info("Monitoring operation %s  caldera=%s  ES=%s", operation_id, caldera_url, ES_URL)
    log.info("Poll interval: %ds  Detection window: %ds  Min score: %.2f", poll_interval, detect_window, min_score)

    op_name = operation_id

    while True:
        # ── Fetch operation state ─────────────────────────────────────────────
        try:
            op = fetch_operation(caldera_url, operation_id)
        except Exception as exc:
            log.warning("Could not fetch operation metadata: %s — retrying in %ds", exc, poll_interval)
            time.sleep(poll_interval)
            continue

        op_name  = op.get("name", operation_id)
        op_state = op.get("state", "running")
        log.info("Operation '%s' state: %s", op_name, op_state)

        # ── Fetch links ───────────────────────────────────────────────────────
        try:
            links = fetch_links(caldera_url, operation_id)
        except Exception as exc:
            log.warning("Could not fetch links: %s — retrying in %ds", exc, poll_interval)
            time.sleep(poll_interval)
            continue

        # Process only completed links we haven't seen before
        for link in links:
            link_id = link.get("id", "")
            status  = link.get("status", 0)

            # Status 2 = success, 3 = failed (technique ran but failed on target)
            if status not in (2, 3):
                continue
            if link_id in seen_link_ids:
                continue
            seen_link_ids.add(link_id)

            technique_id = _technique_from_link(link)
            ability_name = (link.get("ability") or {}).get("name", "(unknown)")
            hostname     = _hostname_from_link(link)
            exec_ts      = _link_timestamp(link)

            if exec_ts is None:
                log.warning("Link %s has no parseable timestamp — skipping", link_id[:8])
                continue

            log.info(
                "Completed link: technique=%s  ability='%s'  host=%s  at=%s  status=%d",
                technique_id, ability_name, hostname, exec_ts.isoformat(), status,
            )

            # ── Query ES for detections ───────────────────────────────────────
            detections: list[dict] = []
            if not dry_run:
                try:
                    detections = query_detections(
                        es, hostname, exec_ts, detect_window, min_score,
                    )
                except Exception as exc:
                    log.warning("ES query failed for %s: %s", technique_id, exc)

            detected = len(detections) > 0
            max_score: float = 0.0
            max_pct: Optional[float] = None
            latency: Optional[float] = None

            if detections:
                first = detections[0]   # sorted by score desc
                max_score = float((first.get("ml") or {}).get("anomaly_score", 0))
                max_pct   = (first.get("ml") or {}).get("anomaly_percentile")
                # latency from technique execution to first detection timestamp
                try:
                    det_ts = datetime.fromisoformat(
                        first["@timestamp"].replace("Z", "+00:00")
                    )
                    latency = (det_ts - exec_ts).total_seconds()
                    if latency < 0:
                        latency = 0.0
                except (KeyError, ValueError):
                    latency = None

            result = {
                "technique_id":               technique_id,
                "ability_name":               ability_name,
                "hostname":                   hostname,
                "executed_at":                exec_ts.isoformat(),
                "detected":                   detected,
                "max_score":                  round(max_score, 4),
                "max_percentile":             round(max_pct, 2) if max_pct is not None else None,
                "detection_latency_seconds":  round(latency, 1) if latency is not None else None,
                "detecting_events":           len(detections),
            }
            technique_results.append(result)

            status_str = "DETECTED" if detected else "MISSED"
            log.info("  → %s  max_score=%.4f  latency=%s s",
                     status_str, max_score,
                     f"{latency:.1f}" if latency is not None else "n/a")

            if verbose and detections:
                for d in detections:
                    log.info(
                        "     event: proc=%s  score=%.4f  routing=%s",
                        (d.get("process") or {}).get("name", "?"),
                        (d.get("ml") or {}).get("anomaly_score", 0),
                        (d.get("ml") or {}).get("routing_decision", "?"),
                    )

        # ── Check if operation finished ───────────────────────────────────────
        if op_state in ("finished", "completed", "cleanup", "out_of_time"):
            log.info("Operation finished — writing scorecard")
            break

        log.info("Sleeping %ds before next poll …", poll_interval)
        time.sleep(poll_interval)

    # ── Build scorecard ───────────────────────────────────────────────────────
    detected_results = [r for r in technique_results if r["detected"]]
    missed_results   = [r for r in technique_results if not r["detected"]]

    latencies = [
        r["detection_latency_seconds"]
        for r in detected_results
        if r["detection_latency_seconds"] is not None
    ]
    avg_latency = round(sum(latencies) / len(latencies), 1) if latencies else None
    n_executed  = len(technique_results)

    scorecard = {
        "operation":      operation_id,
        "operation_name": op_name,
        "generated_at":   datetime.now(timezone.utc).isoformat(),
        "demo":           False,
        "techniques_executed": n_executed,
        "detected":       len(detected_results),
        "missed":         len(missed_results),
        "detection_rate": round(len(detected_results) / n_executed, 4) if n_executed else 0.0,
        "avg_detection_latency_seconds": avg_latency,
        "technique_results": technique_results,
        "missed_techniques": [r["technique_id"] for r in missed_results],
    }

    return scorecard


# ── Output ────────────────────────────────────────────────────────────────────

def write_scorecard(scorecard: dict) -> Path:
    """
    Write the scorecard to data/runs/live_detection_YYYY-MM-DD.json.

    If a file for today already exists it is overwritten so the dashboard
    always shows the freshest run for the day.
    """
    RUNS_DIR.mkdir(parents=True, exist_ok=True)
    date_str = datetime.now().strftime("%Y-%m-%d")
    path     = RUNS_DIR / f"live_detection_{date_str}.json"
    path.write_text(json.dumps(scorecard, indent=2))
    log.info("Scorecard written to %s", path)
    return path


def print_scorecard(scorecard: dict) -> None:
    """Print a human-readable summary of the scorecard to stdout."""
    n_exec = scorecard["techniques_executed"]
    n_det  = scorecard["detected"]
    n_miss = scorecard["missed"]
    rate   = scorecard["detection_rate"]
    lat    = scorecard.get("avg_detection_latency_seconds")

    print(f"\n{'='*60}")
    print(f"  CALDERA Live Detection Scorecard")
    print(f"  Operation : {scorecard['operation_name']}")
    print(f"  Generated : {scorecard['generated_at']}")
    print(f"{'='*60}")
    print(f"  Techniques executed : {n_exec}")
    print(f"  Detected            : {n_det}")
    print(f"  Missed              : {n_miss}")
    print(f"  Detection rate      : {rate:.1%}")
    print(f"  Avg latency         : {lat:.1f} s" if lat is not None else "  Avg latency         : n/a")
    print(f"\n  Per-technique results:")

    for r in scorecard.get("technique_results", []):
        marker  = "✓" if r["detected"] else "✗"
        latency = f"{r['detection_latency_seconds']:.1f}s" if r["detection_latency_seconds"] else "—"
        score   = f"{r['max_score']:.4f}" if r["detected"] else "—"
        print(
            f"  {marker} {r['technique_id']:<14}  {r['ability_name']:<35}"
            f"  score={score:<8}  latency={latency}"
        )

    if scorecard.get("missed_techniques"):
        print(f"\n  Missed ATT&CK techniques:")
        for t in scorecard["missed_techniques"]:
            print(f"    - {t}")

    print(f"{'='*60}\n")


# ── CLI ────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Monitor a CALDERA operation and score ML detection coverage."
    )
    parser.add_argument(
        "--operation-id", metavar="UUID",
        help="CALDERA operation UUID (from the URL bar after starting an operation).",
    )
    parser.add_argument(
        "--caldera-url", default=CALDERA_URL, metavar="URL",
        help=f"CALDERA server URL (default: {CALDERA_URL}; env: CALDERA_URL).",
    )
    parser.add_argument(
        "--poll-interval", type=int, default=DEFAULT_POLL, metavar="SECONDS",
        help=f"Seconds between CALDERA API polls (default: {DEFAULT_POLL}).",
    )
    parser.add_argument(
        "--detect-window", type=int, default=DETECT_WINDOW, metavar="SECONDS",
        help=f"Seconds after technique execution to search for detections (default: {DETECT_WINDOW}).",
    )
    parser.add_argument(
        "--detection-threshold", type=float, default=MIN_SCORE, metavar="SCORE",
        help=f"Minimum ml.anomaly_score to count as detected (default: {MIN_SCORE}).",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Print what would be queried without hitting Elasticsearch.",
    )
    parser.add_argument(
        "--verbose", action="store_true",
        help="Print individual detecting event details.",
    )
    parser.add_argument(
        "--demo", action="store_true",
        help="Generate a synthetic scorecard without a live CALDERA server (for testing).",
    )
    args = parser.parse_args()

    if args.demo:
        scorecard = _demo_scorecard()
        print_scorecard(scorecard)
        path = write_scorecard(scorecard)
        print(f"Demo scorecard written to: {path}")
        return

    if not args.operation_id:
        parser.error("--operation-id is required (or use --demo for offline testing)")

    scorecard = monitor(
        operation_id     = args.operation_id,
        caldera_url      = args.caldera_url,
        poll_interval    = args.poll_interval,
        detect_window    = args.detect_window,
        min_score        = args.detection_threshold,
        dry_run          = args.dry_run,
        verbose          = args.verbose,
    )

    print_scorecard(scorecard)

    if not args.dry_run:
        path = write_scorecard(scorecard)
        print(f"Scorecard written to: {path}")


if __name__ == "__main__":
    main()
