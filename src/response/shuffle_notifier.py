"""
Shuffle SOAR notifier — polls security-scores-if for high-priority alerts
and forwards them to a Shuffle webhook for automated response playbooks.

Security intuition: ML routing decisions are only useful if they reach a
response system in time. This script closes that gap: every 5 minutes it
finds alerts the model flagged as 'high_priority' or 'analyst_review' that
have not yet been sent to Shuffle, POSTs them to the configured webhook,
and marks them notified. The idempotency flag (ml.shuffle_notified) ensures
each alert triggers exactly one SOAR workflow run regardless of how often
the notifier is invoked.

Sending only high_priority and analyst_review to Shuffle — and not
auto-close — prevents alert fatigue in the SOAR platform: workflows receive
only events where the ML pipeline has enough confidence to warrant human or
automated action.

Usage:
  python src/response/shuffle_notifier.py               # run once (called by cron)
  python src/response/shuffle_notifier.py --dry-run     # no POSTs, no ES updates
  python src/response/shuffle_notifier.py --verbose
  python src/response/shuffle_notifier.py --limit 50
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from datetime import datetime, timezone
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

ES_URL           = os.getenv("ELASTIC_URL", "http://localhost:9200")
SCORES_INDEX     = "security-scores-if"
SHUFFLE_WEBHOOK  = os.getenv("SHUFFLE_WEBHOOK_URL", "")
NOTIFY_LOG       = Path(__file__).resolve().parents[2] / "data" / "runs" / "notified_alerts.json"
DEFAULT_LIMIT    = 200
NOTIFY_DECISIONS = ["high_priority", "analyst_review"]


# ── Elasticsearch helpers ─────────────────────────────────────────────────────

def fetch_unnotified(client: Elasticsearch, limit: int) -> list[dict]:
    """
    Return alerts that need SOAR response but haven't been forwarded yet.

    Querying only routing_decision IN (high_priority, analyst_review) keeps
    Shuffle free of low-confidence auto-close events that would dilute analyst
    attention. The must_not clause catches both missing and explicitly-false
    shuffle_notified fields so the filter is safe on first run.
    """
    resp = client.search(
        index=SCORES_INDEX,
        size=limit,
        query={
            "bool": {
                "filter": [
                    {"terms": {"ml.routing_decision": NOTIFY_DECISIONS}},
                ],
                "must_not": [
                    {"term": {"ml.shuffle_notified": True}},
                ],
            }
        },
        sort=[{"ml.combined_confidence": {"order": "desc"}}],
    )
    return resp["hits"]["hits"]


def mark_notified(client: Elasticsearch, doc_id: str) -> None:
    """
    Set ml.shuffle_notified=true via Painless so the notifier never sends
    the same alert twice, even if it crashes mid-batch and restarts.
    """
    client.update(
        index=SCORES_INDEX,
        id=doc_id,
        script={
            "source": "ctx._source.ml.shuffle_notified = true;",
            "lang": "painless",
        },
    )


# ── Shuffle webhook ───────────────────────────────────────────────────────────

def build_payload(doc_id: str, source: dict) -> dict:
    """
    Assemble the webhook payload sent to Shuffle.

    Including the full source lets Shuffle workflows branch on any field
    (host, process, ATT&CK technique) without needing to call back to ES.
    The top-level ml_* fields are duplicated for easy use in Shuffle
    condition nodes without navigating nested JSON.
    """
    ml = source.get("ml", {})
    return {
        "alert_id":          doc_id,
        "es_index":          SCORES_INDEX,
        "routing_decision":  ml.get("routing_decision"),
        "combined_confidence": ml.get("combined_confidence"),
        "anomaly_score":     ml.get("anomaly_score"),
        "enrichment_path":   ml.get("enrichment_path"),
        "timestamp":         source.get("@timestamp"),
        "host":              source.get("host", {}).get("name"),
        "alert":             source,
    }


def post_to_shuffle(payload: dict, timeout: int = 10) -> bool:
    """
    POST one alert payload to the Shuffle webhook URL.

    Returns True on HTTP 2xx, False otherwise. Shuffle webhooks return 200
    immediately and execute the workflow asynchronously, so a 200 response
    means the workflow was triggered, not that it completed.
    """
    if not SHUFFLE_WEBHOOK:
        log.error("SHUFFLE_WEBHOOK_URL is not set — set it in your environment or .env")
        return False
    try:
        resp = requests.post(
            SHUFFLE_WEBHOOK,
            json=payload,
            timeout=timeout,
            headers={"Content-Type": "application/json"},
        )
        if resp.status_code < 300:
            log.debug("Shuffle accepted alert %s (HTTP %s)", payload["alert_id"], resp.status_code)
            return True
        log.warning(
            "Shuffle returned HTTP %s for alert %s: %s",
            resp.status_code, payload["alert_id"], resp.text[:200],
        )
        return False
    except requests.exceptions.RequestException as exc:
        log.error("Failed to reach Shuffle webhook: %s", exc)
        return False


# ── Audit log ─────────────────────────────────────────────────────────────────

def append_notify_log(doc_id: str, routing: Optional[str], confidence: Optional[float], status: str) -> None:
    """
    Append one JSON line to the notification audit log.

    JSON Lines format (one object per line) lets the file be tailed and
    grepped without parsing the whole log; it also survives partial writes
    if the process is killed mid-run.
    """
    NOTIFY_LOG.parent.mkdir(parents=True, exist_ok=True)
    entry = {
        "timestamp":         datetime.now(timezone.utc).isoformat(),
        "alert_id":          doc_id,
        "routing_decision":  routing,
        "combined_confidence": confidence,
        "status":            status,
    }
    with open(NOTIFY_LOG, "a") as f:
        f.write(json.dumps(entry) + "\n")


# ── Main ──────────────────────────────────────────────────────────────────────

def run(limit: int = DEFAULT_LIMIT, dry_run: bool = False, verbose: bool = False) -> dict:
    """
    Poll ES, forward unnotified high-priority alerts to Shuffle, mark them done.

    Returns a summary dict so this function can be called from tests or other
    scripts without spawning a subprocess.
    """
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    es = Elasticsearch(ES_URL)
    hits = fetch_unnotified(es, limit)

    sent = skipped = failed = 0

    for hit in hits:
        doc_id = hit["_id"]
        source = hit["_source"]
        ml     = source.get("ml", {})
        routing    = ml.get("routing_decision")
        confidence = ml.get("combined_confidence")

        log.info(
            "Alert %s | routing=%s | confidence=%s",
            doc_id, routing, confidence,
        )

        if dry_run:
            log.info("  [dry-run] would POST to Shuffle and mark notified")
            skipped += 1
            continue

        payload = build_payload(doc_id, source)
        ok = post_to_shuffle(payload)

        if ok:
            mark_notified(es, doc_id)
            append_notify_log(doc_id, routing, confidence, "sent")
            sent += 1
            log.info("  Sent and marked notified")
        else:
            append_notify_log(doc_id, routing, confidence, "failed")
            failed += 1
            log.warning("  POST failed — will retry on next run")

    summary = {
        "total_fetched": len(hits),
        "sent": sent,
        "skipped_dry_run": skipped,
        "failed": failed,
    }
    log.info("Done: %s", summary)
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description="Forward high-priority ML alerts to Shuffle SOAR")
    parser.add_argument("--dry-run",  action="store_true", help="No POSTs, no ES updates")
    parser.add_argument("--verbose",  action="store_true", help="DEBUG logging")
    parser.add_argument("--limit",    type=int, default=DEFAULT_LIMIT, help="Max alerts per run")
    args = parser.parse_args()
    run(limit=args.limit, dry_run=args.dry_run, verbose=args.verbose)


if __name__ == "__main__":
    main()
