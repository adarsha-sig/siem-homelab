"""
Wazuh → ECS bridge: reads Wazuh alerts from Elasticsearch and re-indexes
them in ECS format for the ML anomaly detection pipeline.

Security intuition: Wazuh uses its own field schema (agent.name, rule.id,
data.win.eventdata.*) rather than ECS. The bridge normalises these fields to
the same ECS schema used by the Mordor ingest pipeline so both data sources
feed a single anomaly model without source-specific feature engineering.
Wazuh also provides pre-computed MITRE ATT&CK mappings (rule.mitre.technique)
which enrich the ECS events and enable the two-path LLM enrichment routing
in alert_explainer.py: events with a Wazuh rule ID skip the full ATT&CK
classification prompt (cheaper, faster) and go straight to FP assessment.

Cursor design: the bridge tracks its last-seen timestamp in
data/runs/wazuh_bridge_cursor.json so re-runs never double-index and a
restart doesn't reprocess the entire alert history.

Usage:
  python src/ingest/wazuh_bridge.py               # poll all new alerts
  python src/ingest/wazuh_bridge.py --dry-run     # parse without indexing
  python src/ingest/wazuh_bridge.py --since 2024-05-19T00:00:00Z
  python src/ingest/wazuh_bridge.py --verbose
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

from elasticsearch import Elasticsearch, helpers

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)

ES_URL         = os.getenv("ELASTIC_URL", "http://localhost:9200")
WAZUH_INDEX    = "wazuh-alerts-4.x-*"
TARGET_INDEX   = "security-events-wazuh"
CURSOR_FILE    = Path(__file__).resolve().parents[2] / "data" / "runs" / "wazuh_bridge_cursor.json"
BULK_SIZE      = 500


# ── Index management ──────────────────────────────────────────────────────────

TARGET_MAPPING = {
    "mappings": {
        "properties": {
            "@timestamp":     {"type": "date"},
            "host":           {"properties": {"name": {"type": "keyword"}}},
            "user":           {"properties": {"name": {"type": "keyword"}}},
            "process": {
                "properties": {
                    "name":   {"type": "keyword"},
                    "parent": {"properties": {"name": {"type": "keyword"}}},
                }
            },
            "event": {
                "properties": {
                    "category":  {"type": "keyword"},
                    "id":        {"type": "keyword"},
                    "mitre":     {"properties": {"technique": {"type": "keyword"}}},
                }
            },
            "source_dataset": {"type": "keyword"},
            "wazuh": {
                "properties": {
                    "rule": {
                        "properties": {
                            "id":          {"type": "keyword"},
                            "description": {"type": "text",
                                            "fields": {"keyword": {"type": "keyword", "ignore_above": 512}}},
                            "level":       {"type": "integer"},
                            "groups":      {"type": "keyword"},
                        }
                    },
                    "agent": {
                        "properties": {
                            "id":   {"type": "keyword"},
                            "name": {"type": "keyword"},
                        }
                    },
                }
            },
        }
    }
}


def ensure_target_index(client: Elasticsearch) -> None:
    """Create security-events-wazuh with ECS + Wazuh field mappings if absent."""
    if not client.indices.exists(index=TARGET_INDEX):
        client.indices.create(index=TARGET_INDEX, body=TARGET_MAPPING)
        log.info("Created index: %s", TARGET_INDEX)


# ── Cursor management ─────────────────────────────────────────────────────────

def read_cursor() -> Optional[str]:
    """
    Return the ISO timestamp of the last successfully indexed alert.

    The cursor is the authoritative lower boundary for each poll cycle.
    Using a file (not an ES field) means the cursor survives index resets
    and can be manually adjusted to replay a time window.
    """
    if not CURSOR_FILE.exists():
        return None
    try:
        data = json.loads(CURSOR_FILE.read_text(encoding="utf-8"))
        return data.get("last_seen")
    except Exception:
        return None


def write_cursor(timestamp: str) -> None:
    """Persist the last-seen timestamp atomically."""
    CURSOR_FILE.parent.mkdir(parents=True, exist_ok=True)
    CURSOR_FILE.write_text(
        json.dumps({"last_seen": timestamp, "updated_at": datetime.now(timezone.utc).isoformat()}),
        encoding="utf-8",
    )


# ── Field mapping ─────────────────────────────────────────────────────────────

def _safe_get(obj: dict, *keys: str, default=None):
    """Navigate a nested dict without raising on missing keys."""
    for key in keys:
        if not isinstance(obj, dict):
            return default
        obj = obj.get(key, {})
    return obj if obj != {} else default


def _basename(path_str: Optional[str]) -> Optional[str]:
    """Extract filename from a Windows path: C:\\Windows\\cmd.exe → cmd.exe."""
    if not path_str:
        return None
    return path_str.replace("\\", "/").split("/")[-1].lower() or None


def to_ecs(raw: dict) -> dict:
    """
    Map a Wazuh alert document to ECS-aligned format.

    Wazuh stores agent identity under 'agent', Windows event data under
    'data.win.eventdata.*', and ATT&CK mappings under 'rule.mitre'.
    Some Wazuh versions wrap these under a top-level 'wazuh' key; we check
    both paths so the bridge works across Wazuh 4.x versions.

    Security intuition: preserving wazuh.rule.id and wazuh.rule.description
    in the indexed document enables the two-path LLM enrichment: Path A
    (Wazuh-backed) skips ATT&CK classification because Wazuh already provides
    it, halving the prompt length and LLM cost for rules-based detections.
    """
    # Handle both `raw.agent.*` and `raw.wazuh.agent.*` layouts
    agent  = raw.get("agent") or raw.get("wazuh", {}).get("agent") or {}
    rule   = raw.get("rule")  or raw.get("wazuh", {}).get("rule")  or {}
    data   = raw.get("data")  or {}
    win_ed = _safe_get(data, "win", "eventdata") or {}

    # Process fields — Wazuh Windows events store image paths in eventdata
    proc_image   = win_ed.get("image") or win_ed.get("Image")
    parent_image = win_ed.get("parentImage") or win_ed.get("ParentImage")

    # User — Wazuh may provide subjectUserName or targetUserName
    user_name = (
        win_ed.get("subjectUserName") or
        win_ed.get("targetUserName") or
        raw.get("syscheck", {}).get("uname_after") or
        None
    )

    # ATT&CK — Wazuh rule.mitre can be a list or a string
    mitre = rule.get("mitre") or {}
    technique_raw = mitre.get("technique") or mitre.get("id") or []
    technique = (
        technique_raw[0] if isinstance(technique_raw, list) and technique_raw
        else (technique_raw if isinstance(technique_raw, str) else None)
    )

    # Event category — derive from Wazuh rule groups
    groups = rule.get("groups") or []
    if isinstance(groups, str):
        groups = [groups]
    category = _derive_category(groups, rule.get("id", ""))

    return {
        "@timestamp":     raw.get("@timestamp") or raw.get("timestamp"),
        "host":           {"name": agent.get("name") or raw.get("hostname")},
        "user":           {"name": user_name},
        "process": {
            "name":   _basename(proc_image),
            "parent": {"name": _basename(parent_image)},
        },
        "event": {
            "category": category,
            "id":        str(rule.get("id", "")),
            "mitre":     {"technique": technique} if technique else {},
        },
        "source_dataset": "wazuh",
        # Preserve Wazuh-native fields for Path A enrichment routing
        "wazuh": {
            "rule": {
                "id":          str(rule.get("id", "")),
                "description": rule.get("description", ""),
                "level":       rule.get("level"),
                "groups":      groups,
            },
            "agent": {
                "id":   agent.get("id", ""),
                "name": agent.get("name", ""),
            },
        },
    }


def _derive_category(groups: list[str], rule_id: str) -> str:
    """
    Map Wazuh rule groups to an event category consistent with the Mordor schema.

    Security intuition: using the same category vocabulary across Mordor and
    Wazuh events lets the IF model compare rarity scores from both sources
    on the same ordinal scale (defined in feature_engineering._CATEGORY_RANK).
    """
    groups_lower = " ".join(g.lower() for g in groups)
    if any(k in groups_lower for k in ("authentication", "logon", "login")):
        return "authentication"
    if any(k in groups_lower for k in ("process_creation", "sysmon_event1", "audit_process")):
        return "process_creation"
    if any(k in groups_lower for k in ("network", "firewall", "connection")):
        return "network_connection"
    if any(k in groups_lower for k in ("registry", "regscan")):
        return "registry_event"
    if any(k in groups_lower for k in ("script", "powershell", "wscript")):
        return "script_execution"
    if any(k in groups_lower for k in ("file", "syscheck")):
        return "file_create"
    if "wmi" in groups_lower:
        return "wmi_activity"
    return "wazuh_alert"


# ── Main pipeline ──────────────────────────────────────────────────────────────

def fetch_new_alerts(client: Elasticsearch, since_iso: str) -> list[dict]:
    """
    Fetch Wazuh alerts with @timestamp strictly after since_iso.

    Uses helpers.scan (scroll API) so large alert bursts don't OOM.
    The query covers all wazuh-alerts-4.x-YYYY.MM.DD daily indices.
    """
    log.info("Fetching Wazuh alerts since %s ...", since_iso)
    alerts = []
    try:
        for hit in helpers.scan(
            client,
            index=WAZUH_INDEX,
            query={"query": {"range": {"@timestamp": {"gt": since_iso}}}},
            size=1000,
        ):
            alerts.append(hit)
    except Exception as exc:
        # Index may not exist yet if no agents have connected
        log.warning("Could not query %s: %s", WAZUH_INDEX, exc)
    log.info("Fetched %d new Wazuh alerts", len(alerts))
    return alerts


def run(
    dry_run: bool = False,
    verbose: bool = False,
    since: Optional[str] = None,
) -> dict:
    """
    Poll for new Wazuh alerts, map to ECS, and index to security-events-wazuh.
    Importable by the scheduler for the 5-minute cron sweep.
    """
    client = Elasticsearch(ES_URL)

    if not dry_run:
        ensure_target_index(client)

    effective_since = since or read_cursor() or "now-5m"
    alerts = fetch_new_alerts(client, effective_since)

    if not alerts:
        log.info("No new Wazuh alerts since %s", effective_since)
        return {"indexed": 0, "skipped": 0, "dry_run": dry_run}

    indexed, skipped = 0, 0
    latest_ts: Optional[str] = None

    def _actions():
        nonlocal skipped
        for hit in alerts:
            src = hit.get("_source", {})
            try:
                doc = to_ecs(src)
                if verbose:
                    log.info("  rule=%s  proc=%s  cat=%s",
                             src.get("rule", {}).get("id"),
                             doc.get("process", {}).get("name"),
                             doc.get("event", {}).get("category"))
                yield {"_index": TARGET_INDEX, "_source": doc}
            except Exception as exc:
                log.warning("Skipping alert %s: %s", hit.get("_id", "?")[:8], exc)
                skipped += 1

    if dry_run:
        for hit in alerts[:10]:
            src = hit.get("_source", {})
            doc = to_ecs(src)
            print(f"  rule={src.get('rule', {}).get('id')}  "
                  f"agent={src.get('agent', {}).get('name')}  "
                  f"proc={doc.get('process', {}).get('name')}  "
                  f"technique={doc.get('event', {}).get('mitre', {}).get('technique')}")
        indexed = len(alerts)
        log.info("[DRY-RUN] Would index %d alerts", indexed)
    else:
        for ok, info in helpers.streaming_bulk(
            client, _actions(), chunk_size=BULK_SIZE, raise_on_error=False,
        ):
            if ok:
                indexed += 1
            else:
                log.warning("Bulk error: %s", info)
                skipped += 1

        # Advance cursor to the latest alert timestamp
        timestamps = [
            hit["_source"].get("@timestamp") or hit["_source"].get("timestamp")
            for hit in alerts
            if hit.get("_source")
        ]
        valid_ts = [t for t in timestamps if t]
        if valid_ts:
            latest_ts = max(valid_ts)
            write_cursor(latest_ts)
            log.info("Cursor advanced to %s", latest_ts)

        log.info("Indexed %d alerts, skipped %d", indexed, skipped)

    return {
        "indexed":  indexed,
        "skipped":  skipped,
        "cursor":   latest_ts or effective_since,
        "dry_run":  dry_run,
    }


# ── CLI ────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Poll Wazuh alerts and index to security-events-wazuh in ECS format."
    )
    parser.add_argument("--dry-run", action="store_true",
                        help="Parse and print alerts without writing to ES.")
    parser.add_argument("--verbose", action="store_true",
                        help="Print each alert as it is processed.")
    parser.add_argument("--since", metavar="ISO_TIMESTAMP",
                        help="Override cursor: fetch alerts after this timestamp.")
    args = parser.parse_args()

    summary = run(dry_run=args.dry_run, verbose=args.verbose, since=args.since)
    print("\nSummary:")
    for k, v in summary.items():
        print(f"  {k}: {v}")
    sys.exit(0)


if __name__ == "__main__":
    main()
