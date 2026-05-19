"""
Bulk-indexes OTRF Security-Datasets (Mordor) zip archives into Elasticsearch.

Security intuition: Mordor datasets are pre-recorded Windows telemetry from
controlled ATT&CK simulations. Indexing them gives the ML models a labelled
corpus of real attack behaviour — process trees, credential access patterns,
lateral movement chains — without needing a live lab. The index becomes the
ground truth for anomaly scoring and LLM triage in later phases.

Usage:
  python src/ingest/load_mordor.py                        # all zips in data/raw/
  python src/ingest/load_mordor.py --source path/to.zip  # single file
  python src/ingest/load_mordor.py --dry-run --verbose    # preview without indexing
"""

from __future__ import annotations

import argparse
import io
import json
import logging
import os
import sys
import zipfile
from pathlib import Path
from typing import Generator

from elasticsearch import Elasticsearch, helpers

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)

ES_URL = os.getenv("ELASTIC_URL", "http://localhost:9200")
INDEX = "security-events-mordor"
BULK_SIZE = 500
DATA_RAW = Path(__file__).resolve().parents[2] / "data" / "raw"


# ── Index management ──────────────────────────────────────────────────────────

INDEX_MAPPING = {
    "mappings": {
        "properties": {
            "@timestamp":           {"type": "date"},
            "host":                 {"properties": {"name": {"type": "keyword"}}},
            "user":                 {"properties": {"name": {"type": "keyword"}}},
            "process": {
                "properties": {
                    "name":         {"type": "keyword"},
                    "command_line": {"type": "text", "fields": {"keyword": {"type": "keyword", "ignore_above": 2048}}},
                    "parent":       {"properties": {"name": {"type": "keyword"}}},
                }
            },
            "event": {
                "properties": {
                    "category":     {"type": "keyword"},
                    "id":           {"type": "keyword"},
                    "channel":      {"type": "keyword"},
                }
            },
            "source_dataset":       {"type": "keyword"},
            "tags":                 {"type": "keyword"},
            "_raw":                 {"type": "object", "enabled": False},  # store but don't index raw fields
        }
    }
}


def ensure_index(client: Elasticsearch) -> None:
    """
    Create the index with ECS-aligned mappings if it doesn't exist.

    Security intuition: explicit mappings prevent ES from auto-typing fields
    as 'text' when they should be 'keyword' (e.g. process names), which would
    break exact-match aggregations used by the anomaly models downstream.
    """
    if not client.indices.exists(index=INDEX):
        client.indices.create(index=INDEX, body=INDEX_MAPPING)
        log.info("Created index: %s", INDEX)
    else:
        log.info("Index already exists: %s", INDEX)


# ── Field mapping ─────────────────────────────────────────────────────────────

def _basename(path_str: str | None) -> str | None:
    """Extract the filename from a Windows path, e.g. C:\\Windows\\cmd.exe → cmd.exe."""
    if not path_str:
        return None
    return path_str.replace("\\", "/").split("/")[-1].lower() or None


def _event_category(channel: str, event_id: int) -> str:
    """
    Derive a coarse ATT&CK-flavoured category from the Windows channel + EventID.

    Security intuition: grouping by category (rather than raw EventID) lets the
    anomaly models learn tactic-level patterns — e.g. 'how often does this host
    see credential_access events' — which is more signal-rich than raw event
    counts and more resilient to vendor-specific EventID numbering.
    """
    ch = channel.lower()
    if "sysmon" in ch:
        sysmon_map = {
            1: "process_creation", 3: "network_connection", 5: "process_termination",
            7: "image_load", 8: "create_remote_thread", 10: "process_access",
            11: "file_create", 12: "registry_event", 13: "registry_event",
            15: "file_create_stream_hash", 17: "pipe_event", 22: "dns_query",
            23: "file_delete", 25: "process_tamper",
        }
        return sysmon_map.get(event_id, f"sysmon_{event_id}")
    if "security" in ch:
        if event_id in (4624, 4625, 4648, 4768, 4769, 4771):
            return "authentication"
        if event_id in (4688, 4689):
            return "process_creation"
        if event_id in (4662, 4663, 4670):
            return "object_access"
        if event_id in (4720, 4722, 4723, 4724, 4725, 4726, 4738):
            return "account_management"
        if event_id in (4776, 4798, 4799):
            return "credential_access"
        if event_id in (5140, 5145):
            return "network_share"
        return f"security_{event_id}"
    if "powershell" in ch:
        return "script_execution"
    if "wmi" in ch:
        return "wmi_activity"
    return "other"


def to_ecs(raw: dict, source_dataset: str) -> dict:
    """
    Map a raw Mordor/NXLog event to an ECS-aligned document.

    Security intuition: normalising to ECS means the same field names are used
    regardless of which Windows channel produced the event, so the feature
    engineering pipeline can join process events, authentication events, and
    Sysmon events without per-source logic.
    """
    event_id = int(raw.get("EventID", 0))
    channel  = raw.get("Channel", "")

    # process fields — field names differ by channel/EventID
    proc_image = (
        raw.get("Image") or
        raw.get("SourceImage") or
        raw.get("NewProcessName") or
        raw.get("ProcessName")
    )
    parent_image = (
        raw.get("ParentImage") or
        raw.get("ParentProcessName")
    )
    command_line = (
        raw.get("CommandLine") or
        raw.get("ParentCommandLine") or
        raw.get("ScriptBlockText")
    )

    # user fields
    user_name = (
        raw.get("AccountName") or
        raw.get("SubjectUserName") or
        raw.get("TargetUserName") or
        raw.get("User")
    )
    if user_name and user_name in ("-", ""):
        user_name = None

    return {
        "@timestamp":    raw.get("@timestamp") or raw.get("EventTime"),
        "host":          {"name": raw.get("Hostname") or raw.get("host")},
        "user":          {"name": user_name},
        "process": {
            "name":         _basename(proc_image),
            "command_line": command_line,
            "parent":       {"name": _basename(parent_image)},
        },
        "event": {
            "category": _event_category(channel, event_id),
            "id":        str(event_id),
            "channel":   channel,
        },
        "source_dataset": source_dataset,
        "tags":           raw.get("tags", []),
        "_raw":           raw,   # full original event stored but not indexed
    }


# ── Streaming read ─────────────────────────────────────────────────────────────

def stream_zip(zip_path: Path) -> Generator[dict, None, None]:
    """
    Stream-parse a Mordor zip without loading the whole JSON into memory.

    Security intuition: some datasets contain 100k+ events. Streaming avoids
    OOM on a constrained home-lab VM and lets the bulk indexer overlap I/O
    with network writes.
    """
    source = zip_path.stem
    with zipfile.ZipFile(zip_path) as zf:
        for name in zf.namelist():
            if not name.endswith(".json"):
                continue
            log.info("Reading %s from %s", name, zip_path.name)
            with zf.open(name) as f:
                for line in io.TextIOWrapper(f, encoding="utf-8", errors="replace"):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        raw = json.loads(line)
                        yield to_ecs(raw, source)
                    except json.JSONDecodeError:
                        continue


def generate_bulk_actions(zip_path: Path) -> Generator[dict, None, None]:
    for doc in stream_zip(zip_path):
        yield {"_index": INDEX, "_source": doc}


# ── Main ingest logic ─────────────────────────────────────────────────────────

def ingest_zip(zip_path: Path, client: Elasticsearch, dry_run: bool, verbose: bool) -> int:
    """
    Index all events from one zip file. Returns the count of indexed documents.

    Design: dry_run mode runs the full parse pipeline (catches schema errors)
    but skips the ES write, so it can be used in CI without a running cluster.
    """
    total = 0
    if dry_run:
        for doc in stream_zip(zip_path):
            total += 1
            if verbose:
                log.info("[DRY-RUN] %s", json.dumps(doc, default=str)[:200])
        log.info("[DRY-RUN] %s → would index %d documents", zip_path.name, total)
    else:
        actions = generate_bulk_actions(zip_path)
        for ok, info in helpers.streaming_bulk(
            client, actions, chunk_size=BULK_SIZE, raise_on_error=False
        ):
            if not ok:
                log.warning("Index error: %s", info)
            else:
                total += 1
                if verbose and total % 1000 == 0:
                    log.info("  … %d documents indexed from %s", total, zip_path.name)
        log.info("%s → indexed %d documents", zip_path.name, total)
    return total


def run(source: str | None = None, dry_run: bool = False, verbose: bool = False) -> dict:
    """
    Entry point for programmatic use (e.g. from the scheduler or notebook).

    Returns a summary dict: {zip_name: doc_count, ...}
    """
    client = Elasticsearch(ES_URL) if not dry_run else None

    if not dry_run:
        ensure_index(client)

    if source:
        zip_paths = [Path(source)]
    else:
        zip_paths = sorted(DATA_RAW.glob("*.zip"))

    if not zip_paths:
        log.warning("No .zip files found in %s", DATA_RAW)
        return {}

    summary = {}
    for zp in zip_paths:
        if not zp.exists():
            log.error("File not found: %s", zp)
            continue
        count = ingest_zip(zp, client, dry_run=dry_run, verbose=verbose)
        summary[zp.name] = count

    total = sum(summary.values())
    log.info("Total: %d documents from %d files", total, len(summary))
    return summary


# ── CLI ────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Index OTRF Mordor datasets into Elasticsearch."
    )
    parser.add_argument(
        "--source", metavar="PATH",
        help="Path to a single .zip file. Defaults to all zips in data/raw/.",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Parse and validate without writing to Elasticsearch.",
    )
    parser.add_argument(
        "--verbose", action="store_true",
        help="Log each document (useful with --dry-run for spot-checking).",
    )
    args = parser.parse_args()

    summary = run(source=args.source, dry_run=args.dry_run, verbose=args.verbose)
    if summary:
        print("\nSummary:")
        for name, count in summary.items():
            print(f"  {name}: {count:,} documents")
        print(f"  Total: {sum(summary.values()):,}")
    sys.exit(0)


if __name__ == "__main__":
    main()
