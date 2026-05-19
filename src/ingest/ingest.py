"""
Parses raw log files and bulk-indexes them into Elasticsearch.
Extend parse_line() to handle additional log formats (syslog, JSON, CEF, etc.).
"""

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Generator

import os

from elasticsearch import Elasticsearch, helpers
from loguru import logger

ES_HOST = os.getenv("ELASTIC_URL", "http://localhost:9200")
INDEX = "siem-logs"


def get_client() -> Elasticsearch:
    return Elasticsearch(ES_HOST)


def ensure_index(client: Elasticsearch) -> None:
    if not client.indices.exists(index=INDEX):
        client.indices.create(
            index=INDEX,
            body={
                "mappings": {
                    "properties": {
                        "timestamp": {"type": "date"},
                        "source_ip": {"type": "ip"},
                        "event_type": {"type": "keyword"},
                        "raw": {"type": "text"},
                        "anomaly_score": {"type": "float"},
                    }
                }
            },
        )
        logger.info(f"Created index: {INDEX}")


def parse_line(line: str) -> dict | None:
    """Minimal parser — extend regexes for your actual log format."""
    line = line.strip()
    if not line:
        return None

    # Try JSON first
    if line.startswith("{"):
        try:
            doc = json.loads(line)
            doc.setdefault("timestamp", datetime.now(timezone.utc).isoformat())
            return doc
        except json.JSONDecodeError:
            pass

    # Fallback: extract common syslog-style fields
    ip_match = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", line)
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source_ip": ip_match.group(1) if ip_match else None,
        "event_type": "generic",
        "raw": line,
        "anomaly_score": None,
    }


def generate_docs(path: Path) -> Generator[dict, None, None]:
    with open(path, "r", errors="replace") as f:
        for line in f:
            doc = parse_line(line)
            if doc:
                yield {"_index": INDEX, "_source": doc}


def ingest_file(path: str | Path) -> int:
    path = Path(path)
    client = get_client()
    ensure_index(client)

    success, _ = helpers.bulk(client, generate_docs(path), raise_on_error=False)
    logger.info(f"Indexed {success} documents from {path.name}")
    return success


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python ingest.py <log_file>")
        sys.exit(1)
    ingest_file(sys.argv[1])
