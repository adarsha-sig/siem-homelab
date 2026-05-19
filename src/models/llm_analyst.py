"""
Sends top anomalies to a local Ollama LLM and returns a plain-English triage summary.
Requires Ollama running with a model pulled: `ollama pull llama3.2:3b`

NOTE: this is Phase 1 scaffolding. It will be superseded by
src/enrichment/alert_explainer.py in Phase 4, which targets the correct
security-scores-if index and returns structured JSON for ES write-back.
"""

from __future__ import annotations

import json
import os

import ollama
from elasticsearch import Elasticsearch
from loguru import logger

ES_HOST = os.getenv("ELASTIC_URL", "http://localhost:9200")
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434")
INDEX = "siem-logs"

# llama3.2:3b — ~2 GB RAM, ~2 s/response. Fast enough for real-time triage
# in the dashboard. Use llama3.1:8b for the weekly enrichment sweep where
# latency is acceptable and ATT&CK mapping accuracy matters more.
OLLAMA_MODEL = "llama3.2:3b"
SCORE_THRESHOLD = 0.75
MAX_EVENTS = 10


def fetch_top_anomalies(client: Elasticsearch) -> list[dict]:
    resp = client.search(
        index=INDEX,
        query={"range": {"anomaly_score": {"gte": SCORE_THRESHOLD}}},
        sort=[{"anomaly_score": "desc"}],
        size=MAX_EVENTS,
        _source=["timestamp", "source_ip", "event_type", "raw", "anomaly_score"],
    )
    return [h["_source"] for h in resp["hits"]["hits"]]


def build_prompt(events: list[dict]) -> str:
    events_text = json.dumps(events, indent=2, default=str)
    return (
        "You are a senior SOC analyst. The following events were flagged as anomalous "
        "by an ML model (anomaly_score closer to 1.0 = more suspicious). "
        "For each event, provide: (1) a one-sentence plain-English description of what happened, "
        "(2) the likely threat category (e.g. brute force, lateral movement, data exfil), "
        "(3) recommended immediate action.\n\n"
        f"Events:\n{events_text}"
    )


def analyse(model: str = OLLAMA_MODEL) -> str:
    client = Elasticsearch(ES_HOST)
    events = fetch_top_anomalies(client)

    if not events:
        return "No anomalies above threshold found."

    prompt = build_prompt(events)
    logger.info(f"Sending {len(events)} anomalies to {model} for triage")

    response = ollama.chat(
        model=model,
        messages=[{"role": "user", "content": prompt}],
    )
    return response["message"]["content"]


if __name__ == "__main__":
    print(analyse())
