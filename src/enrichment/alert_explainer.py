"""
LLM-based alert enrichment for anomalies scored by the Isolation Forest.

Security intuition: anomaly scores tell you *that* an event is unusual but not
*why* it matters. A score of 0.95 on a process_creation event is meaningless to
a tier-1 analyst without context — is it a false positive from a patching tool or
a real PsExec lateral movement? This script sends each flagged alert to a local
LLM (no data leaves the machine) and asks it to produce: an ATT&CK technique
mapping, a plain-English description, a false-positive assessment, and three
concrete investigation steps. That output is written back to the scores index as
ml.llm_triage so the dashboard can surface it alongside the alert.

Design decisions:
- Processes only documents where ml.is_anomaly=true AND ml.llm_triage is absent,
  making runs safely idempotent and supporting incremental enrichment.
- Uses a Painless script update (not a doc-level replace) so ml.anomaly_score,
  ml.is_anomaly, ml.model, and ml.scored_at are never touched.
- Prompts for strict JSON output and validates the schema; falls back gracefully
  if the model returns prose instead of JSON.
- Uses ollama.Client(host=...) to respect the OLLAMA_URL env var — the default
  ollama.chat() ignores custom host settings.

Usage:
  python src/enrichment/alert_explainer.py               # enrich up to 50 anomalies
  python src/enrichment/alert_explainer.py --dry-run     # preview without ES writes
  python src/enrichment/alert_explainer.py --limit 10 --verbose
  python src/enrichment/alert_explainer.py --model llama3.1:8b
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import sys
from pathlib import Path

import ollama
from elasticsearch import Elasticsearch

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)

ES_URL       = os.getenv("ELASTIC_URL", "http://localhost:9200")
OLLAMA_URL   = os.getenv("OLLAMA_URL", "http://localhost:11434")
SCORES_INDEX = "security-scores-if"

# llama3.2:3b — ~2 GB RAM, ~2 s/response; good for interactive triage.
# llama3.1:8b — ~5 GB RAM, ~8 s/response; better ATT&CK technique accuracy.
DEFAULT_MODEL = "llama3.2:3b"
DEFAULT_LIMIT = 50

# Required keys in the LLM JSON response; used for validation.
_REQUIRED_KEYS = {
    "attack_technique",
    "attack_tactic",
    "description",
    "fp_assessment",
    "fp_reasoning",
    "investigation_steps",
}
_VALID_FP = {"low", "medium", "high"}


# ── Elasticsearch helpers ─────────────────────────────────────────────────────

def fetch_unenriched_anomalies(
    client: Elasticsearch,
    limit: int = DEFAULT_LIMIT,
) -> list[dict]:
    """
    Return the top-scoring anomalies that have not yet been LLM-enriched.

    Security intuition: sorting by anomaly_score descending means we always
    enrich the highest-confidence findings first. If the LLM quota or rate
    limit cuts a run short, the most important alerts have already been triaged.
    The must_not filter on ml.enriched makes runs idempotent. We use the
    indexed boolean ml.enriched (not ml.llm_triage) because ml.llm_triage has
    mapping enabled:false — ES stores it in _source but never indexes it, so
    exists queries on it always return zero results.
    """
    resp = client.search(
        index=SCORES_INDEX,
        body={
            "query": {
                "bool": {
                    "must":     [{"term": {"ml.is_anomaly": True}}],
                    "must_not": [{"term": {"ml.enriched": True}}],
                }
            },
            "sort": [{"ml.anomaly_score": "desc"}],
            "size": limit,
            "_source": [
                "@timestamp",
                "host.name",
                "user.name",
                "process.name",
                "process.parent.name",
                "process.command_line",
                "event.category",
                "event.channel",
                "event.id",
                "source_dataset",
                "ml.anomaly_score",
            ],
        },
    )
    hits = resp["hits"]["hits"]
    log.info("Found %d unenriched anomalies to process", len(hits))
    return hits


def write_triage(client: Elasticsearch, doc_id: str, triage: dict) -> None:
    """
    Patch ml.llm_triage onto an existing document using a Painless script.

    Security intuition for the design: a doc-level update ({"doc": {"ml": {...}}})
    would replace the entire ml object, silently zeroing out anomaly_score and
    is_anomaly. The Painless script surgically sets only the llm_triage sub-field,
    leaving all other ml.* fields untouched. Safe to call multiple times — it
    overwrites llm_triage if it already exists.
    """
    client.update(
        index=SCORES_INDEX,
        id=doc_id,
        script={
            # Set both the triage payload and the indexed flag atomically.
            # ml.llm_triage has enabled:false so ES won't index it, but
            # ml.enriched is a normal boolean and IS indexed — use it for
            # exists/term queries and the idempotency filter.
            "source": (
                "ctx._source.ml.llm_triage = params.triage; "
                "ctx._source.ml.enriched = true"
            ),
            "lang":   "painless",
            "params": {"triage": triage},
        },
    )


# ── Prompt engineering ────────────────────────────────────────────────────────

def build_prompt(src: dict) -> str:
    """
    Build the LLM prompt for a single alert.

    Security intuition: smaller models (3b parameters) need more explicit
    output-format guidance than larger ones. Including one concrete JSON example
    in the prompt dramatically improves schema compliance for llama3.2:3b.
    We deliberately exclude fields the LLM can't usefully interpret (raw binary
    data, internal ES IDs) to keep the context tight and within the model's
    effective attention window.
    """
    proc    = (src.get("process") or {}).get("name") or "unknown"
    parent  = ((src.get("process") or {}).get("parent") or {}).get("name") or "unknown"
    cmd     = (src.get("process") or {}).get("command_line") or "(not recorded)"
    user    = (src.get("user") or {}).get("name") or "unknown"
    host    = (src.get("host") or {}).get("name") or "unknown"
    cat     = (src.get("event") or {}).get("category") or "unknown"
    channel = (src.get("event") or {}).get("channel") or "unknown"
    score   = (src.get("ml") or {}).get("anomaly_score", 0)
    dataset = src.get("source_dataset") or "unknown"

    event_summary = (
        f"anomaly_score: {score:.4f}\n"
        f"event.category: {cat}\n"
        f"event.channel: {channel}\n"
        f"process.name: {proc}\n"
        f"process.parent.name: {parent}\n"
        f"process.command_line: {cmd}\n"
        f"user.name: {user}\n"
        f"host.name: {host}\n"
        f"source_dataset: {dataset}"
    )

    return f"""You are a senior SOC analyst and MITRE ATT&CK expert. Analyse the following Windows security event that was flagged as anomalous by a machine learning model. Respond ONLY with a valid JSON object — no markdown, no explanation outside the JSON.

Event:
{event_summary}

Required JSON schema (respond with exactly these keys):
{{
  "attack_technique": "TXXXX or TXXXX.XXX (single best match)",
  "attack_tactic":    "ATT&CK tactic name (e.g. Lateral Movement)",
  "description":      "One sentence plain-English summary of what happened and why it is suspicious",
  "fp_assessment":    "low | medium | high  (confidence this is a TRUE POSITIVE — low FP means high confidence)",
  "fp_reasoning":     "One sentence explaining the FP assessment",
  "investigation_steps": [
    "Step 1: concrete action an analyst should take",
    "Step 2: ...",
    "Step 3: ..."
  ]
}}

Example of a correctly formatted response:
{{
  "attack_technique": "T1059.001",
  "attack_tactic": "Execution",
  "description": "PowerShell was launched with an encoded command, a common obfuscation technique used to hide malicious payload downloads.",
  "fp_assessment": "low",
  "fp_reasoning": "Encoded PowerShell commands have very few legitimate uses in enterprise environments.",
  "investigation_steps": [
    "Decode the base64 command and review the plaintext payload for IOCs",
    "Check for outbound network connections from the same host within 60 seconds",
    "Review parent process tree to determine how powershell.exe was launched"
  ]
}}

Respond now with JSON only:"""


# ── LLM interaction ───────────────────────────────────────────────────────────

_JSON_RE = re.compile(r"\{.*\}", re.DOTALL)


def call_llm(prompt: str, model: str, client: ollama.Client) -> str:
    """
    Send a prompt to Ollama and return the raw response text.

    Security intuition: temperature=0 makes the model deterministic so that
    re-running the enrichment on the same alert produces a stable ATT&CK
    mapping. Stochastic outputs would make the triage unreliable for audit
    trail purposes.
    """
    response = client.chat(
        model=model,
        messages=[{"role": "user", "content": prompt}],
        options={"temperature": 0},
    )
    return response["message"]["content"]


def parse_response(raw: str) -> dict | None:
    """
    Extract and validate the JSON triage object from the LLM response.

    The model sometimes wraps JSON in markdown code fences or adds a leading
    explanation sentence. The regex extracts the first {...} block so minor
    formatting variations don't cause hard failures.
    """
    # Strip markdown code fences if present.
    text = raw.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text)

    # Extract the first JSON object from the response.
    match = _JSON_RE.search(text)
    if not match:
        log.warning("LLM returned no JSON object in response")
        return None

    try:
        obj = json.loads(match.group())
    except json.JSONDecodeError as exc:
        log.warning("JSON parse failed: %s", exc)
        return None

    # Validate required keys.
    missing = _REQUIRED_KEYS - set(obj.keys())
    if missing:
        log.warning("LLM response missing keys: %s", missing)
        return None

    # Normalise fp_assessment to expected values.
    obj["fp_assessment"] = obj["fp_assessment"].strip().lower()
    if obj["fp_assessment"] not in _VALID_FP:
        obj["fp_assessment"] = "medium"

    # Ensure investigation_steps is a list of strings.
    steps = obj.get("investigation_steps", [])
    if not isinstance(steps, list) or len(steps) < 1:
        log.warning("investigation_steps is missing or not a list")
        return None
    obj["investigation_steps"] = [str(s) for s in steps[:5]]  # cap at 5

    return obj


# ── Per-alert enrichment ──────────────────────────────────────────────────────

def enrich_one(
    hit: dict,
    ollama_client: ollama.Client,
    model: str,
    dry_run: bool,
    verbose: bool,
) -> dict | None:
    """
    Enrich a single alert: build prompt → call LLM → parse → write to ES.

    Returns the parsed triage dict on success, None on failure. Failures are
    logged but not raised so a single bad LLM response doesn't abort the batch.
    """
    doc_id = hit["_id"]
    src    = hit["_source"]
    score  = (src.get("ml") or {}).get("anomaly_score", 0)
    proc   = (src.get("process") or {}).get("name") or "(none)"

    log.info(
        "Enriching %s — score=%.4f  proc=%s  category=%s",
        doc_id[:8], score, proc,
        (src.get("event") or {}).get("category", "?"),
    )

    prompt = build_prompt(src)

    try:
        raw = call_llm(prompt, model, ollama_client)
    except Exception as exc:
        log.error("Ollama call failed for %s: %s", doc_id[:8], exc)
        return None

    if verbose:
        log.info("Raw LLM response:\n%s", raw)

    triage = parse_response(raw)
    if triage is None:
        log.warning("Skipping %s — could not parse LLM response", doc_id[:8])
        return None

    if dry_run:
        print(f"\n  [{doc_id[:8]}] score={score:.4f}  proc={proc}")
        print(f"    technique : {triage['attack_technique']}  ({triage['attack_tactic']})")
        print(f"    fp        : {triage['fp_assessment']} — {triage['fp_reasoning']}")
        print(f"    summary   : {triage['description']}")
        for i, step in enumerate(triage["investigation_steps"], 1):
            print(f"    step {i}    : {step}")
    else:
        try:
            write_triage(client_from_env(), doc_id, triage)
        except Exception as exc:
            log.error("ES write failed for %s: %s", doc_id[:8], exc)
            return None

    return triage


# ── Main pipeline ──────────────────────────────────────────────────────────────

def client_from_env() -> Elasticsearch:
    """Return an ES client using ELASTIC_URL from the environment."""
    return Elasticsearch(ES_URL)


def run(
    dry_run: bool = False,
    verbose: bool = False,
    limit: int = DEFAULT_LIMIT,
    model: str = DEFAULT_MODEL,
) -> dict:
    """
    Enrich up to `limit` unenriched anomalies. Returns a summary dict.

    Importable by the scheduler for the weekly enrichment sweep.
    """
    es     = client_from_env()
    ollama_client = ollama.Client(host=OLLAMA_URL)

    hits = fetch_unenriched_anomalies(es, limit=limit)
    if not hits:
        log.info("No unenriched anomalies found — nothing to do.")
        return {"processed": 0, "succeeded": 0, "failed": 0, "dry_run": dry_run}

    succeeded, failed = 0, 0
    for hit in hits:
        result = enrich_one(hit, ollama_client, model, dry_run=dry_run, verbose=verbose)
        if result is not None:
            succeeded += 1
        else:
            failed += 1

    log.info(
        "Enrichment complete: %d succeeded, %d failed (dry_run=%s)",
        succeeded, failed, dry_run,
    )
    return {
        "processed": len(hits),
        "succeeded": succeeded,
        "failed":    failed,
        "dry_run":   dry_run,
        "model":     model,
    }


# ── CLI ────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Enrich anomalies in security-scores-if with LLM triage via Ollama."
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Print triage results to stdout without writing to Elasticsearch.",
    )
    parser.add_argument(
        "--verbose", action="store_true",
        help="Print the raw LLM response for each alert.",
    )
    parser.add_argument(
        "--limit", type=int, default=DEFAULT_LIMIT, metavar="N",
        help=f"Maximum number of alerts to enrich per run (default: {DEFAULT_LIMIT}).",
    )
    parser.add_argument(
        "--model", default=DEFAULT_MODEL, metavar="NAME",
        help=f"Ollama model to use (default: {DEFAULT_MODEL}).",
    )
    args = parser.parse_args()

    summary = run(
        dry_run=args.dry_run,
        verbose=args.verbose,
        limit=args.limit,
        model=args.model,
    )
    print("\nSummary:")
    for k, v in summary.items():
        print(f"  {k}: {v}")
    sys.exit(0)


if __name__ == "__main__":
    main()
