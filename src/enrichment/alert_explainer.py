"""
LLM-based alert enrichment for anomalies scored by the Isolation Forest.

Security intuition: anomaly scores tell you *that* an event is unusual but not
*why* it matters. This script sends each flagged alert to an LLM and asks it to
produce: an ATT&CK technique mapping, a plain-English description, a false-positive
assessment, and three concrete investigation steps. It then combines the IF score,
the percentile rank, and the LLM's TP confidence into a single combined_confidence
score and writes everything back to the scores index.

LLM backends (LLM_BACKEND env var, default "groq"):
  groq   — Groq cloud API (llama-3.1-8b-instant); requires GROQ_API_KEY
  claude — Anthropic API (claude-haiku-4-5-20251001); requires ANTHROPIC_API_KEY
  ollama — local Ollama (llama3.2:3b); requires OLLAMA_URL and a pulled model

Design decisions:
- Processes only documents where ml.is_anomaly=true AND ml.enriched is absent/false,
  making runs safely idempotent.
- Painless script updates are used for all ES writes so ml.anomaly_score and
  ml.is_anomaly are never touched.
- Prompts include the statistical context (percentile, top features) so the LLM
  understands the severity relative to the environment baseline.
- compute_combined_confidence() fuses IF score, percentile, and LLM TP confidence
  into a single scalar and detects IF↔LLM disagreements.

Usage:
  python src/enrichment/alert_explainer.py               # enrich up to 50 anomalies
  python src/enrichment/alert_explainer.py --dry-run
  python src/enrichment/alert_explainer.py --limit 20 --backend groq
  python src/enrichment/alert_explainer.py --backend claude --verbose
  python src/enrichment/alert_explainer.py --backend ollama --model llama3.1:8b
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import sys
from pathlib import Path
from typing import Optional

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

# ── Backend configuration ─────────────────────────────────────────────────────
# LLM_BACKEND selects the inference provider. Default is groq for fast cloud
# inference without local GPU requirements. Ollama is the local fallback.
LLM_BACKEND    = os.getenv("LLM_BACKEND", "groq")
GROQ_MODEL     = "llama-3.1-8b-instant"
CLAUDE_MODEL   = "claude-haiku-4-5-20251001"
OLLAMA_MODEL   = "llama3.2:3b"
DEFAULT_MODEL  = OLLAMA_MODEL   # kept for backward-compat with existing callers

DEFAULT_LIMIT  = 50

# Required keys in the LLM JSON response.
_REQUIRED_KEYS = {
    "attack_technique",
    "attack_tactic",
    "description",
    "fp_assessment",
    "fp_reasoning",
    "investigation_steps",
}
_VALID_FP = {"low", "medium", "high"}

# fp_assessment → llm_confidence (confidence that this is a TRUE POSITIVE).
# Mapping direction: "low" FP probability = high TP confidence = 1.0.
# "high" FP probability = low TP confidence = 0.2.
# This is intentionally the inverse of the fp_assessment label to ensure
# combined_confidence is high for events the LLM believes are real threats.
_FP_TO_LLM_CONF: dict[str, float] = {
    "low":    1.0,   # low FP probability → confident it's a TP
    "medium": 0.6,
    "high":   0.2,   # high FP probability → LLM doubts it's real
}


# ── Elasticsearch helpers ─────────────────────────────────────────────────────

def client_from_env() -> Elasticsearch:
    return Elasticsearch(ES_URL)


def fetch_unenriched_anomalies(
    client: Elasticsearch,
    limit: int = DEFAULT_LIMIT,
) -> list[dict]:
    """
    Return the top-scoring anomalies that have not yet been LLM-enriched.

    Fetches anomaly_percentile and top_features alongside the event fields so
    build_prompt() can include statistical context without a second ES round-trip.
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
                "@timestamp", "host.name", "user.name",
                "process.name", "process.parent.name", "process.command_line",
                "event.category", "event.channel", "event.id",
                "source_dataset",
                "ml.anomaly_score", "ml.anomaly_percentile", "ml.top_features",
            ],
        },
    )
    hits = resp["hits"]["hits"]
    log.info("Found %d unenriched anomalies to process", len(hits))
    return hits


def write_triage(client: Elasticsearch, doc_id: str, triage: dict) -> None:
    """
    Patch ml.llm_triage and ml.enriched onto an existing document via Painless.
    Does NOT touch ml.anomaly_score, ml.is_anomaly, or any other ml.* field.
    """
    client.update(
        index=SCORES_INDEX,
        id=doc_id,
        script={
            "source": (
                "ctx._source.ml.llm_triage = params.triage; "
                "ctx._source.ml.enriched = true"
            ),
            "lang":   "painless",
            "params": {"triage": triage},
        },
    )


def write_combined_confidence(
    client: Elasticsearch, doc_id: str, fields: dict,
) -> None:
    """
    Write combined_confidence, llm_confidence, if_llm_disagreement, and
    routing_decision back to the document via a single Painless script.

    A separate script from write_triage so these fields can be recomputed
    independently of the triage text (e.g. when thresholds change).
    """
    client.update(
        index=SCORES_INDEX,
        id=doc_id,
        script={
            "source": (
                "ctx._source.ml.combined_confidence = params.combined; "
                "ctx._source.ml.llm_confidence = params.llm_conf; "
                "ctx._source.ml.if_llm_disagreement = params.disagreement; "
                "ctx._source.ml.routing_decision = params.routing;"
            ),
            "lang":   "painless",
            "params": {
                "combined":    fields["combined_confidence"],
                "llm_conf":    fields["llm_confidence"],
                "disagreement": fields["if_llm_disagreement"],
                "routing":     fields["routing_decision"],
            },
        },
    )


# ── Combined confidence ───────────────────────────────────────────────────────

def compute_combined_confidence(
    if_score: float,
    percentile: Optional[float],
    fp_assessment: str,
) -> dict:
    """
    Fuse the IF anomaly score, percentile rank, and LLM TP confidence into a
    single combined_confidence score, then derive routing and disagreement flag.

    Formula: combined = (if_score × pct_norm × llm_conf)^(1/3)

    Geometric mean keeps the score in [0,1] and ensures all three signals must
    be present for a high combined score — one weak signal drags it down. This
    prevents a very high IF score from overriding a strong LLM FP assessment.

    Security intuition: if_llm_disagreement fires when the IF model and the LLM
    reach opposite conclusions. The IF scored the event very high (structural
    rarity) but the LLM believes it is probably a false positive (contextual
    reasoning). These cases deserve a human analyst eye — the model may have
    learned a spurious pattern, or the LLM may be missing domain context.
    """
    llm_conf = _FP_TO_LLM_CONF.get(fp_assessment.strip().lower(), 0.5)

    # Normalise percentile to [0,1]; fall back to the IF score itself when absent
    # (events scored before model_runner.py added percentile computation).
    pct_norm = (percentile / 100.0) if percentile is not None else float(if_score)

    combined = float((float(if_score) * pct_norm * llm_conf) ** (1.0 / 3.0))

    # Disagreement: IF says highly anomalous but LLM has low TP confidence.
    disagreement = bool(float(if_score) > 0.8 and llm_conf < 0.3)

    if combined >= 0.7:
        routing = "tier-1"
    elif combined >= 0.4:
        routing = "tier-2"
    else:
        routing = "auto-close"

    return {
        "combined_confidence": round(combined, 4),
        "llm_confidence":      round(llm_conf, 2),
        "if_llm_disagreement": disagreement,
        "routing_decision":    routing,
    }


# ── Prompt engineering ────────────────────────────────────────────────────────

def _format_top_features(top_features: Optional[list]) -> str:
    """Render top_features list as a readable string for the prompt."""
    if not top_features:
        return "(not available — event was scored before feature attribution was added)"
    parts = []
    for feat in top_features[:3]:
        z = feat.get("z_score", 0)
        direction = "above" if z > 0 else "below"
        parts.append(f"{feat['feature']} (z={z:+.2f}, {direction} baseline)")
    return "; ".join(parts)


def build_prompt(src: dict) -> str:
    """
    Build the LLM prompt for a single alert, including statistical context.

    Security intuition: providing the percentile rank and top contributing
    features gives the LLM the same statistical context a data scientist would
    have. Without it, a model cannot distinguish between a score of 0.95 that
    is the 99th percentile (very rare) vs one that is the 70th percentile
    (moderately unusual). The phrase "statistically unusual for this specific
    environment" grounds the assessment in the actual deployment baseline rather
    than generic threat intelligence.
    """
    proc        = (src.get("process") or {}).get("name") or "unknown"
    parent      = ((src.get("process") or {}).get("parent") or {}).get("name") or "unknown"
    cmd         = (src.get("process") or {}).get("command_line") or "(not recorded)"
    user        = (src.get("user") or {}).get("name") or "unknown"
    host        = (src.get("host") or {}).get("name") or "unknown"
    cat         = (src.get("event") or {}).get("category") or "unknown"
    channel     = (src.get("event") or {}).get("channel") or "unknown"
    ml          = src.get("ml") or {}
    score       = ml.get("anomaly_score", 0)
    percentile  = ml.get("anomaly_percentile")
    top_feats   = ml.get("top_features")
    dataset     = src.get("source_dataset") or "unknown"

    pct_str = (
        f"{percentile:.1f}th percentile" if percentile is not None
        else "percentile unavailable"
    )
    feat_str = _format_top_features(top_feats)

    event_summary = (
        f"anomaly_score: {score:.4f}  ({pct_str})\n"
        f"event.category: {cat}\n"
        f"event.channel: {channel}\n"
        f"process.name: {proc}\n"
        f"process.parent.name: {parent}\n"
        f"process.command_line: {cmd}\n"
        f"user.name: {user}\n"
        f"host.name: {host}\n"
        f"source_dataset: {dataset}\n"
        f"top_contributing_features: {feat_str}"
    )

    return f"""You are a senior SOC analyst and MITRE ATT&CK expert. Analyse the following Windows security event. Note that this event is statistically unusual for this specific environment — it scored at the {pct_str}, meaning it is more anomalous than the vast majority of events observed in this deployment. Your analysis must account for this statistical context. Respond ONLY with a valid JSON object.

Event:
{event_summary}

Required JSON schema (respond with exactly these keys):
{{
  "attack_technique": "TXXXX or TXXXX.XXX (single best match)",
  "attack_tactic":    "ATT&CK tactic name (e.g. Lateral Movement)",
  "description":      "One sentence plain-English summary referencing the percentile rank to convey severity",
  "fp_assessment":    "low | medium | high  (low = very likely a true positive; high = likely a false positive)",
  "fp_reasoning":     "One sentence explaining the FP assessment, referencing the top features if relevant",
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
  "description": "PowerShell was launched with an encoded command at the 99th percentile of anomaly, strongly suggesting malicious obfuscation rather than legitimate administrative use.",
  "fp_assessment": "low",
  "fp_reasoning": "cmd_has_encoding and proc_rarity are both multiple standard deviations above baseline — encoded PowerShell spawned from a rare parent process is nearly always malicious.",
  "investigation_steps": [
    "Decode the base64 command and review the plaintext payload for IOCs",
    "Check for outbound network connections from the same host within 60 seconds",
    "Review parent process tree to determine how powershell.exe was launched"
  ]
}}

Respond now with JSON only:"""


# ── LLM interaction ───────────────────────────────────────────────────────────

_JSON_RE = re.compile(r"\{.*\}", re.DOTALL)


def call_llm(prompt: str, backend: str, model: str) -> str:
    """
    Dispatch the prompt to the requested LLM backend and return the raw text.

    temperature=0 is applied on all backends for deterministic output so that
    re-running enrichment on the same alert produces a stable ATT&CK mapping.

    Security intuition: deterministic output is important for audit trails —
    the triage written to ES must not change on every re-run, otherwise analysts
    cannot rely on previously enriched alerts staying consistent.
    """
    if backend == "groq":
        from groq import Groq
        client = Groq(api_key=os.getenv("GROQ_API_KEY"))
        resp = client.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": prompt}],
            temperature=0,
            max_tokens=1024,
        )
        return resp.choices[0].message.content

    if backend == "claude":
        import anthropic
        client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
        resp = client.messages.create(
            model=model,
            max_tokens=1024,
            messages=[{"role": "user", "content": prompt}],
        )
        return resp.content[0].text

    # Default: ollama (local, no API key required)
    import ollama as _ollama
    oc = _ollama.Client(host=OLLAMA_URL)
    resp = oc.chat(
        model=model,
        messages=[{"role": "user", "content": prompt}],
        options={"temperature": 0},
    )
    return resp["message"]["content"]


def parse_response(raw: str) -> Optional[dict]:
    """
    Extract and validate the JSON triage object from the LLM response.
    Handles markdown code fences and leading prose gracefully.
    """
    text = raw.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text)

    match = _JSON_RE.search(text)
    if not match:
        log.warning("LLM returned no JSON object in response")
        return None

    try:
        obj = json.loads(match.group())
    except json.JSONDecodeError as exc:
        log.warning("JSON parse failed: %s", exc)
        return None

    missing = _REQUIRED_KEYS - set(obj.keys())
    if missing:
        log.warning("LLM response missing keys: %s", missing)
        return None

    obj["fp_assessment"] = obj["fp_assessment"].strip().lower()
    if obj["fp_assessment"] not in _VALID_FP:
        obj["fp_assessment"] = "medium"

    steps = obj.get("investigation_steps", [])
    if not isinstance(steps, list) or len(steps) < 1:
        log.warning("investigation_steps is missing or not a list")
        return None
    obj["investigation_steps"] = [str(s) for s in steps[:5]]

    return obj


# ── Per-alert enrichment ──────────────────────────────────────────────────────

def enrich_one(
    hit: dict,
    backend: str,
    model: str,
    dry_run: bool,
    verbose: bool,
) -> Optional[dict]:
    """
    Enrich a single alert: build prompt → call LLM → parse → compute confidence
    → write triage and confidence fields to ES.

    Returns a dict with triage + confidence on success, None on failure.
    Failures are logged but not re-raised so one bad response doesn't abort
    the batch.
    """
    doc_id = hit["_id"]
    src    = hit["_source"]
    ml     = src.get("ml") or {}
    score  = ml.get("anomaly_score", 0)
    pct    = ml.get("anomaly_percentile")
    proc   = (src.get("process") or {}).get("name") or "(none)"

    log.info(
        "Enriching %s — score=%.4f  pct=%s  proc=%s  category=%s  backend=%s",
        doc_id[:8], score,
        f"{pct:.1f}" if pct is not None else "?",
        proc,
        (src.get("event") or {}).get("category", "?"),
        backend,
    )

    prompt = build_prompt(src)

    try:
        raw = call_llm(prompt, backend, model)
    except Exception as exc:
        log.error("%s call failed for %s: %s", backend, doc_id[:8], exc)
        return None

    if verbose:
        log.info("Raw LLM response:\n%s", raw)

    triage = parse_response(raw)
    if triage is None:
        log.warning("Skipping %s — could not parse LLM response", doc_id[:8])
        return None

    confidence = compute_combined_confidence(score, pct, triage["fp_assessment"])

    if dry_run:
        pct_str = f"{pct:.1f}" if pct is not None else "?"
        print(f"\n  [{doc_id[:8]}] score={score:.4f}  pct={pct_str}  proc={proc}")
        print(f"    technique : {triage['attack_technique']}  ({triage['attack_tactic']})")
        print(f"    fp        : {triage['fp_assessment']} — {triage['fp_reasoning']}")
        print(f"    summary   : {triage['description']}")
        print(
            f"    combined  : {confidence['combined_confidence']:.4f}"
            f"  llm_conf={confidence['llm_confidence']}"
            f"  routing={confidence['routing_decision']}"
            f"  disagreement={confidence['if_llm_disagreement']}"
        )
        for i, step in enumerate(triage["investigation_steps"], 1):
            print(f"    step {i}    : {step}")
    else:
        es = client_from_env()
        try:
            write_triage(es, doc_id, triage)
            write_combined_confidence(es, doc_id, confidence)
        except Exception as exc:
            log.error("ES write failed for %s: %s", doc_id[:8], exc)
            return None

    return {**triage, **confidence}


# ── Main pipeline ──────────────────────────────────────────────────────────────

def run(
    dry_run: bool = False,
    verbose: bool = False,
    limit: int = DEFAULT_LIMIT,
    model: Optional[str] = None,
    backend: Optional[str] = None,
) -> dict:
    """
    Enrich up to `limit` unenriched anomalies. Importable by the scheduler.

    backend defaults to LLM_BACKEND env var (default: "groq").
    model defaults to the backend's canonical model when not specified.
    """
    _backend = backend or LLM_BACKEND
    _model   = model or {
        "groq":   GROQ_MODEL,
        "claude": CLAUDE_MODEL,
        "ollama": OLLAMA_MODEL,
    }.get(_backend, OLLAMA_MODEL)

    log.info("Starting enrichment: backend=%s model=%s limit=%d dry_run=%s",
             _backend, _model, limit, dry_run)

    es   = client_from_env()
    hits = fetch_unenriched_anomalies(es, limit=limit)
    if not hits:
        log.info("No unenriched anomalies found — nothing to do.")
        return {"processed": 0, "succeeded": 0, "failed": 0,
                "dry_run": dry_run, "backend": _backend, "model": _model}

    succeeded, failed = 0, 0
    disagreements = []

    for hit in hits:
        result = enrich_one(hit, _backend, _model, dry_run=dry_run, verbose=verbose)
        if result is not None:
            succeeded += 1
            if result.get("if_llm_disagreement"):
                disagreements.append({
                    "doc_id":   hit["_id"][:8],
                    "score":    (hit["_source"].get("ml") or {}).get("anomaly_score"),
                    "proc":     (hit["_source"].get("process") or {}).get("name"),
                    "combined": result.get("combined_confidence"),
                    "technique": result.get("attack_technique"),
                    "fp":       result.get("fp_assessment"),
                })
        else:
            failed += 1

    log.info("Enrichment complete: %d succeeded, %d failed, %d disagreements",
             succeeded, failed, len(disagreements))

    return {
        "processed":    len(hits),
        "succeeded":    succeeded,
        "failed":       failed,
        "disagreements": len(disagreements),
        "disagreement_details": disagreements,
        "dry_run":      dry_run,
        "backend":      _backend,
        "model":        _model,
    }


# ── CLI ────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Enrich anomalies in security-scores-if with LLM triage."
    )
    parser.add_argument("--dry-run", action="store_true",
                        help="Print results without writing to Elasticsearch.")
    parser.add_argument("--verbose", action="store_true",
                        help="Print the raw LLM response for each alert.")
    parser.add_argument("--limit", type=int, default=DEFAULT_LIMIT, metavar="N",
                        help=f"Max alerts to enrich per run (default: {DEFAULT_LIMIT}).")
    parser.add_argument("--backend", default=None, metavar="BACKEND",
                        choices=["groq", "claude", "ollama"],
                        help="LLM backend: groq (default), claude, ollama. "
                             "Overrides LLM_BACKEND env var.")
    parser.add_argument("--model", default=None, metavar="NAME",
                        help="Override the backend's default model name.")
    args = parser.parse_args()

    summary = run(
        dry_run=args.dry_run,
        verbose=args.verbose,
        limit=args.limit,
        model=args.model,
        backend=args.backend,
    )
    print("\nSummary:")
    for k, v in summary.items():
        if k != "disagreement_details":
            print(f"  {k}: {v}")
    if summary.get("disagreement_details"):
        print("\nDisagreement cases (IF anomalous, LLM says FP):")
        for d in summary["disagreement_details"]:
            print(f"  [{d['doc_id']}] score={d['score']:.4f}  proc={d['proc']}"
                  f"  combined={d['combined']:.4f}  technique={d['technique']}  fp={d['fp']}")
    sys.exit(0)


if __name__ == "__main__":
    main()
