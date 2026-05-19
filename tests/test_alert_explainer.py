"""
Tests for src/enrichment/alert_explainer.py.

Unit tests cover prompt construction and JSON response parsing — neither
requires a running Ollama instance or Elasticsearch cluster.

Integration tests (marked @pytest.mark.integration) require:
  - ES running with a populated security-scores-if index
  - Ollama running with llama3.2:3b pulled

Run unit tests only:   pytest tests/test_alert_explainer.py -v -m "not integration"
Run all tests:         pytest tests/test_alert_explainer.py -v -m integration
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.enrichment.alert_explainer import (
    DEFAULT_MODEL,
    _REQUIRED_KEYS,
    _VALID_FP,
    build_prompt,
    compute_combined_confidence,
    parse_response,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────

def _make_src(
    proc: str = "powershell.exe",
    parent: str = "cmd.exe",
    cmd: str = "powershell -EncodedCommand SQBFAFgA",
    user: str = "SYSTEM",
    host: str = "DC01.corp.local",
    category: str = "process_creation",
    channel: str = "Microsoft-Windows-Sysmon/Operational",
    score: float = 0.95,
    percentile: float = 98.5,
    dataset: str = "empire_psexec_lateral",
) -> dict:
    return {
        "@timestamp":    "2020-09-21T02:14:36.000Z",
        "host":          {"name": host},
        "user":          {"name": user},
        "process":       {"name": proc, "command_line": cmd, "parent": {"name": parent}},
        "event":         {"category": category, "channel": channel, "id": "1"},
        "source_dataset": dataset,
        "ml": {
            "anomaly_score":      score,
            "anomaly_percentile": percentile,
            "is_anomaly":         True,
            "top_features": [
                {"feature": "proc_rarity",       "z_score": 3.45},
                {"feature": "parent_child_rarity","z_score": 2.87},
                {"feature": "cmd_has_encoding",  "z_score": 1.23},
            ],
        },
    }


GOOD_RESPONSE = json.dumps({
    "attack_technique":    "T1059.001",
    "attack_tactic":       "Execution",
    "description":         "PowerShell launched with an encoded command to hide payload.",
    "fp_assessment":       "low",
    "fp_reasoning":        "Encoded PowerShell has no legitimate administrative use here.",
    "investigation_steps": [
        "Decode the base64 payload and scan for IOCs",
        "Check for outbound connections from the host within 60 s",
        "Review parent process tree to find how cmd.exe was launched",
    ],
})

MARKDOWN_WRAPPED = f"```json\n{GOOD_RESPONSE}\n```"

PROSE_WITH_JSON = f"Here is my analysis:\n{GOOD_RESPONSE}\nHope that helps!"

MISSING_KEY_RESPONSE = json.dumps({
    "attack_technique": "T1059.001",
    "attack_tactic":    "Execution",
    # missing description, fp_assessment, fp_reasoning, investigation_steps
})

INVALID_FP_RESPONSE = json.dumps({
    "attack_technique":    "T1059.001",
    "attack_tactic":       "Execution",
    "description":         "Something happened.",
    "fp_assessment":       "VERY_HIGH",   # not in {low, medium, high}
    "fp_reasoning":        "Looks bad.",
    "investigation_steps": ["Step 1"],
})

NO_JSON_RESPONSE = "I cannot determine the ATT&CK technique from this data."


# ── build_prompt tests ────────────────────────────────────────────────────────

class TestBuildPrompt:
    def test_returns_string(self):
        prompt = build_prompt(_make_src())
        assert isinstance(prompt, str)

    def test_contains_process_name(self):
        prompt = build_prompt(_make_src(proc="mimikatz.exe"))
        assert "mimikatz.exe" in prompt

    def test_contains_command_line(self):
        cmd = "powershell -EncodedCommand SQBFAFgA"
        prompt = build_prompt(_make_src(cmd=cmd))
        assert cmd in prompt

    def test_contains_anomaly_score(self):
        prompt = build_prompt(_make_src(score=0.9876))
        assert "0.9876" in prompt

    def test_null_process_renders_as_unknown(self):
        src = _make_src()
        src["process"]["name"] = None
        prompt = build_prompt(src)
        assert "unknown" in prompt

    def test_no_command_line_renders_gracefully(self):
        src = _make_src()
        src["process"]["command_line"] = None
        prompt = build_prompt(src)
        assert "(not recorded)" in prompt

    def test_prompt_requests_json_output(self):
        prompt = build_prompt(_make_src())
        assert "JSON" in prompt
        assert "attack_technique" in prompt
        assert "investigation_steps" in prompt

    def test_empty_source_does_not_raise(self):
        prompt = build_prompt({})
        assert isinstance(prompt, str)
        assert "unknown" in prompt

    def test_contains_required_statistical_phrase(self):
        prompt = build_prompt(_make_src())
        assert "statistically unusual for this specific environment" in prompt

    def test_contains_percentile(self):
        prompt = build_prompt(_make_src(percentile=97.3))
        assert "97.3" in prompt

    def test_contains_top_features(self):
        prompt = build_prompt(_make_src())
        assert "proc_rarity" in prompt

    def test_percentile_unavailable_renders_gracefully(self):
        src = _make_src()
        src["ml"].pop("anomaly_percentile", None)
        prompt = build_prompt(src)
        assert "percentile unavailable" in prompt

    def test_no_top_features_renders_gracefully(self):
        src = _make_src()
        src["ml"].pop("top_features", None)
        prompt = build_prompt(src)
        assert "not available" in prompt


# ── compute_combined_confidence tests ─────────────────────────────────────────

class TestComputeCombinedConfidence:
    def test_returns_all_required_keys(self):
        result = compute_combined_confidence(0.9, 95.0, "low")
        for key in ("combined_confidence", "llm_confidence",
                    "if_llm_disagreement", "routing_decision"):
            assert key in result

    def test_high_score_low_fp_gives_high_combined(self):
        result = compute_combined_confidence(0.95, 99.0, "low")
        # low FP = llm_conf=1.0; high score; high percentile → high combined
        assert result["combined_confidence"] > 0.7

    def test_high_score_high_fp_gives_low_combined(self):
        result = compute_combined_confidence(0.95, 99.0, "high")
        # high FP = llm_conf=0.2 → pulls combined down
        assert result["combined_confidence"] < 0.7

    def test_fp_assessment_maps_to_llm_confidence_correctly(self):
        # low FP → high TP confidence
        assert compute_combined_confidence(0.8, 90.0, "low")["llm_confidence"]   == 1.0
        assert compute_combined_confidence(0.8, 90.0, "medium")["llm_confidence"] == 0.6
        assert compute_combined_confidence(0.8, 90.0, "high")["llm_confidence"]  == 0.2

    def test_disagreement_fires_when_if_high_llm_low(self):
        # if_score > 0.8 AND llm_conf < 0.3 (fp_assessment="high" → llm_conf=0.2)
        result = compute_combined_confidence(0.9, 95.0, "high")
        assert result["if_llm_disagreement"] is True

    def test_no_disagreement_when_both_agree(self):
        # IF high + LLM confident → no disagreement
        result = compute_combined_confidence(0.9, 95.0, "low")
        assert result["if_llm_disagreement"] is False

    def test_no_disagreement_when_if_score_low(self):
        # IF score below threshold even if LLM says FP
        result = compute_combined_confidence(0.6, 60.0, "high")
        assert result["if_llm_disagreement"] is False

    def test_routing_tier1_when_combined_high(self):
        result = compute_combined_confidence(0.95, 99.0, "low")
        assert result["routing_decision"] == "tier-1"

    def test_routing_auto_close_when_combined_low(self):
        result = compute_combined_confidence(0.3, 30.0, "high")
        assert result["routing_decision"] == "auto-close"

    def test_combined_in_zero_one_range(self):
        for if_s in [0.1, 0.5, 0.9]:
            for pct in [10.0, 50.0, 99.0]:
                for fp in ["low", "medium", "high"]:
                    r = compute_combined_confidence(if_s, pct, fp)
                    assert 0.0 <= r["combined_confidence"] <= 1.0

    def test_none_percentile_falls_back_to_if_score(self):
        r_none = compute_combined_confidence(0.8, None, "low")
        r_same = compute_combined_confidence(0.8, 80.0, "low")
        # pct_norm = if_score = 0.8, so results should match
        assert abs(r_none["combined_confidence"] - r_same["combined_confidence"]) < 0.001

    def test_unknown_fp_defaults_to_medium(self):
        result = compute_combined_confidence(0.8, 80.0, "unknown_value")
        assert result["llm_confidence"] == 0.5


# ── parse_response tests ──────────────────────────────────────────────────────

class TestParseResponse:
    def test_valid_json_returns_dict(self):
        result = parse_response(GOOD_RESPONSE)
        assert isinstance(result, dict)

    def test_all_required_keys_present(self):
        result = parse_response(GOOD_RESPONSE)
        assert result is not None
        assert _REQUIRED_KEYS.issubset(set(result.keys()))

    def test_fp_assessment_is_normalised_lowercase(self):
        result = parse_response(GOOD_RESPONSE)
        assert result["fp_assessment"] in _VALID_FP

    def test_markdown_fences_stripped(self):
        result = parse_response(MARKDOWN_WRAPPED)
        assert result is not None
        assert result["attack_technique"] == "T1059.001"

    def test_json_embedded_in_prose(self):
        result = parse_response(PROSE_WITH_JSON)
        assert result is not None
        assert result["attack_tactic"] == "Execution"

    def test_missing_required_keys_returns_none(self):
        result = parse_response(MISSING_KEY_RESPONSE)
        assert result is None

    def test_invalid_fp_value_normalised_to_medium(self):
        result = parse_response(INVALID_FP_RESPONSE)
        assert result is not None
        assert result["fp_assessment"] == "medium"

    def test_no_json_in_response_returns_none(self):
        result = parse_response(NO_JSON_RESPONSE)
        assert result is None

    def test_empty_string_returns_none(self):
        assert parse_response("") is None

    def test_investigation_steps_is_list_of_strings(self):
        result = parse_response(GOOD_RESPONSE)
        assert isinstance(result["investigation_steps"], list)
        for step in result["investigation_steps"]:
            assert isinstance(step, str)

    def test_investigation_steps_capped_at_five(self):
        """LLM occasionally returns more steps than requested."""
        too_many = json.dumps({
            **json.loads(GOOD_RESPONSE),
            "investigation_steps": [f"Step {i}" for i in range(10)],
        })
        result = parse_response(too_many)
        assert result is not None
        assert len(result["investigation_steps"]) <= 5


# ── Integration tests ─────────────────────────────────────────────────────────

@pytest.mark.integration
class TestIntegration:
    """
    Requires: ES with security-scores-if populated, Ollama with llama3.2:3b.

    Run with: pytest tests/test_alert_explainer.py -v -m integration
    """

    def test_dry_run_finds_and_processes_anomalies(self, capsys):
        from src.enrichment.alert_explainer import run

        summary = run(dry_run=True, verbose=False, limit=3, model=DEFAULT_MODEL)

        assert summary["processed"] >= 1, "Expected at least 1 unenriched anomaly"
        assert summary["dry_run"] is True
        assert summary["model"] == DEFAULT_MODEL

    def test_live_enrichment_writes_llm_triage(self):
        import os
        from elasticsearch import Elasticsearch
        from src.enrichment.alert_explainer import SCORES_INDEX, run

        summary = run(dry_run=False, verbose=False, limit=3, model=DEFAULT_MODEL)
        assert summary["succeeded"] >= 1

        es   = Elasticsearch(os.getenv("ELASTIC_URL", "http://localhost:9200"))
        resp = es.search(
            index=SCORES_INDEX,
            body={
                "query":  {"exists": {"field": "ml.llm_triage"}},
                "size":   3,
                "sort":   [{"ml.anomaly_score": "desc"}],
                "_source": ["ml"],
            },
        )
        for hit in resp["hits"]["hits"]:
            triage = hit["_source"]["ml"].get("llm_triage", {})
            assert "attack_technique" in triage
            assert "investigation_steps" in triage
            assert isinstance(triage["investigation_steps"], list)
            # Verify ml.anomaly_score was NOT wiped by the update
            assert "anomaly_score" in hit["_source"]["ml"]
