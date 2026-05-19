"""
Tests for feature_engineering.py and isolation_forest.py.

Unit tests use synthetic event dicts — no Elasticsearch required.
Integration tests (marked with @pytest.mark.integration) require a running
ES cluster and the security-events-mordor index to be populated.

Run unit tests only:   pytest tests/test_isolation_forest.py -v
Run integration tests: pytest tests/test_isolation_forest.py -v -m integration
"""

from __future__ import annotations

import sys
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.models.feature_engineering import (
    FEATURE_NAMES,
    build_feature_matrix,
    build_frequency_tables,
    extract_row,
)
from src.models.isolation_forest import compute_scores, train


# ── Fixtures ──────────────────────────────────────────────────────────────────

def _make_event(
    proc: str = "cmd.exe",
    parent: str = "explorer.exe",
    user: str = "SYSTEM",
    host: str = "DC01.corp.local",
    category: str = "process_creation",
    channel: str = "Microsoft-Windows-Sysmon/Operational",
    event_id: str = "1",
    cmd: str = "",
    timestamp: str = "2020-09-21T02:14:36.000Z",
    dataset: str = "test",
) -> dict:
    """Return a minimal ECS-aligned event dict for testing."""
    return {
        "@timestamp": timestamp,
        "host":   {"name": host},
        "user":   {"name": user},
        "process": {
            "name": proc,
            "command_line": cmd or None,
            "parent": {"name": parent},
        },
        "event": {
            "category": category,
            "id":       event_id,
            "channel":  channel,
        },
        "source_dataset": dataset,
    }


SYNTHETIC_EVENTS = [
    _make_event("cmd.exe",        "explorer.exe",  category="process_creation",  event_id="1"),
    _make_event("cmd.exe",        "explorer.exe",  category="process_creation",  event_id="1"),
    _make_event("cmd.exe",        "explorer.exe",  category="process_creation",  event_id="1"),
    _make_event("powershell.exe", "cmd.exe",       category="process_creation",  event_id="1",
                cmd="powershell -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAn"),
    _make_event("msbuild.exe",    "winword.exe",   category="process_creation",  event_id="1"),
    _make_event("svchost.exe",    "services.exe",  category="process_access",    event_id="10"),
    _make_event("lsass.exe",      "svchost.exe",   category="process_access",    event_id="10"),
    _make_event(proc=None,        parent=None,     category="script_execution",  event_id="800",
                channel="Windows PowerShell"),
    _make_event(proc=None,        parent=None,     category="registry_event",    event_id="13",
                channel="Microsoft-Windows-Sysmon/Operational"),
    _make_event("mimikatz.exe",   "cmd.exe",       category="process_creation",  event_id="1",
                cmd="mimikatz sekurlsa::logonpasswords"),
]


# ── Feature engineering unit tests ────────────────────────────────────────────

class TestBuildFrequencyTables:
    def test_proc_counter_counts_correctly(self):
        freq = build_frequency_tables(SYNTHETIC_EVENTS)
        # events 0,1,2 have process.name=cmd.exe; parent names go into freq["parent"]
        assert freq["proc"]["cmd.exe"] == 3

    def test_missing_proc_not_counted(self):
        freq = build_frequency_tables(SYNTHETIC_EVENTS)
        assert freq["proc"].get("None", 0) == 0

    def test_parent_child_pair_counted(self):
        freq = build_frequency_tables(SYNTHETIC_EVENTS)
        assert freq["parent_child"][("explorer.exe", "cmd.exe")] == 3

    def test_returns_all_expected_keys(self):
        freq = build_frequency_tables(SYNTHETIC_EVENTS)
        assert set(freq.keys()) == {"proc", "parent", "parent_child", "user", "host_event"}


class TestExtractRow:
    def setup_method(self):
        self.freq = build_frequency_tables(SYNTHETIC_EVENTS)
        self.n    = len(SYNTHETIC_EVENTS)

    def test_returns_all_feature_names(self):
        row = extract_row(SYNTHETIC_EVENTS[0], self.freq, self.n)
        assert set(row.keys()) == set(FEATURE_NAMES)

    def test_has_cmd_is_zero_when_no_command_line(self):
        row = extract_row(SYNTHETIC_EVENTS[7], self.freq, self.n)  # script_execution, no cmd
        assert row["has_cmd"] == 0

    def test_has_cmd_is_one_when_command_line_present(self):
        row = extract_row(SYNTHETIC_EVENTS[3], self.freq, self.n)  # powershell with -EncodedCommand
        assert row["has_cmd"] == 1

    def test_cmd_has_encoding_detects_base64(self):
        row = extract_row(SYNTHETIC_EVENTS[3], self.freq, self.n)
        assert row["cmd_has_encoding"] == 1

    def test_cmd_has_encoding_false_for_normal_cmd(self):
        row = extract_row(SYNTHETIC_EVENTS[0], self.freq, self.n)
        assert row["cmd_has_encoding"] == 0

    def test_rare_proc_gets_higher_rarity_than_common_proc(self):
        # msbuild.exe (1 occurrence) should be rarer than cmd.exe (many occurrences)
        row_msbuild = extract_row(SYNTHETIC_EVENTS[4], self.freq, self.n)
        row_cmd     = extract_row(SYNTHETIC_EVENTS[0], self.freq, self.n)
        assert row_msbuild["proc_rarity"] > row_cmd["proc_rarity"]

    def test_null_proc_gives_zero_rarity(self):
        row = extract_row(SYNTHETIC_EVENTS[7], self.freq, self.n)
        assert row["proc_rarity"] == 0.0

    def test_hour_extracted_from_timestamp(self):
        row = extract_row(SYNTHETIC_EVENTS[0], self.freq, self.n)
        assert 0 <= row["hour"] <= 23

    def test_all_values_are_numeric(self):
        row = extract_row(SYNTHETIC_EVENTS[0], self.freq, self.n)
        for k, v in row.items():
            assert isinstance(v, (int, float)), f"{k} is not numeric: {type(v)}"


class TestBuildFeatureMatrix:
    def test_returns_dataframe(self):
        df = build_feature_matrix(SYNTHETIC_EVENTS)
        assert isinstance(df, pd.DataFrame)

    def test_row_count_matches_event_count(self):
        df = build_feature_matrix(SYNTHETIC_EVENTS)
        assert len(df) == len(SYNTHETIC_EVENTS)

    def test_column_names_match_feature_names(self):
        df = build_feature_matrix(SYNTHETIC_EVENTS)
        assert list(df.columns) == FEATURE_NAMES

    def test_empty_input_returns_empty_dataframe(self):
        df = build_feature_matrix([])
        assert df.empty
        assert list(df.columns) == FEATURE_NAMES

    def test_no_null_values_in_matrix(self):
        df = build_feature_matrix(SYNTHETIC_EVENTS)
        assert not df.isnull().any().any(), "Feature matrix must have no NaN values"

    def test_source_wrapper_handled(self):
        """Events wrapped in {'_source': {...}} (ES format) must work too."""
        wrapped = [{"_id": f"id{i}", "_source": e} for i, e in enumerate(SYNTHETIC_EVENTS)]
        df = build_feature_matrix(wrapped)
        assert len(df) == len(SYNTHETIC_EVENTS)


# ── Isolation Forest unit tests ───────────────────────────────────────────────

class TestTrainAndScore:
    def setup_method(self):
        df = build_feature_matrix(SYNTHETIC_EVENTS)
        self.X = df.values.astype(np.float32)

    def test_train_returns_model_and_scaler(self):
        model, scaler = train(self.X, contamination=0.1)
        assert model is not None
        assert scaler is not None

    def test_scores_in_zero_one_range(self):
        model, scaler = train(self.X, contamination=0.1)
        scores, _ = compute_scores(model, scaler, self.X)
        assert scores.min() >= 0.0
        assert scores.max() <= 1.0

    def test_is_anomaly_is_boolean_array(self):
        model, scaler = train(self.X, contamination=0.1)
        _, is_anom = compute_scores(model, scaler, self.X)
        assert is_anom.dtype == bool

    def test_anomaly_count_matches_contamination(self):
        contamination = 0.2
        model, scaler = train(self.X, contamination=contamination)
        _, is_anom = compute_scores(model, scaler, self.X)
        expected = int(len(SYNTHETIC_EVENTS) * contamination)
        # sklearn IF guarantees exactly floor(contamination * n) anomalies
        assert int(is_anom.sum()) == expected

    def test_mimikatz_scores_higher_than_svchost(self):
        """
        Security intuition: mimikatz.exe (proc_rarity very high, suspicious cmd)
        should score higher than svchost.exe (common, no command line).
        """
        model, scaler = train(self.X, contamination=0.1)
        scores, _    = compute_scores(model, scaler, self.X)
        mimikatz_idx = 9   # SYNTHETIC_EVENTS[9] = mimikatz.exe
        svchost_idx  = 5   # SYNTHETIC_EVENTS[5] = svchost.exe
        assert scores[mimikatz_idx] >= scores[svchost_idx], (
            f"Expected mimikatz ({scores[mimikatz_idx]:.4f}) >= "
            f"svchost ({scores[svchost_idx]:.4f})"
        )


# ── Integration tests (require live ES + populated index) ─────────────────────

@pytest.mark.integration
class TestIntegration:
    """
    These tests hit real Elasticsearch. Run with:
        pytest tests/test_isolation_forest.py -v -m integration
    """

    def test_scores_index_created_and_populated(self):
        from elasticsearch import Elasticsearch
        from src.models.isolation_forest import SCORES_INDEX, run

        summary = run(dry_run=False, verbose=False, contamination=0.05)

        assert summary["events_scored"] > 1000, "Expected > 1000 events scored"
        assert summary["anomalies_found"] > 0,  "Expected at least one anomaly"
        assert not summary["dry_run"]

        client = Elasticsearch(os.getenv("ELASTIC_URL", "http://localhost:9200"))
        resp   = client.count(index=SCORES_INDEX)
        assert resp["count"] > 1000, "Scores index should have > 1000 documents"

    def test_top_anomalies_have_ml_fields(self):
        import os
        from elasticsearch import Elasticsearch
        from src.models.isolation_forest import SCORES_INDEX

        client = Elasticsearch(os.getenv("ELASTIC_URL", "http://localhost:9200"))
        resp   = client.search(
            index=SCORES_INDEX,
            body={
                "size": 5,
                "sort": [{"ml.anomaly_score": "desc"}],
                "_source": ["ml", "event", "process", "source_dataset"],
            },
        )
        for hit in resp["hits"]["hits"]:
            ml = hit["_source"].get("ml", {})
            assert "anomaly_score" in ml
            assert "is_anomaly"    in ml
            assert "model"         in ml
            assert ml["anomaly_score"] > 0.5, "Top anomalies should have score > 0.5"
