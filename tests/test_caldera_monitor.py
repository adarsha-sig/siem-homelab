"""
Unit tests for src/redblue/caldera_monitor.py.

No live CALDERA server or Elasticsearch required.
All functions under test are pure (no I/O) or use monkeypatching for I/O.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.redblue.caldera_monitor import (
    _demo_scorecard,
    _hostname_from_link,
    _link_timestamp,
    _technique_from_link,
    print_scorecard,
    write_scorecard,
)


# ── _technique_from_link ──────────────────────────────────────────────────────

class TestTechniqueFromLink:
    def test_extracts_technique_id(self):
        link = {"ability": {"technique_id": "T1087.001", "name": "Enum users"}}
        assert _technique_from_link(link) == "T1087.001"

    def test_empty_technique_id_falls_back_to_ability_name(self):
        link = {"ability": {"technique_id": "", "name": "My ability"}, "id": "abc"}
        assert _technique_from_link(link) == "unknown:My ability"

    def test_none_technique_id_falls_back_to_ability_name(self):
        link = {"ability": {"technique_id": None, "name": "Dump creds"}, "id": "abc"}
        assert _technique_from_link(link) == "unknown:Dump creds"

    def test_missing_ability_falls_back_to_link_id(self):
        link = {"id": "link-uuid-123"}
        result = _technique_from_link(link)
        assert result.startswith("unknown:")
        assert "link-uuid-123" in result

    def test_empty_link_uses_fallback(self):
        result = _technique_from_link({"id": "x"})
        assert result.startswith("unknown:")


# ── _link_timestamp ───────────────────────────────────────────────────────────

class TestLinkTimestamp:
    def test_parses_finish_timestamp(self):
        link = {"finish": "2026-05-20T12:00:00Z"}
        ts = _link_timestamp(link)
        assert ts is not None
        assert ts.tzinfo is not None
        assert ts.year == 2026 and ts.month == 5 and ts.day == 20

    def test_falls_back_to_create_when_no_finish(self):
        link = {"create": "2026-05-20T09:30:00Z"}
        ts = _link_timestamp(link)
        assert ts is not None
        assert ts.hour == 9

    def test_prefers_finish_over_create(self):
        link = {"finish": "2026-05-20T14:00:00Z", "create": "2026-05-20T12:00:00Z"}
        ts = _link_timestamp(link)
        assert ts.hour == 14

    def test_returns_none_when_both_absent(self):
        assert _link_timestamp({}) is None

    def test_returns_none_on_unparseable_string(self):
        assert _link_timestamp({"finish": "not-a-date"}) is None

    def test_returns_none_on_empty_string(self):
        assert _link_timestamp({"finish": ""}) is None

    def test_utc_timezone_attached(self):
        ts = _link_timestamp({"finish": "2026-01-01T00:00:00Z"})
        assert ts is not None
        assert ts.utcoffset().total_seconds() == 0


# ── _hostname_from_link ───────────────────────────────────────────────────────

class TestHostnameFromLink:
    def test_returns_lowercase_host(self):
        link = {"host": "VICTIM-WIN10"}
        assert _hostname_from_link(link) == "victim-win10"

    def test_falls_back_to_paw(self):
        link = {"paw": "abc123"}
        assert _hostname_from_link(link) == "abc123"

    def test_returns_unknown_when_both_absent(self):
        assert _hostname_from_link({}) == "unknown"

    def test_already_lowercase_unchanged(self):
        link = {"host": "workstation-01"}
        assert _hostname_from_link(link) == "workstation-01"

    def test_prefers_host_over_paw(self):
        link = {"host": "REAL-HOST", "paw": "abc123"}
        assert _hostname_from_link(link) == "real-host"


# ── _demo_scorecard ───────────────────────────────────────────────────────────

class TestDemoScorecard:
    def test_returns_dict(self):
        assert isinstance(_demo_scorecard(), dict)

    def test_required_top_level_keys_present(self):
        s = _demo_scorecard()
        required = {
            "operation", "operation_name", "generated_at", "demo",
            "techniques_executed", "detected", "missed",
            "detection_rate", "technique_results", "missed_techniques",
        }
        missing = required - set(s.keys())
        assert not missing, f"missing keys: {missing}"

    def test_demo_flag_is_true(self):
        assert _demo_scorecard()["demo"] is True

    def test_counts_consistent(self):
        s = _demo_scorecard()
        assert s["detected"] + s["missed"] == s["techniques_executed"]

    def test_detection_rate_matches_counts(self):
        s = _demo_scorecard()
        expected = round(s["detected"] / s["techniques_executed"], 4)
        assert abs(s["detection_rate"] - expected) < 0.001

    def test_missed_list_length_matches_count(self):
        s = _demo_scorecard()
        assert len(s["missed_techniques"]) == s["missed"]

    def test_technique_results_list_length_matches_executed(self):
        s = _demo_scorecard()
        assert len(s["technique_results"]) == s["techniques_executed"]

    def test_each_technique_result_has_required_fields(self):
        required = {
            "technique_id", "ability_name", "hostname", "executed_at",
            "detected", "max_score", "detecting_events",
        }
        for r in _demo_scorecard()["technique_results"]:
            missing = required - set(r.keys())
            assert not missing, f"technique result missing: {missing}"

    def test_detected_results_have_positive_score(self):
        for r in _demo_scorecard()["technique_results"]:
            if r["detected"]:
                assert r["max_score"] > 0

    def test_missed_results_have_zero_score(self):
        for r in _demo_scorecard()["technique_results"]:
            if not r["detected"]:
                assert r["max_score"] == 0.0

    def test_missed_technique_ids_match_results(self):
        s = _demo_scorecard()
        missed_from_results = {
            r["technique_id"] for r in s["technique_results"] if not r["detected"]
        }
        assert missed_from_results == set(s["missed_techniques"])


# ── write_scorecard ───────────────────────────────────────────────────────────

class TestWriteScorecard:
    def test_creates_json_file(self, tmp_path, monkeypatch):
        import src.redblue.caldera_monitor as m
        monkeypatch.setattr(m, "RUNS_DIR", tmp_path)
        path = write_scorecard(_demo_scorecard())
        assert path.exists()

    def test_json_is_valid_and_round_trips(self, tmp_path, monkeypatch):
        import src.redblue.caldera_monitor as m
        monkeypatch.setattr(m, "RUNS_DIR", tmp_path)
        sc = _demo_scorecard()
        path = write_scorecard(sc)
        loaded = json.loads(path.read_text())
        assert loaded["operation"] == sc["operation"]
        assert loaded["detection_rate"] == sc["detection_rate"]

    def test_filename_contains_live_detection_prefix(self, tmp_path, monkeypatch):
        import src.redblue.caldera_monitor as m
        monkeypatch.setattr(m, "RUNS_DIR", tmp_path)
        path = write_scorecard(_demo_scorecard())
        assert path.name.startswith("live_detection_")
        assert path.suffix == ".json"

    def test_filename_contains_date(self, tmp_path, monkeypatch):
        import src.redblue.caldera_monitor as m
        monkeypatch.setattr(m, "RUNS_DIR", tmp_path)
        path = write_scorecard(_demo_scorecard())
        # Filename: live_detection_YYYY-MM-DD.json (3 underscore segments)
        parts = path.stem.split("_")
        assert len(parts) == 3, f"unexpected stem: {path.stem}"
        date_str = parts[2]  # "YYYY-MM-DD"
        datetime.strptime(date_str, "%Y-%m-%d")  # raises if not a valid date

    def test_overwrites_same_day_file(self, tmp_path, monkeypatch):
        import src.redblue.caldera_monitor as m
        monkeypatch.setattr(m, "RUNS_DIR", tmp_path)
        write_scorecard(_demo_scorecard())
        write_scorecard(_demo_scorecard())
        files = list(tmp_path.glob("live_detection_*.json"))
        assert len(files) == 1  # overwritten, not duplicated

    def test_creates_runs_dir_if_absent(self, tmp_path, monkeypatch):
        import src.redblue.caldera_monitor as m
        target = tmp_path / "nested" / "runs"
        monkeypatch.setattr(m, "RUNS_DIR", target)
        write_scorecard(_demo_scorecard())
        assert target.exists()


# ── print_scorecard ───────────────────────────────────────────────────────────

class TestPrintScorecard:
    def test_does_not_crash(self, capsys):
        print_scorecard(_demo_scorecard())
        out = capsys.readouterr().out
        assert len(out) > 0

    def test_shows_detection_rate(self, capsys):
        print_scorecard(_demo_scorecard())
        assert "Detection rate" in capsys.readouterr().out

    def test_shows_missed_technique(self, capsys):
        print_scorecard(_demo_scorecard())
        # T1070.004 is the missed technique in the demo scorecard
        assert "T1070.004" in capsys.readouterr().out

    def test_shows_detected_technique(self, capsys):
        print_scorecard(_demo_scorecard())
        assert "T1087.001" in capsys.readouterr().out

    def test_avg_latency_shown(self, capsys):
        print_scorecard(_demo_scorecard())
        out = capsys.readouterr().out
        assert "latency" in out.lower() or "Avg" in out
