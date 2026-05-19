"""
Tests for src/scheduler/nightly_retrain.py.

All unit tests use tmp_path so nothing is written to data/runs/ during CI.
Integration tests (marked @pytest.mark.integration) require a running
Elasticsearch cluster with a populated security-events-mordor index.

Run unit tests:   pytest tests/test_nightly_retrain.py -v -m "not integration"
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.scheduler.nightly_retrain import _build_summary, write_run_summary


# ── Fixtures ──────────────────────────────────────────────────────────────────

STARTED_AT = datetime(2024, 5, 19, 2, 0, 0, tzinfo=timezone.utc)

RETRAIN_RESULT = {
    "events_scored":   30033,
    "anomalies_found": 1243,
    "contamination":   0.05,
    "written":         30033,
    "dry_run":         False,
}

ENRICH_RESULT = {
    "processed":  50,
    "succeeded":  48,
    "failed":     2,
    "dry_run":    False,
    "model":      "llama3.2:3b",
}


# ── _build_summary tests ──────────────────────────────────────────────────────

class TestBuildSummary:
    def test_has_all_required_keys(self):
        s = _build_summary("retrain", STARTED_AT, RETRAIN_RESULT, [], False)
        for key in ("run_id", "job_type", "started_at", "completed_at",
                    "duration_seconds", "dry_run", "result", "errors"):
            assert key in s, f"Missing key: {key}"

    def test_job_type_preserved(self):
        s = _build_summary("retrain", STARTED_AT, RETRAIN_RESULT, [], False)
        assert s["job_type"] == "retrain"

    def test_dry_run_flag_preserved(self):
        s = _build_summary("retrain", STARTED_AT, RETRAIN_RESULT, [], True)
        assert s["dry_run"] is True

    def test_result_payload_preserved(self):
        s = _build_summary("retrain", STARTED_AT, RETRAIN_RESULT, [], False)
        assert s["result"]["events_scored"] == 30033
        assert s["result"]["anomalies_found"] == 1243

    def test_errors_list_empty_on_success(self):
        s = _build_summary("retrain", STARTED_AT, RETRAIN_RESULT, [], False)
        assert s["errors"] == []

    def test_errors_list_preserved_on_failure(self):
        errs = ["Traceback: Connection refused"]
        s = _build_summary("retrain", STARTED_AT, {}, errs, False)
        assert s["errors"] == errs

    def test_duration_is_positive_float(self):
        s = _build_summary("retrain", STARTED_AT, RETRAIN_RESULT, [], False)
        assert isinstance(s["duration_seconds"], float)
        assert s["duration_seconds"] >= 0

    def test_run_id_matches_started_at_format(self):
        s = _build_summary("retrain", STARTED_AT, RETRAIN_RESULT, [], False)
        # run_id should be "YYYYMMDD_HHMMSS"
        assert s["run_id"] == "20240519_020000"

    def test_started_at_is_iso_string(self):
        s = _build_summary("retrain", STARTED_AT, RETRAIN_RESULT, [], False)
        # Should parse back to a datetime without raising
        dt = datetime.fromisoformat(s["started_at"])
        assert dt.year == 2024

    def test_enrichment_job_type(self):
        s = _build_summary("enrichment", STARTED_AT, ENRICH_RESULT, [], False)
        assert s["job_type"] == "enrichment"
        assert s["result"]["processed"] == 50


# ── write_run_summary tests ───────────────────────────────────────────────────

class TestWriteRunSummary:
    def test_creates_file_in_runs_dir(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            "src.scheduler.nightly_retrain.RUNS_DIR", tmp_path
        )
        s = _build_summary("retrain", STARTED_AT, RETRAIN_RESULT, [], False)
        path = write_run_summary(s)
        assert path.exists()

    def test_file_is_valid_json(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            "src.scheduler.nightly_retrain.RUNS_DIR", tmp_path
        )
        s = _build_summary("retrain", STARTED_AT, RETRAIN_RESULT, [], False)
        path = write_run_summary(s)
        content = json.loads(path.read_text())
        assert content["job_type"] == "retrain"

    def test_filename_includes_job_type_and_run_id(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            "src.scheduler.nightly_retrain.RUNS_DIR", tmp_path
        )
        s = _build_summary("retrain", STARTED_AT, RETRAIN_RESULT, [], False)
        path = write_run_summary(s)
        assert "retrain" in path.name
        assert "20240519_020000" in path.name

    def test_dry_run_summary_written(self, tmp_path, monkeypatch):
        """Dry-run must still write the audit JSON so the operator can inspect it."""
        monkeypatch.setattr(
            "src.scheduler.nightly_retrain.RUNS_DIR", tmp_path
        )
        s = _build_summary("retrain", STARTED_AT, {}, [], dry_run=True)
        path = write_run_summary(s)
        content = json.loads(path.read_text())
        assert content["dry_run"] is True

    def test_enrichment_summary_filename(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            "src.scheduler.nightly_retrain.RUNS_DIR", tmp_path
        )
        s = _build_summary("enrichment", STARTED_AT, ENRICH_RESULT, [], False)
        path = write_run_summary(s)
        assert "enrichment" in path.name

    def test_returns_path_object(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            "src.scheduler.nightly_retrain.RUNS_DIR", tmp_path
        )
        s = _build_summary("retrain", STARTED_AT, RETRAIN_RESULT, [], False)
        result = write_run_summary(s)
        assert isinstance(result, Path)

    def test_multiple_runs_do_not_overwrite(self, tmp_path, monkeypatch):
        """Each run must produce a distinct file."""
        monkeypatch.setattr(
            "src.scheduler.nightly_retrain.RUNS_DIR", tmp_path
        )
        s1 = _build_summary("retrain", STARTED_AT, RETRAIN_RESULT, [], False)
        # Second run at a different second
        started2 = datetime(2024, 5, 19, 2, 0, 1, tzinfo=timezone.utc)
        s2 = _build_summary("retrain", started2, RETRAIN_RESULT, [], False)

        p1 = write_run_summary(s1)
        p2 = write_run_summary(s2)
        assert p1 != p2
        assert len(list(tmp_path.glob("*.json"))) == 2

    def test_runs_dir_created_if_absent(self, tmp_path, monkeypatch):
        target = tmp_path / "nested" / "runs"
        monkeypatch.setattr("src.scheduler.nightly_retrain.RUNS_DIR", target)
        s = _build_summary("retrain", STARTED_AT, RETRAIN_RESULT, [], False)
        write_run_summary(s)
        assert target.exists()


# ── Integration test ──────────────────────────────────────────────────────────

@pytest.mark.integration
class TestIntegration:
    """
    Requires a running ES cluster with security-events-mordor populated.
    Run with: pytest tests/test_nightly_retrain.py -v -m integration
    """

    def test_dry_run_retrain_produces_summary_file(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            "src.scheduler.nightly_retrain.RUNS_DIR", tmp_path
        )
        from src.scheduler.nightly_retrain import run_retrain
        summary = run_retrain(dry_run=True, verbose=False)

        # Summary returned from function
        assert summary["job_type"] == "retrain"
        assert summary["dry_run"] is True
        assert summary["result"].get("events_scored", 0) > 0
        assert summary["errors"] == []

        # File written to disk
        files = list(tmp_path.glob("retrain_*.json"))
        assert len(files) == 1
        content = json.loads(files[0].read_text())
        assert content["result"]["events_scored"] > 1000

    def test_dry_run_enrichment_produces_summary_file(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            "src.scheduler.nightly_retrain.RUNS_DIR", tmp_path
        )
        from src.scheduler.nightly_retrain import run_enrichment_sweep
        summary = run_enrichment_sweep(dry_run=True, verbose=False, limit=3)

        assert summary["job_type"] == "enrichment"
        assert summary["dry_run"] is True

        files = list(tmp_path.glob("enrichment_*.json"))
        assert len(files) == 1
