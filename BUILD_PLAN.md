# Build plan

## Phase 1 — Infrastructure (target: 1 hour) ✅ COMPLETE
- [x] docker-compose.yml with all four services
- [x] Custom Dockerfiles for jupyter and streamlit
- [x] docker/jupyter/requirements.txt
- [x] Verify: all containers start, ES responds on :9200
- Verified: `curl localhost:9200/_cluster/health` → status green, 4/4 containers healthy

## Phase 2 — Data ingestion (target: 30 min) ✅ COMPLETE
- [x] Download OTRF Mordor small dataset to data/raw/ (6 zips, 3 ATT&CK tactic categories)
- [x] src/ingest/load_mordor.py — bulk index to security-events-mordor
- [x] Verify: index exists, document count > 1000
- Verified: 30,033 documents indexed; event categories: script_execution (14,641), registry_event (3,637), process_access (3,415), process_creation (88), authentication (72), network_connection (132)

## Phase 3 — Isolation Forest model (target: 1 hour) ✅ COMPLETE
- [x] src/models/isolation_forest.py — 200-tree IF, StandardScaler, --dry-run/--verbose
- [x] src/models/feature_engineering.py — 13 features: rarity scores, event category, channel, EventID, cmd indicators
- [x] Writes security-scores-if index — 30,033 scored docs, 1,243 flagged anomalies (4.1%)
- [x] tests/test_isolation_forest.py — 24/24 unit tests pass, 2 integration tests (require ES)
- [x] Verify: top anomalies confirmed ATT&CK techniques — PsExec (T1021.002), WMI execution (T1047), PowerShell (T1059.001), whoami recon (T1033), wmiprvse.exe LOLBin (T1218)
- Model saved to data/models/isolation_forest.pkl

## Phase 4 — LLM enrichment (target: 45 min) ✅ COMPLETE
- [x] Pull llama3.2:3b into ollama (2.0 GB, ~6 min/alert on CPU — GPU would be ~10 s)
- [x] src/enrichment/alert_explainer.py — idempotent, Painless script update, --dry-run/--verbose/--limit/--model
- [x] Writes ml.llm_triage back to security-scores-if (10 alerts written; remainder via nightly scheduler sweep)
- [x] Verify (dry-run): top 5 alerts returned coherent ATT&CK mapping (T1059.001, T1021.002), fp_assessment, and 3 investigation steps
- tests/test_alert_explainer.py — 19/19 unit tests pass (build_prompt + parse_response; no Ollama/ES required)
- Note: 3b model anchors to prompt example for near-identical events; use llama3.1:8b for weekly sweep

## Phase 5 — Streamlit dashboard (target: 1 hour) ✅ COMPLETE
- [x] src/dashboard/app.py — full rewrite; three tabs (Alert Queue, Model Metrics, Dataset Summary)
- [x] Alert Queue: st.dataframe row selection → inline LLM triage panel with ATT&CK badge, FP colour, investigation steps; "Enrich now" button for unenriched alerts; raw event expander
- [x] Model Metrics: score distribution histogram with threshold line, anomalies-by-category horizontal bar chart, 4-KPI header row
- [x] Dataset Summary: events-by-dataset bar chart, top-15-categories bar chart, enrichment progress bar
- [x] Bugfix: ml.llm_triage has mapping enabled:false so ES exists queries silently return zero; added indexed ml.enriched boolean flag; backfilled 2 existing enriched docs via Update By Query using Painless _source inspection
- [x] Verify: dashboard at :8501 HTTP 200, all panels render, enriched alert row shows full triage, unenriched row shows Enrich Now button

## Phase 6 — Scheduler and retrain loop (target: 30 min) ✅ COMPLETE
- [x] src/scheduler/nightly_retrain.py — APScheduler CronTrigger; retrain daily@02:00 UTC, enrichment sweep weekly Sun@03:00 UTC; --dry-run/--verbose/--run-now/--enrich-limit/--enrich-model
- [x] data/runs/ — JSON audit trail; one file per run: {job_type}_{YYYYMMDD_HHMMSS}.json with started_at, completed_at, duration_seconds, result, errors
- [x] Verify: --dry-run --run-now retrain completed in 75.9 s; retrain_20260519_091326.json written; 30,033 events scored, 1,243 anomalies, 0 errors
- [x] tests/test_nightly_retrain.py — 18/18 unit tests pass; all tests use tmp_path, no real data/runs/ writes during CI
- Full test suite: 61/61 unit tests pass (test_isolation_forest + test_alert_explainer + test_nightly_retrain)

## Current phase: complete
## Last completed: Phase 6 — Scheduler and retrain loop
## Blockers: none