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

## Phase 3 — Isolation Forest model (target: 1 hour)
- [ ] src/models/isolation_forest.py
- [ ] src/models/feature_engineering.py (shared feature logic)
- [ ] Writes security-scores-if index
- [ ] tests/test_isolation_forest.py
- [ ] Verify: top anomalies look like real ATT&CK techniques

## Phase 4 — LLM enrichment (target: 45 min)
- [ ] Pull llama3.1:8b into ollama
- [ ] src/enrichment/alert_explainer.py
- [ ] Writes ml.llm_triage back to security-scores-if
- [ ] Verify: top 5 alerts have coherent ATT&CK mapping and investigation steps

## Phase 5 — Streamlit dashboard (target: 1 hour)
- [ ] src/dashboard/app.py with all four panels
- [ ] Verify: dashboard loads at :8501, alert click shows LLM triage

## Phase 6 — Scheduler and retrain loop (target: 30 min)
- [ ] src/scheduler/nightly_retrain.py
- [ ] data/runs/ directory with JSON audit trail
- [ ] Verify: --dry-run completes, JSON run summary written

## Current phase: 3
## Last completed: Phase 2 — Data ingestion
## Blockers: none