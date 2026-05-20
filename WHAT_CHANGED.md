# WHAT_CHANGED.md — SOC ML Lab: Full Upgrade Summary

This document records every significant decision made across the full build of
the SOC ML Lab, from blank repo to a live red/blue adversary-emulation loop.
It covers what was added, what was eliminated, why each choice was made, and
what the lab can do now that it could not do at the start.

---

## Starting point

A bare Docker Compose skeleton with Elasticsearch, Jupyter, Ollama, and
Streamlit. No ML pipeline, no data, no automation, no security logic.

---

## Phase 1 — Infrastructure

**Added:**
- `docker-compose.yml` with four services: Elasticsearch 8.14 (no-auth, single-node),
  Ollama, custom Jupyter (Python 3.11 + full ML stack baked into image), custom Streamlit.
- `ES_JAVA_OPTS=-Xms512m -Xmx1g` heap cap — prevents OOM on a constrained Mac.
- Named volumes (`es_data`, `ollama_models`) so data survives `docker compose down`.

**Why:** Everything in containers means zero host Python dependency conflicts and
identical behaviour on Mac, Linux, and Windows WSL2.

---

## Phase 2 — Data ingestion

**Added:**
- `src/ingest/load_mordor.py` — downloads 6 OTRF Mordor ATT&CK scenario ZIPs
  (lateral movement, credential access, execution) and bulk-indexes to ES.
- 30,033 documents; event categories span process_creation, script_execution,
  network_connection, authentication, registry_event.

**Why Mordor:** Labeled adversary-simulation data with known ATT&CK techniques.
The Isolation Forest has no labels at training time, but Mordor lets us verify
retrospectively that the model flags known-bad events.

---

## Phase 3 — Isolation Forest model

**Added:**
- `src/models/isolation_forest.py` (later subsumed by model_runner.py):
  200-tree IF, StandardScaler, 13 engineered features.
- `src/models/feature_engineering.py`: rarity scores, event category,
  Windows channel, EventID, cmd-line indicators.
- `security-scores-if` index with `ml.anomaly_score`, `ml.is_anomaly`.
- Model saved to `data/models/isolation_forest.pkl`.

**Why Isolation Forest:** No labeled data required. Trains on normal behaviour
and scores new events by how different they are from the training distribution.
Fast inference (milliseconds per event), interpretable (feature z-scores), and
well-validated on security telemetry in the literature.

**Why 13 features:** Deliberately small — the Mordor dataset has ~30,033 events
across 6 files. More features would require more data to avoid spurious anomalies
from the curse of dimensionality.

---

## Phase 4 — LLM enrichment

**Added:**
- `src/enrichment/alert_explainer.py` — sends IF-flagged anomalies to an LLM
  and writes back: ATT&CK technique, tactic, FP assessment, investigation steps.
- Three LLM backends via `LLM_BACKEND` env var:
  - `groq` (default) — Groq cloud, llama-3.1-8b-instant, ~0.5 s/alert, no GPU.
  - `claude` — Anthropic API, claude-haiku, highest ATT&CK accuracy.
  - `ollama` — local llama3.2:3b, privacy-preserving, ~6 min/alert on CPU.
- Combined confidence score: geometric mean of IF score, percentile, LLM TP
  confidence. Geometric mean ensures all three signals must agree for a high score.
- `if_llm_disagreement` flag: IF > 0.8 but LLM says FP. These cases are surfaced
  first in the Streamlit dashboard as requiring human review.

**Decision: Groq as default** — The goal is real-time analyst augmentation. A
6-minute LLM call per alert defeats the purpose. Groq is fast enough to run on
every alert as it arrives. Claude is used for weekly sweep passes where accuracy
matters more than speed.

**Decision: deterministic output (temperature=0)** — Alert enrichments written to
ES must be stable across re-runs. A different ATT&CK mapping on each run would
confuse analysts reviewing history.

---

## Phase 5 — Streamlit dashboard (first version)

**Added:** Three-tab dashboard: Alert Queue (row-selection + inline triage),
Model Metrics, Dataset Summary.

**Later eliminated:** Tabs 3 and 4 (Model Metrics, Dataset Summary) removed in
Phase 8 consolidation. They showed useful charts but were never used operationally
— MLflow provides a better audit trail for model metrics, and the dataset summary
is a one-time sanity check.

---

## Phase 6 — Scheduler and retrain loop

**Added:**
- `src/scheduler/nightly_retrain.py` — runs one job and exits (no long-running
  process inside the container).
- `data/runs/*.json` audit files — one per run, recording start/end/errors.
- `soc_cron` (ofelia) service — reads `ofelia.job-exec.*` labels from the Jupyter
  container and exec-s the scripts on cron schedule.

**Decision: ofelia over cron inside the container** — A cron daemon inside a
container either requires the container to stay root or needs a separate supervisor
process. Ofelia runs outside the containers and exec-s into them via the Docker
socket — no privileged processes inside the ML container, schedule defined in
`docker-compose.yml` labels so it's version-controlled.

**Decision: MLflow as primary audit trail** (not the `data/runs/` JSON files) —
MLflow stores params, metrics, and artifact files with a proper UI and comparison
view. The JSON files are retained only for `get_last_retrain_time()` (incremental
scoring boundary).

---

## Phase 7 — Incremental scoring + Windows portability

**Added:**
- `--score-only` flag in model_runner.py — loads saved model, fetches only events
  after the last retrain timestamp. Reduces scoring time from 3 min to <10 s on
  already-trained data.
- `--since ISO_TIMESTAMP` override.
- `.gitattributes` for LF enforcement — prevents Windows CRLF corruption of
  Dockerfiles and Python scripts.
- `Makefile` with GNU Make shortcuts and PowerShell comments.
- `WINDOWS_SETUP.md` — step-by-step Docker Desktop + WSL2 setup.

**Why incremental scoring:** The Wazuh bridge adds new events every 5 minutes.
Re-training the IF from scratch every 5 minutes would cause constant model drift
and high CPU. Score-only uses the stable trained model and only processes new data.

---

## Phase 8 — Consolidation

**Added:**
- `src/models/model_runner.py` — unified dispatcher replacing `isolation_forest.py`.
  New fields: `ml.anomaly_percentile`, `ml.top_features` (top-3 z-score contributors),
  `ml.routing_decision` (tier-1 / tier-2 / auto-close from the IF).
- Combined confidence routing in `alert_explainer.py`: `high_priority /
  analyst_review / auto-close` (separate from the IF routing — fuses IF + LLM).

**Eliminated:**
- `src/models/isolation_forest.py` — subsumed by model_runner.py. Removed to
  avoid two implementations of the same logic diverging over time.
- Dashboard Tabs 3 and 4 — removed (see Phase 5 note above).
- APScheduler import in nightly_retrain.py — scheduling moved to ofelia.

**Decision: two routing systems** — `_routing_decision` in model_runner.py routes
purely on IF score (fast, used immediately at scoring time). `compute_combined_confidence`
in alert_explainer.py routes on the fused IF+LLM signal (used only after enrichment).
Separating them means the IF routing is always available, even for unenriched alerts.

---

## Wazuh integration (between Phase 8 and CALDERA)

**Added:**
- `docker-compose.wazuh.yml` — Wazuh 4.14.5 manager + dashboard as a separate
  compose file sharing `soc_net`.
- `src/ingest/wazuh_bridge.py` — every 5 min, copies new Wazuh alerts from
  `wazuh-alerts-4.x-*` to `security-events-wazuh` in ECS format for the ML pipeline.
- Two-path LLM enrichment (Path A / Path B):
  - Path A: event has a Wazuh rule ID → ATT&CK technique pre-populated; LLM only
    asked for FP assessment + investigation steps. ~60% shorter prompt, lower cost.
  - Path B: no Wazuh backing → full ATT&CK classification from scratch.
- `ml.enrichment_path` as a keyword field — allows measuring ML novelty:
  path=B + anomalous = things the ML found that Wazuh missed.

**Decision: separate compose file for Wazuh** — Wazuh requires ~2 GB RAM and is
not needed for the core ML pipeline. Running it in a separate file lets the main
stack start on an 8 GB machine and Wazuh be added only when agent monitoring is
needed.

**Decision: ECS copy (security-events-wazuh)** rather than querying
`wazuh-alerts-4.x-*` directly — the Wazuh index template uses OpenSearch-specific
mappings that conflict with the ML pipeline's ES 8.14 expectations. The bridge
normalises fields to ECS before writing to the ML index.

---

## Shuffle SOAR integration

**Added:**
- Four Shuffle containers in the main `docker-compose.yml`: shuffle-database
  (OpenSearch, internal only), shuffle-backend (:5001), shuffle-frontend (:3001),
  shuffle-orborus (workflow executor).
- `src/response/shuffle_notifier.py` — polls `security-scores-if` for
  `routing_decision IN (high_priority, analyst_review)` with `ml.shuffle_notified != true`,
  POSTs each to the Shuffle webhook, marks `ml.shuffle_notified=true` for idempotency.
- Ofelia label on the Jupyter container to run the notifier every 5 minutes.

**Why Shuffle over PagerDuty/JIRA:** Open-source, self-hosted, no SaaS dependency.
The notifier pattern (poll → POST → mark) is intentionally simple — it makes the
forwarding idempotent and restartable without tracking external state.

**Eliminated from consideration:** A pub/sub pattern (ES watcher or Kafka) would
be faster but adds significant operational complexity for a single-analyst lab.
Polling every 5 minutes is fast enough for a home lab and survives container
restarts without reprocessing alerts.

---

## CALDERA red/blue simulation integration

**Added:**
- `docker-compose.caldera.yml` — CALDERA 5.x in Docker, port 8889 (8888 taken
  by Jupyter), attached to soc_net.
- `docker/caldera/entrypoint.sh` — generates `conf/local.yml` from environment
  variables at startup. CALDERA has no native env-var support for its config;
  this bridges the gap without requiring a hardcoded config file.
- `src/redblue/caldera_monitor.py` — polls the CALDERA API for completed technique
  links, queries ES for anomalies in a 90-second window, writes a per-technique
  detection scorecard.
- `data/runs/live_detection_YYYY-MM-DD.json` — scorecard format with
  `detection_rate`, `avg_detection_latency_seconds`, `missed_techniques`.
- Streamlit Tab 2 (Coverage Gap) — replaced the stub chart with a live view of
  the scorecard: KPI row, per-technique table with colour coding, and LLM
  one-sentence improvement suggestion for each missed technique.

**Decision: port 8889 for CALDERA** — Port 8888 is already mapped by `soc_jupyter`.
CALDERA's internal container port stays 8888 (unchanged), only the host binding
differs. Container-to-container traffic (caldera_monitor.py inside jupyter) still
uses `http://caldera:8888`.

**Decision: entrypoint.sh over mounted local.yml** — The project convention is
"credentials in .env, not in files." An entrypoint that generates `local.yml` at
runtime from env vars keeps all secrets in one place. The `--insecure` flag was
dropped because it silently forces CALDERA to use `default.yml` instead of
`local.yml`, defeating the injection.

**Decision: 90-second detection window** — Wide enough to capture Wazuh's 5-minute
bridge + scoring pipeline latency for events that were already queued, narrow enough
to avoid attributing unrelated host activity to the technique execution.

---

## Final phase — Bootstrap and operations

**Added:**
- `bootstrap.sh` / `bootstrap.ps1` — one-shot lab setup scripts covering
  prerequisites, startup sequence (main → Wazuh → model pull → ingest → train
  → enrich), and service URL printout.
- `--skip-wazuh` flag — allows starting on 8 GB machines.
- `--skip-data` flag — makes the script safe to re-run without re-ingesting.
- Makefile targets: `bootstrap`, `bootstrap-skip-data`, `wazuh-up`, `wazuh-down`,
  `caldera-up`, `caldera-down`, `caldera-demo`, `caldera-monitor`, `status`,
  `pull-model-8b`, `drift`.
- `make status` — prints `docker compose ps` output for all three stacks plus
  an Elasticsearch cluster health summary.
- CLAUDE.md: Windows migration section (GPU passthrough, 3b→8b upgrade, Wazuh
  agent re-pointing).
- `tests/test_caldera_monitor.py` — 24 unit tests for caldera_monitor.py pure
  functions; no live CALDERA or ES required.

**Bug fixed:** `test_routing_tier1_when_combined_high` in test_alert_explainer.py
asserted the stale label `"tier-1"` from model_runner.py instead of
`"high_priority"` from alert_explainer.py. The two scripts use separate routing
systems with different label names; the test was not updated when alert_explainer.py
was renamed from tier-1 to high_priority.

---

## What the lab can do now vs. the starting point

| Capability | Before | After |
|---|---|---|
| Ingest security telemetry | Manual | Automated via load_mordor.py + Wazuh bridge |
| Anomaly detection | None | Isolation Forest (200 trees, 13 features, percentile ranking) |
| Alert triage | None | LLM enrichment with ATT&CK mapping, FP assessment, investigation steps |
| Analyst prioritisation | None | Combined IF+LLM confidence score with routing tiers |
| Scheduled retraining | None | Nightly retrain + weekly enrichment sweep via ofelia |
| Drift detection | None | Evidently HTML reports, exits non-zero on significant drift |
| Incident response | None | Shuffle SOAR webhook forwarding for high-priority alerts |
| Agent telemetry | Synthetic only | Live Wazuh agents on Windows/Linux endpoints |
| Red team simulation | None | CALDERA adversary emulation with ATT&CK technique library |
| Detection measurement | None | Per-technique detection scorecard (rate, latency, missed) |
| Coverage gap analysis | None | Streamlit Tab 2 with LLM improvement suggestions |
| Setup time (fresh install) | Manual, ~2 hours | `bash bootstrap.sh`, ~15 min |
| Windows support | Partial | Full bootstrap.ps1 + GPU passthrough docs |
| Experiment tracking | None | MLflow with params, metrics, and model artifacts |

The lab now implements a closed red/blue loop: simulate with CALDERA → detect with
the Isolation Forest → measure coverage gaps → improve the model → repeat. Each
iteration produces a measurable delta in `detection_rate` that is traceable through
the scorecard files and MLflow run history.
