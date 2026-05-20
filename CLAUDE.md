# SOC ML Lab — Claude Code operating instructions

## What this project is
A lean security ML research lab for detecting threats using machine learning
and LLM-based analyst augmentation. Running on Docker Compose:
Elasticsearch (data), Jupyter (ML), Ollama (LLM), Streamlit (UI),
MLflow (experiment tracking), and ofelia (cron scheduler).

## Stack and versions
- Python 3.11
- Elasticsearch 8.14 (no auth, local only)
- Docker Compose v2
- LLM enrichment: three backends selected via LLM_BACKEND env var (default: groq)
  # groq   — Groq cloud API, model llama-3.1-8b-instant; requires GROQ_API_KEY.
  #          Fast (~0.5 s/alert), no local GPU required. Best default for real-time triage.
  # claude — Anthropic API, model claude-haiku-4-5-20251001; requires ANTHROPIC_API_KEY.
  #          Highest ATT&CK mapping accuracy; use for weekly enrichment sweep.
  # ollama — Local inference (no API key), model llama3.2:3b (default) or llama3.1:8b.
  #          Privacy-preserving; ~6 min/alert on CPU, ~10 s with GPU.
- Ollama with llama3.2:3b (local fallback when LLM_BACKEND=ollama)
- MLflow :5000 — experiment tracking, param/metric/artifact store (primary audit tool)
- Evidently — data drift + quality reports; HTML saved to data/runs/drift_YYYY-MM-DD.html
- Key Python libs: elasticsearch==8.14, scikit-learn, pyod, torch, streamlit, mlflow, evidently

## Coding conventions
- All scripts use argparse with --dry-run and --verbose flags
- All ES connections use ELASTIC_URL env var (default: http://localhost:9200)
- All Ollama calls use OLLAMA_URL env var (default: http://localhost:11434)
- MLFLOW_TRACKING_URI env var (default: http://localhost:5000) — set in Jupyter container
- LLM_BACKEND env var: groq (default) | claude | ollama
- GROQ_API_KEY: required when LLM_BACKEND=groq
- ANTHROPIC_API_KEY: required when LLM_BACKEND=claude
- SHUFFLE_WEBHOOK_URL: required for shuffle_notifier.py; set to
  http://shuffle-backend:5001/api/v1/hooks/<hook-id> (container hostname, not localhost,
  because the notifier runs inside the jupyter container on soc_net).
  Create the hook in the Shuffle UI: Triggers → Webhook → copy the URL.
- Log with Python logging module, not print (except CLI output)
- Every script must be runnable standalone AND importable as a module
- Write a brief docstring on every function explaining the security intuition,
  not just what the code does

## How to explain your work
After building any component, explain:
1. The security intuition — why this technique catches this type of threat
2. The design choices — why you structured the code this way
3. What to watch for — what the output tells me and how to interpret it
4. What to try next — natural extension or experiment to run

## Wazuh integration
- Stack file: docker-compose.wazuh.yml (separate compose file, shares homelabsiem_soc_net)
- Start: docker compose -f docker-compose.wazuh.yml up -d
- Dashboard: https://localhost (port 443) — admin/admin
- Wazuh API: https://localhost:55000
- Alert index in our ES: wazuh-alerts-4.x-* (written by Wazuh manager filebeat)
- ECS copy for ML pipeline: security-events-wazuh (written by wazuh_bridge.py every 5 min)
- Bridge cursor: data/runs/wazuh_bridge_cursor.json (last-seen timestamp)

## Shuffle SOAR integration
- Services: shuffle-database (OpenSearch, internal only), shuffle-backend (:5001),
  shuffle-frontend (:3001 HTTP / :3443 HTTPS), shuffle-orborus (workflow executor)
- UI: http://localhost:3001 — first login creates the admin account
- Backend API: http://localhost:5001 (host) / http://shuffle-backend:5001 (container-to-container)
- Notifier script: src/response/shuffle_notifier.py — runs every 5 min via ofelia
  Polls security-scores-if for routing_decision IN (high_priority, analyst_review)
  that have ml.shuffle_notified != true, POSTs each to SHUFFLE_WEBHOOK_URL, then
  marks ml.shuffle_notified=true for idempotency.
- To wire up: create a Webhook trigger in the Shuffle UI, copy the URL, set
  SHUFFLE_WEBHOOK_URL=http://shuffle-backend:5001/api/v1/hooks/<hook-id> in .env
- Credentials and SHUFFLE_WEBHOOK_URL must come from .env (see .env.example) —
  never hardcode them in docker-compose.yml

## Two-path LLM enrichment (alert_explainer.py)
- Path A — Wazuh-backed: alert has wazuh.rule.id → ATT&CK technique pre-populated
  from Wazuh rule, LLM asked ONLY for fp_assessment + investigation_steps.
  ~60% shorter prompt, lower LLM cost. ml.enrichment_path = "A".
- Path B — Full prompt: no Wazuh rule → LLM classifies ATT&CK technique from scratch.
  ml.enrichment_path = "B".
- ml.enrichment_path is indexed as keyword; use it to measure ML novelty:
  alerts with path="B" that are anomalous = things ML found that Wazuh missed.

## Observability
- **Primary audit tool**: MLflow at http://localhost:5000
  View retrain runs, compare contamination values, inspect feature importance plots.
  Each run logs: params (model_type, contamination, n_estimators, feature_names),
  metrics (anomaly_count, anomaly_rate, top_score, score_p95), and artifacts
  (isolation_forest.pkl, feature_importance.png).
- **Drift monitoring**: Evidently — run src/monitoring/evidently_monitor.py
  HTML report: data/runs/drift_YYYY-MM-DD.html
  Exits 1 if >3 features drift or current event volume drops >30% vs training set.
- The data/runs/*.json files remain as implementation detail for get_last_retrain_time()
  (incremental scoring boundary) but are NOT the audit trail — use MLflow for that.

## Testing
Run `pytest tests/ -v` after any change to a src/ file.
ES must be running for integration tests. Use --dry-run for unit tests.

## CALDERA red/blue simulation integration

- Stack file: docker-compose.caldera.yml (separate compose file, shares homelabsiem_soc_net)
- Start: docker compose -f docker-compose.caldera.yml up -d
- UI: http://localhost:8888 — red/redpassword or blue/bluepassword
- REST API: http://localhost:8888 (KEY: <CALDERA_API_KEY> header)
- Entrypoint script: docker/caldera/entrypoint.sh — generates conf/local.yml from env vars
  at container startup so credentials never live in the image or a mounted config file.
- Setup doc: docs/caldera_setup.md — Windows Sandcat agent deploy, operation creation guide
- Monitor script: src/redblue/caldera_monitor.py
  Polls GET /api/v2/operations/{id}/links every 30 s
  For each completed link: records technique_id and timestamp, then queries
  security-scores-if for anomalies on that host within 90 s of execution.
  Writes scorecard to data/runs/live_detection_YYYY-MM-DD.json
- Scorecard schema: {operation, operation_name, techniques_executed, detected, missed,
  detection_rate, avg_detection_latency_seconds, technique_results[], missed_techniques[]}
- Environment variables (all in .env):
  CALDERA_API_KEY — injected into local.yml and used by caldera_monitor.py
  CALDERA_URL=http://localhost:8888 (host) or http://caldera:8888 (inside jupyter container)
  CALDERA_RED_PASSWORD / CALDERA_BLUE_PASSWORD — optional UI login overrides
- Demo mode (no live CALDERA): python src/redblue/caldera_monitor.py --demo
  Writes a synthetic 3-technique scorecard so the dashboard can be tested offline.
- Detection threshold: ml.anomaly_score ≥ 0.5 within 90 s counts as "detected".
  Override with --detection-threshold and --detect-window flags.

## Red/Blue simulation loop

The full adversary emulation → ML detection → coverage gap → improve cycle:

```
1. SIMULATE   — Run a CALDERA operation (choose an adversary profile, target the
                Windows victim VM, click Start in the CALDERA UI)

2. DETECT     — The Isolation Forest scores events in security-scores-if every
                5 min (ofelia cron). Wazuh bridge copies Wazuh alerts to ES.

3. SCORE      — caldera_monitor.py correlates each technique execution with ES
                anomaly events, records detected/missed per technique.
                Output: data/runs/live_detection_YYYY-MM-DD.json

4. COVERAGE   — Streamlit Tab 2 (Coverage Gap) reads the scorecard and shows:
                · Detection rate + avg latency KPIs
                · Per-technique table (green = detected, red = missed)
                · LLM one-sentence suggestion for each missed technique

5. IMPROVE    — For each missed technique:
                a. Follow the LLM suggestion (add Wazuh rule, add feature to
                   feature_engineering.py, adjust contamination param).
                b. Re-run src/models/model_runner.py --retrain to update the model.
                c. MLflow at http://localhost:5000 tracks the retrain run.

6. REPEAT     — Run another CALDERA operation (same adversary or a harder one)
                and watch the detection rate climb.
```

Measuring progress: compare detection_rate across scorecard files in data/runs/.
A technique that was "missed" and becomes "detected" after a model update is a
confirmed detection engineering improvement. Logged in MLflow as a metric.

## Project layout (updated)
soc-ml-lab/
├── CLAUDE.md              ← you are here
├── SPEC.md                ← full feature spec, read before building anything
├── BUILD_PLAN.md          ← phased milestones, check current phase before starting
├── docker-compose.yml
├── docker/
│   ├── jupyter/Dockerfile
│   └── streamlit/Dockerfile
├── src/
│   ├── ingest/            ← data loading and ES indexing scripts
│   ├── models/            ← ML model training and scoring scripts
│   ├── enrichment/        ← LLM-based alert enrichment
│   ├── dashboard/         ← Streamlit app
│   ├── redblue/           ← CALDERA red/blue simulation scripts
│   │   └── caldera_monitor.py
│   ├── response/          ← Shuffle SOAR notifier
│   ├── monitoring/        ← Evidently drift monitor
│   └── scheduler/         ← cron jobs
├── docs/
│   ├── caldera_setup.md   ← CALDERA install + agent deploy guide
│   └── shuffle_workflow_setup.md
├── notebooks/             ← Jupyter exploration notebooks
├── data/
│   ├── raw/               ← downloaded datasets, never modified
│   ├── processed/         ← feature-engineered outputs
│   ├── models/            ← saved .pkl model files
│   └── runs/              ← scorecard + cursor JSON files (NOT the audit trail)
└── tests/                 ← pytest tests for each module

## Never do
- Never hardcode credentials or IP addresses (use env vars)
- Never delete data in /data/raw/
- Never modify an existing index schema without asking first
- Never run model training without first confirming the source index exists