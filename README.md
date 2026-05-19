# SOC ML Lab

A self-contained home-lab SIEM with machine-learning anomaly detection and
local LLM-powered alert triage. Everything runs in four Docker containers —
no data leaves the machine, no cloud accounts required.

## What it does

```
OTRF Mordor datasets          Elasticsearch 8.14
(Windows attack telemetry) →  security-events-mordor  (30k events)
                           →  security-scores-if       (IF anomaly scores)
                                    ↓
                           Isolation Forest model
                           (13 features, 200 trees)
                                    ↓
                           Ollama llama3.2:3b triage
                           ml.llm_triage: ATT&CK technique,
                           FP assessment, investigation steps
                                    ↓
                           Streamlit dashboard :8501
```

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  Docker network: soc_net                                        │
│                                                                 │
│  ┌──────────────────┐  ┌──────────────────┐                    │
│  │  Elasticsearch   │  │     Ollama        │                    │
│  │  :9200           │  │  :11434           │                    │
│  │  security-events │  │  llama3.2:3b      │                    │
│  │  security-scores │  │  (local LLM)      │                    │
│  └────────┬─────────┘  └────────┬──────────┘                   │
│           │                     │                               │
│  ┌────────▼─────────────────────▼──────────┐                   │
│  │           Jupyter Lab  :8888             │                   │
│  │  src/ingest/     src/models/             │                   │
│  │  src/enrichment/ src/scheduler/          │                   │
│  └──────────────────────────────────────────┘                   │
│                                                                 │
│  ┌──────────────────────────────────────────┐                   │
│  │       Streamlit Dashboard  :8501          │                   │
│  │  Alert Queue · Model Metrics · Dataset    │                   │
│  └──────────────────────────────────────────┘                   │
└─────────────────────────────────────────────────────────────────┘
```

## Quick start (macOS / Linux)

```bash
# 1. Clone
git clone https://github.com/adarsha-sig/siem-homelab.git
cd siem-homelab

# 2. Start the stack
make up
# or: docker compose up -d

# 3. Pull the LLM model (one-time, ~2 GB)
docker exec soc_ollama ollama pull llama3.2:3b

# 4. Download Mordor datasets and index them
make ingest
# or: docker exec soc_jupyter python3 /home/jovyan/work/src/ingest/load_mordor.py

# 5. Train the Isolation Forest and score all events (~3 min)
make train
# or: docker exec soc_jupyter python3 /home/jovyan/work/src/models/model_runner.py --model if

# 6. Open the dashboard
open http://localhost:8501
```

> **Windows users** — see [WINDOWS_SETUP.md](WINDOWS_SETUP.md) for
> PowerShell equivalents and Docker Desktop configuration.

## Services

| Service | URL | Purpose |
|---------|-----|---------|
| Streamlit | http://localhost:8501 | Alert queue, LLM triage, model metrics |
| Jupyter Lab | http://localhost:8888 | Notebooks, interactive analysis |
| Elasticsearch | http://localhost:9200 | Event store + score index |
| Ollama | http://localhost:11434 | Local LLM inference |

## Pipeline scripts

All scripts run inside the `soc_jupyter` container. Each accepts `--dry-run`
and `--verbose`.

```bash
# Ingest Mordor zip archives → security-events-mordor
docker exec soc_jupyter python3 /home/jovyan/work/src/ingest/load_mordor.py

# Full retrain: fetch all events, fit IF, score, save model
docker exec soc_jupyter python3 /home/jovyan/work/src/models/model_runner.py --model if

# Incremental scoring: load saved model, score only new events
docker exec soc_jupyter python3 /home/jovyan/work/src/models/model_runner.py --model if \
  --score-only
# or with an explicit cutoff:
docker exec soc_jupyter python3 /home/jovyan/work/src/models/model_runner.py --model if \
  --score-only --since 2020-09-21T00:00:00Z

# LLM enrichment: add ATT&CK mapping + investigation steps to top anomalies
docker exec soc_jupyter python3 /home/jovyan/work/src/enrichment/alert_explainer.py \
  --limit 50

# Nightly retrain (dry-run) — also writes a JSON audit to data/runs/
docker exec soc_jupyter python3 /home/jovyan/work/src/scheduler/nightly_retrain.py \
  --run-now retrain --dry-run
```

## `make` shortcuts

```
make up           Start all containers
make down         Stop all containers
make ingest       Index Mordor datasets
make train        Full retrain + scoring
make score-only   Incremental scoring (uses saved model + audit trail)
make enrich       LLM enrichment sweep (top 50 unenriched alerts)
make retrain-now  Fire nightly retrain immediately (live)
make retrain-dry  Dry-run the retrain
make test         Unit tests (no ES / Ollama required)
make test-all     All tests including integration
```

## Elasticsearch indices

| Index | Contents |
|-------|----------|
| `security-events-mordor` | Raw ECS-aligned Mordor events (never modified) |
| `security-scores-if` | Scored events with `ml.anomaly_score`, `ml.is_anomaly`, `ml.llm_triage` |

## Models

| File | Description |
|------|-------------|
| `data/models/isolation_forest.pkl` | Fitted IF + StandardScaler bundle (written by `model_runner.py --model if`) |
| `data/runs/retrain_*.json` | JSON audit trail — one file per scheduler run |

## Anomaly features (13 total)

| Feature | Signal |
|---------|--------|
| `proc_rarity` | How rare is this process name in the corpus? |
| `parent_proc_rarity` | How rare is the parent process? |
| `parent_child_rarity` | How rare is this parent→child pair? |
| `user_rarity` | How rare is this user→event combination? |
| `host_event_rarity` | How rare is this host+category combination? |
| `event_category_rank` | Ordinal rank of event category (higher = more interesting) |
| `channel_rank` | Ordinal rank of Windows event channel |
| `event_id` | Raw Windows EventID |
| `has_cmd` | Binary: command line present? |
| `cmd_len` | Command line length (capped at 4096) |
| `cmd_has_encoding` | Base64 blob detected? (T1059.001 indicator) |
| `cmd_has_download` | Download-cradle pattern? (T1105 indicator) |
| `hour` | Hour of day (0–23) |

## LLM triage

Each enriched anomaly gets:
- `ml.llm_triage.attack_technique` — MITRE ATT&CK technique ID
- `ml.llm_triage.attack_tactic` — ATT&CK tactic name
- `ml.llm_triage.description` — plain-English summary
- `ml.llm_triage.fp_assessment` — `low` / `medium` / `high` false-positive confidence
- `ml.llm_triage.fp_reasoning` — one-sentence FP rationale
- `ml.llm_triage.investigation_steps` — list of 3 concrete next steps

Default model: `llama3.2:3b` (fast, ~2 s/alert with GPU).
Swap to `llama3.1:8b` for better ATT&CK accuracy:
```bash
docker exec soc_jupyter python3 /home/jovyan/work/src/enrichment/alert_explainer.py \
  --model llama3.1:8b --limit 50
```

## Scheduler

The nightly scheduler runs two jobs:

| Job | Schedule | What it does |
|-----|----------|-------------|
| Retrain | Daily 02:00 UTC | Full IF retrain + score all events |
| Enrichment sweep | Weekly Sun 03:00 UTC | Enrich up to 100 unenriched anomalies |

```bash
# Start the scheduler (blocking process)
docker exec soc_jupyter python3 /home/jovyan/work/src/scheduler/nightly_retrain.py
```

## Tests

```bash
make test        # 70 unit tests, no infrastructure needed
make test-all    # + integration tests (requires running stack)
```

## Incremental scoring (Phase 7)

After the first full retrain, use `--score-only` to score only newly ingested
events without retraining. The cutoff timestamp is read automatically from the
most recent non-dry-run audit file in `data/runs/`:

```bash
make score-only
# equivalent:
docker exec soc_jupyter python3 /home/jovyan/work/src/models/model_runner.py --model if \
  --score-only
```

For historical datasets like Mordor, pass `--since` explicitly:
```bash
docker exec soc_jupyter python3 /home/jovyan/work/src/models/model_runner.py --model if \
  --score-only --since 2020-09-21T00:00:00Z
```
