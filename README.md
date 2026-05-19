# Security ML Lab

A self-contained home-lab SIEM with machine-learning anomaly detection and local LLM triage. Everything runs in Docker; no data leaves the machine.

## Architecture

```
┌────────────────────────────────────────────────────────────────┐
│  Docker network: siem_net                                      │
│                                                                │
│  ┌─────────────┐    ┌──────────────┐    ┌──────────────────┐  │
│  │ Log files   │───▶│   Ingest     │───▶│  Elasticsearch   │  │
│  │  data/*.log │    │ src/ingest/  │    │  :9200           │  │
│  └─────────────┘    └──────────────┘    └──────┬───────────┘  │
│                                                │               │
│  ┌─────────────┐    ┌──────────────┐           │               │
│  │  Scheduler  │───▶│   Models     │◀──────────┘               │
│  │ src/scheduler│   │ src/models/  │                           │
│  └─────────────┘    └──────┬───────┘                           │
│                            │                                   │
│                    ┌───────▼──────┐    ┌──────────────────┐   │
│                    │    Ollama    │    │    Streamlit     │   │
│                    │  :11434      │    │  src/dashboard/  │   │
│                    │  (local LLM) │    │  :8501           │   │
│                    └──────────────┘    └──────────────────┘   │
│                                                                │
│  Jupyter :8888  (notebooks/ + src/ + data/ mounted)           │
└────────────────────────────────────────────────────────────────┘
```

## Components

| Layer | Path | Purpose |
|-------|------|---------|
| **Ingest** | `src/ingest/ingest.py` | Parse raw logs → Elasticsearch |
| **Models** | `src/models/anomaly.py` | IsolationForest / LOF anomaly scoring |
| **LLM Analyst** | `src/models/llm_analyst.py` | Local Mistral triage via Ollama |
| **Dashboard** | `src/dashboard/app.py` | Streamlit live anomaly view |
| **Scheduler** | `src/scheduler/scheduler.py` | APScheduler: ingest every 5 min, score every 15 min |
| **Notebooks** | `notebooks/` | Interactive EDA and model experiments |
| **Data** | `data/` | Drop `.log` files here for ingest |

## Quick Start

```bash
# 1. Start the stack
docker compose up -d

# 2. Pull a local LLM model (one-time)
docker exec siem_ollama ollama pull mistral

# 3. Drop log files into data/ and trigger ingest
python src/ingest/ingest.py data/your_logs.log

# 4. Run anomaly scoring
python src/models/anomaly.py isolation_forest

# 5. Open the dashboard
open http://localhost:8501

# 6. Open Jupyter Lab
open http://localhost:8888
```

## Running the Scheduler

The scheduler handles ingest and scoring automatically:

```bash
python src/scheduler/scheduler.py
```

Or add it as an extra service in `docker-compose.yml`.

## Anomaly Methods

- **Isolation Forest** (default) — fast, tree-based, handles high-dimensional log features well
- **LOF** (Local Outlier Factor) — density-based; better for clustered normal traffic patterns

Switch method in `scheduler.py` or call `python src/models/anomaly.py lof`.

## LLM Triage

Click **Run LLM Triage** in the dashboard sidebar. The top anomalous events (score ≥ 0.75) are sent to the local Ollama model, which returns a SOC-analyst-style assessment — threat category, plain-English description, and recommended action.

All inference is local. Change the model in `src/models/llm_analyst.py` (`OLLAMA_MODEL`).

## Ports

| Service | Port |
|---------|------|
| Elasticsearch | 9200 |
| Ollama | 11434 |
| Jupyter Lab | 8888 |
| Streamlit | 8501 |
