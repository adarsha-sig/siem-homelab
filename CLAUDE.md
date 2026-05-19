# SOC ML Lab — Claude Code operating instructions

## What this project is
A lean security ML research lab for detecting threats using machine learning
and LLM-based analyst augmentation. Single Ubuntu VM running four Docker
containers: Elasticsearch (data), Jupyter (ML), Ollama (LLM), Streamlit (UI).

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
- Key Python libs: elasticsearch==8.14, scikit-learn, pyod, torch, streamlit

## Project layout
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
│   └── scheduler/         ← cron jobs
├── notebooks/             ← Jupyter exploration notebooks
├── data/
│   ├── raw/               ← downloaded datasets, never modified
│   ├── processed/         ← feature-engineered outputs
│   └── models/            ← saved .pkl model files
└── tests/                 ← pytest tests for each module

## Coding conventions
- All scripts use argparse with --dry-run and --verbose flags
- All ES connections use ELASTIC_URL env var (default: http://localhost:9200)
- All Ollama calls use OLLAMA_URL env var (default: http://localhost:11434)
- LLM_BACKEND env var: groq (default) | claude | ollama
- GROQ_API_KEY: required when LLM_BACKEND=groq
- ANTHROPIC_API_KEY: required when LLM_BACKEND=claude
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

## Testing
Run `pytest tests/ -v` after any change to a src/ file.
ES must be running for integration tests. Use --dry-run for unit tests.

## Never do
- Never hardcode credentials or IP addresses (use env vars)
- Never delete data in /data/raw/
- Never modify an existing index schema without asking first
- Never run model training without first confirming the source index exists