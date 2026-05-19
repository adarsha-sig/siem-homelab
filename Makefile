# SOC ML Lab — common task shortcuts
# Requires GNU Make (Linux/macOS) or make via WSL2 on Windows.
# Windows PowerShell equivalents are shown in each comment block.
#
# Usage:
#   make up          # start the stack
#   make train       # full retrain
#   make score-only  # incremental scoring (use saved model)
#   make test        # unit tests

JUPYTER := docker exec soc_jupyter python3 /home/jovyan/work

# ── Docker ────────────────────────────────────────────────────────────────────

.PHONY: up down restart logs ps pull-model

up:            ## Start all containers
	docker compose up -d

down:          ## Stop all containers (data volumes preserved)
	docker compose down

restart:       ## Restart a single service, e.g. make restart SVC=streamlit
	docker compose restart $(SVC)

logs:          ## Stream logs from all containers
	docker compose logs -f

ps:            ## Show container status
	docker compose ps

pull-model:    ## Pull the default LLM model into Ollama
	docker exec soc_ollama ollama pull llama3.2:3b

# Windows PowerShell equivalents (no make required):
#   docker compose up -d
#   docker compose down
#   docker compose logs -f
#   docker compose ps
#   docker exec soc_ollama ollama pull llama3.2:3b


# ── Data ingestion ────────────────────────────────────────────────────────────

.PHONY: ingest

ingest:        ## Download Mordor datasets and index to Elasticsearch
	$(JUPYTER)/src/ingest/load_mordor.py

# PowerShell: docker exec soc_jupyter python3 /home/jovyan/work/src/ingest/load_mordor.py


# ── ML pipeline ───────────────────────────────────────────────────────────────

.PHONY: train score-only enrich

train:         ## Full retrain: fit IF on all events, score, save model
	$(JUPYTER)/src/models/isolation_forest.py

score-only:    ## Incremental: load saved model, score only new events
	$(JUPYTER)/src/models/isolation_forest.py --score-only

score-since:   ## Score events after a specific timestamp: make score-since SINCE=2020-09-21T00:00:00Z
	$(JUPYTER)/src/models/isolation_forest.py --score-only --since $(SINCE)

enrich:        ## LLM enrichment sweep (top 50 unenriched anomalies)
	$(JUPYTER)/src/enrichment/alert_explainer.py --limit 50

# PowerShell:
#   docker exec soc_jupyter python3 /home/jovyan/work/src/models/isolation_forest.py
#   docker exec soc_jupyter python3 /home/jovyan/work/src/models/isolation_forest.py --score-only
#   docker exec soc_jupyter python3 /home/jovyan/work/src/enrichment/alert_explainer.py --limit 50


# ── Scheduler ─────────────────────────────────────────────────────────────────

.PHONY: retrain-now retrain-dry enrich-now

retrain-now:   ## Fire the nightly retrain job immediately (live)
	$(JUPYTER)/src/scheduler/nightly_retrain.py --run-now retrain

retrain-dry:   ## Dry-run the retrain job (no ES writes, audit JSON written)
	$(JUPYTER)/src/scheduler/nightly_retrain.py --run-now retrain --dry-run

enrich-now:    ## Fire the enrichment sweep immediately (dry-run)
	$(JUPYTER)/src/scheduler/nightly_retrain.py --run-now enrich --dry-run

# PowerShell:
#   docker exec soc_jupyter python3 /home/jovyan/work/src/scheduler/nightly_retrain.py --run-now retrain --dry-run


# ── Tests ─────────────────────────────────────────────────────────────────────

.PHONY: test test-all

test:          ## Unit tests only (no ES or Ollama required)
	python3 -m pytest tests/ -v -m "not integration"

test-all:      ## All tests including integration (requires running stack)
	python3 -m pytest tests/ -v

# PowerShell:
#   python -m pytest tests/ -v -m "not integration"
#   python -m pytest tests/ -v


# ── Cleanup ───────────────────────────────────────────────────────────────────

.PHONY: clean

clean:         ## Remove Python cache files
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete 2>/dev/null || true

# PowerShell:
#   Get-ChildItem -Recurse -Filter __pycache__ -Directory | Remove-Item -Recurse -Force
#   Get-ChildItem -Recurse -Filter *.pyc | Remove-Item -Force


# ── Help ──────────────────────────────────────────────────────────────────────

.PHONY: help
help:          ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
	  | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

.DEFAULT_GOAL := help
