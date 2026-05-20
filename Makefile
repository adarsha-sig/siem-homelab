# SOC ML Lab — common task shortcuts
# Requires GNU Make (Linux/macOS) or make via WSL2 on Windows.
# PowerShell equivalents are shown in each comment block.
#
# Usage:
#   make up            # start main stack
#   make status        # health of every service
#   make train         # full model retrain
#   make test          # unit tests (no ES/Ollama required)

JUPYTER := docker exec soc_jupyter python3 /home/jovyan/work

# ── Bootstrap ─────────────────────────────────────────────────────────────────

.PHONY: bootstrap bootstrap-skip-data

bootstrap:           ## Full one-shot setup: prereqs → start → ingest → train → enrich
	bash bootstrap.sh

bootstrap-skip-data: ## Start stacks only — skip ingest/train/enrich (re-run / CI)
	bash bootstrap.sh --skip-wazuh --skip-data

# PowerShell: .\bootstrap.ps1 -SkipWazuh -SkipData


# ── Docker — main stack ───────────────────────────────────────────────────────

.PHONY: up down restart logs ps

up:              ## Start main stack (docker-compose.yml)
	docker compose up -d

down:            ## Stop main stack — data volumes are preserved
	docker compose down

restart:         ## Restart one service: make restart SVC=streamlit
	docker compose restart $(SVC)

logs:            ## Stream logs from the main stack
	docker compose logs -f

ps:              ## Show container status (main stack)
	docker compose ps

# PowerShell equivalents:
#   docker compose up -d / down / logs -f / ps


# ── Docker — Wazuh ────────────────────────────────────────────────────────────

.PHONY: wazuh-up wazuh-down wazuh-logs

wazuh-up:        ## Start Wazuh stack (docker-compose.wazuh.yml)
	docker compose -f docker-compose.wazuh.yml up -d

wazuh-down:      ## Stop Wazuh stack (data volumes preserved)
	docker compose -f docker-compose.wazuh.yml down

wazuh-logs:      ## Stream Wazuh stack logs
	docker compose -f docker-compose.wazuh.yml logs -f

# PowerShell: docker compose -f docker-compose.wazuh.yml up -d


# ── Docker — CALDERA ──────────────────────────────────────────────────────────

.PHONY: caldera-up caldera-down caldera-logs

caldera-up:      ## Start CALDERA adversary emulation platform (:8889)
	docker compose -f docker-compose.caldera.yml up -d

caldera-down:    ## Stop CALDERA (data volumes preserved)
	docker compose -f docker-compose.caldera.yml down

caldera-logs:    ## Stream CALDERA logs
	docker compose -f docker-compose.caldera.yml logs -f soc_caldera

# PowerShell: docker compose -f docker-compose.caldera.yml up -d


# ── Status ────────────────────────────────────────────────────────────────────

.PHONY: status

status:          ## Print health of every service across all stacks
	@echo ""
	@echo "  ── Main stack (docker-compose.yml) ──────────────────────────────────"
	@docker compose ps --format "table {{.Name}}\t{{.Status}}\t{{.Ports}}" \
	    2>/dev/null || echo "  (not running)"
	@echo ""
	@echo "  ── Wazuh (docker-compose.wazuh.yml) ────────────────────────────────"
	@docker compose -f docker-compose.wazuh.yml ps \
	    --format "table {{.Name}}\t{{.Status}}" 2>/dev/null || echo "  (not running)"
	@echo ""
	@echo "  ── CALDERA (docker-compose.caldera.yml) ────────────────────────────"
	@docker compose -f docker-compose.caldera.yml ps \
	    --format "table {{.Name}}\t{{.Status}}\t{{.Ports}}" 2>/dev/null || echo "  (not running)"
	@echo ""
	@echo "  ── Elasticsearch cluster ────────────────────────────────────────────"
	@curl -sf http://localhost:9200/_cluster/health \
	    | python3 -c "import json,sys; d=json.load(sys.stdin); \
	      print(f'  status={d[\"status\"]}  nodes={d[\"number_of_nodes\"]}  shards_active={d[\"active_shards\"]}')" \
	    2>/dev/null || echo "  ES unreachable — is the main stack running?"
	@echo ""

# PowerShell:
#   docker compose ps
#   docker compose -f docker-compose.wazuh.yml ps
#   docker compose -f docker-compose.caldera.yml ps
#   Invoke-RestMethod http://localhost:9200/_cluster/health


# ── Ollama ────────────────────────────────────────────────────────────────────

.PHONY: pull-model pull-model-8b

pull-model:      ## Pull default LLM model into Ollama (llama3.2:3b, ~2 GB)
	docker exec soc_ollama ollama pull llama3.2:3b

pull-model-8b:   ## Pull high-accuracy model (llama3.1:8b, ~5 GB) — use on GPU machines
	docker exec soc_ollama ollama pull llama3.1:8b

# PowerShell:
#   docker exec soc_ollama ollama pull llama3.2:3b
#   docker exec soc_ollama ollama pull llama3.1:8b


# ── Data ingestion ────────────────────────────────────────────────────────────

.PHONY: ingest

ingest:          ## Download Mordor datasets and index to Elasticsearch
	$(JUPYTER)/src/ingest/load_mordor.py

# PowerShell: docker exec soc_jupyter python3 /home/jovyan/work/src/ingest/load_mordor.py


# ── ML pipeline ───────────────────────────────────────────────────────────────

.PHONY: train score-only score-since enrich

train:           ## Full retrain: fit IF on all events, score, save model
	$(JUPYTER)/src/models/model_runner.py --model if

score-only:      ## Incremental: load saved model, score only new events
	$(JUPYTER)/src/models/model_runner.py --model if --score-only

score-since:     ## Score events after a timestamp: make score-since SINCE=2020-09-21T00:00:00Z
	$(JUPYTER)/src/models/model_runner.py --model if --score-only --since $(SINCE)

enrich:          ## LLM enrichment sweep (top 50 unenriched anomalies)
	$(JUPYTER)/src/enrichment/alert_explainer.py --limit 50

# PowerShell:
#   docker exec soc_jupyter python3 .../model_runner.py --model if
#   docker exec soc_jupyter python3 .../model_runner.py --model if --score-only
#   docker exec soc_jupyter python3 .../alert_explainer.py --limit 50


# ── Scheduler ─────────────────────────────────────────────────────────────────

.PHONY: retrain-now retrain-dry enrich-now

retrain-now:     ## Fire the nightly retrain job immediately (live ES writes)
	$(JUPYTER)/src/scheduler/nightly_retrain.py --run-now retrain

retrain-dry:     ## Dry-run the retrain job (no ES writes, audit JSON written)
	$(JUPYTER)/src/scheduler/nightly_retrain.py --run-now retrain --dry-run

enrich-now:      ## Fire the enrichment sweep immediately (dry-run)
	$(JUPYTER)/src/scheduler/nightly_retrain.py --run-now enrich --dry-run

# PowerShell:
#   docker exec soc_jupyter python3 .../nightly_retrain.py --run-now retrain --dry-run


# ── Red/Blue simulation ───────────────────────────────────────────────────────

.PHONY: caldera-demo caldera-monitor

caldera-demo:    ## Write a synthetic CALDERA scorecard (no live CALDERA needed)
	python3 src/redblue/caldera_monitor.py --demo

caldera-monitor: ## Monitor a live CALDERA operation: make caldera-monitor OP=<uuid>
	python3 src/redblue/caldera_monitor.py --operation-id $(OP)

# PowerShell:
#   python src/redblue/caldera_monitor.py --demo
#   python src/redblue/caldera_monitor.py --operation-id <uuid>


# ── Drift monitoring ──────────────────────────────────────────────────────────

.PHONY: drift

drift:           ## Run Evidently drift check (HTML report → data/runs/)
	$(JUPYTER)/src/monitoring/evidently_monitor.py

# PowerShell: docker exec soc_jupyter python3 .../evidently_monitor.py


# ── Tests ─────────────────────────────────────────────────────────────────────

.PHONY: test test-all

test:            ## Unit tests only (no ES, Ollama, or CALDERA required)
	python3 -m pytest tests/ -v -m "not integration"

test-all:        ## All tests including integration (runs inside jupyter container — correct deps)
	docker exec soc_jupyter python3 -m pytest /home/jovyan/work/tests/ -v

# Unit tests run on the host with whatever Python is available.
# Integration tests MUST run inside soc_jupyter (elasticsearch==8.14, pinned packages).
# PowerShell:
#   python -m pytest tests/ -v -m "not integration"
#   docker exec soc_jupyter python3 -m pytest /home/jovyan/work/tests/ -v


# ── Cleanup ───────────────────────────────────────────────────────────────────

.PHONY: clean

clean:           ## Remove Python cache files
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete 2>/dev/null || true

# PowerShell:
#   Get-ChildItem -Recurse -Filter __pycache__ -Directory | Remove-Item -Recurse -Force
#   Get-ChildItem -Recurse -Filter *.pyc | Remove-Item -Force


# ── Help ──────────────────────────────────────────────────────────────────────

.PHONY: help
help:            ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
	  | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}'

.DEFAULT_GOAL := help
