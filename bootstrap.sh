#!/usr/bin/env bash
# bootstrap.sh — One-shot SOC ML Lab setup.
#
# Checks prerequisites, starts the Docker stacks in order, pulls the LLM
# model if using Ollama, optionally ingests Mordor data and trains the model,
# then prints all service URLs.
#
# Usage:
#   ./bootstrap.sh                          # full setup
#   ./bootstrap.sh --skip-wazuh            # omit Wazuh stack (saves ~2 GB RAM)
#   ./bootstrap.sh --skip-data             # skip ingest/train/enrich (re-run safe)
#   ./bootstrap.sh --skip-wazuh --skip-data
#
# Flags:
#   --skip-wazuh   Do not start docker-compose.wazuh.yml (saves ~2 GB RAM;
#                  use on machines with < 12 GB or when Wazuh is not needed)
#   --skip-data    Skip Mordor ingest, model training, and LLM enrichment
#                  (fast re-run when data is already loaded, or for CI)

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ── Argument parsing ──────────────────────────────────────────────────────────

SKIP_WAZUH=false
SKIP_DATA=false

for arg in "$@"; do
  case "$arg" in
    --skip-wazuh)  SKIP_WAZUH=true  ;;
    --skip-data)   SKIP_DATA=true   ;;
    --help|-h)
      sed -n '2,20p' "$0"
      exit 0
      ;;
    *)
      echo "Unknown flag: $arg  (use --help)" >&2
      exit 1
      ;;
  esac
done

# ── Colour helpers ────────────────────────────────────────────────────────────

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; BOLD='\033[1m'; NC='\033[0m'
ok()   { printf "${GREEN}✓${NC} %s\n" "$*"; }
warn() { printf "${YELLOW}!${NC} %s\n" "$*"; }
err()  { printf "${RED}✗${NC} %s\n" "$*" >&2; }
info() { printf "${BLUE}→${NC} %s\n" "$*"; }
hr()   { printf "${BLUE}%s${NC}\n" "──────────────────────────────────────────────"; }

printf "\n${BOLD}${BLUE}┌──────────────────────────────────────────────┐\n"
printf "│  SOC ML Lab — Bootstrap                      │\n"
printf "└──────────────────────────────────────────────┘${NC}\n\n"

# ── Step 1: Prerequisites ─────────────────────────────────────────────────────

hr; info "Checking prerequisites…"; hr
PREREQ_FAIL=false

# Docker Desktop
if docker info &>/dev/null 2>&1; then
  DOCKER_VER=$(docker --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+' | head -1)
  ok "Docker Desktop running (${DOCKER_VER:-?})"
else
  err "Docker Desktop is not running — start it and re-run bootstrap.sh"
  PREREQ_FAIL=true
fi

# docker compose v2
if docker compose version &>/dev/null 2>&1; then
  ok "docker compose v2 available"
else
  err "docker compose v2 not found — update Docker Desktop to 4.x+"
  PREREQ_FAIL=true
fi

# Git
if git --version &>/dev/null 2>&1; then
  ok "Git $(git --version | awk '{print $3}')"
else
  err "Git not found — install from https://git-scm.com"
  PREREQ_FAIL=true
fi

# Python 3.11+ (host-side tests; not required for the Docker stack itself)
if command -v python3 &>/dev/null 2>&1; then
  PY_VER=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>/dev/null || echo "0.0")
  PY_MAJOR=$(echo "$PY_VER" | cut -d. -f1)
  PY_MINOR=$(echo "$PY_VER" | cut -d. -f2)
  if [ "${PY_MAJOR:-0}" -ge 3 ] && [ "${PY_MINOR:-0}" -ge 11 ]; then
    ok "Python ${PY_VER}"
  else
    warn "Python ${PY_VER} on host — 3.11+ recommended for host-side test runs"
  fi
else
  warn "Python 3 not on PATH — host-side tests must run inside the jupyter container"
fi

# Node.js — only needed for bare-metal CALDERA; Docker install does not require it
if command -v node &>/dev/null 2>&1; then
  ok "Node.js $(node --version) (optional — only needed for non-Docker CALDERA)"
else
  warn "Node.js not found — not required (CALDERA runs in Docker)"
fi

# Free disk space ≥ 30 GB
FREE_KB=$(df -k . 2>/dev/null | awk 'NR==2{print $4}' || echo 0)
FREE_GB=$(( ${FREE_KB:-0} / 1024 / 1024 ))
if [ "${FREE_GB}" -ge 30 ] 2>/dev/null; then
  ok "${FREE_GB} GB free disk"
else
  warn "${FREE_GB} GB free disk — 30 GB recommended (Docker images + Mordor data + models ≈ 20 GB)"
fi

# RAM ≥ 12 GB (≥ 8 GB acceptable with --skip-wazuh)
if [ "$(uname)" = "Darwin" ]; then
  RAM_BYTES=$(sysctl -n hw.memsize 2>/dev/null || echo 0)
  RAM_GB=$(( ${RAM_BYTES:-0} / 1024 / 1024 / 1024 ))
else
  RAM_GB=$(awk '/MemTotal/{printf "%d\n", $2/1024/1024}' /proc/meminfo 2>/dev/null || echo 0)
fi
if [ "${RAM_GB:-0}" -ge 12 ]; then
  ok "${RAM_GB} GB RAM"
elif [ "${RAM_GB:-0}" -ge 8 ]; then
  warn "${RAM_GB} GB RAM — 12 GB recommended; use --skip-wazuh to reduce pressure"
else
  warn "${RAM_GB} GB RAM — may be insufficient; use --skip-wazuh --skip-data"
fi

if [ "$PREREQ_FAIL" = true ]; then
  echo ""
  err "One or more required prerequisites are missing. Fix them and re-run."
  exit 1
fi
echo ""

# ── Step 2: .env check ────────────────────────────────────────────────────────

info "Checking .env…"
if [ ! -f .env ]; then
  cp .env.example .env
  warn ".env not found — created from .env.example."
  warn "Edit .env: set GROQ_API_KEY (or LLM_BACKEND=ollama), SHUFFLE_DEFAULT_PASSWORD,"
  warn "CALDERA_API_KEY, and CALDERA_CRYPT_SALT. Then re-run bootstrap.sh."
  exit 0
fi
ok ".env present"

# Source .env variables for use in this script
set +u
# shellcheck disable=SC1091
source .env 2>/dev/null || true
set -u
LLM_BACKEND="${LLM_BACKEND:-groq}"
echo ""

# ── Step 3: Start main stack ──────────────────────────────────────────────────

hr; info "Starting main stack (docker-compose.yml)…"; hr
docker compose up -d

info "Waiting for Elasticsearch to be healthy (up to 120 s)…"
MAX_WAIT=120; WAITED=0
until curl -sf http://localhost:9200/_cluster/health 2>/dev/null \
    | grep -qE '"status":"(green|yellow)"'; do
  if [ "$WAITED" -ge "$MAX_WAIT" ]; then
    err "Elasticsearch did not become healthy after ${MAX_WAIT} s"
    err "Check logs: docker compose logs elasticsearch"
    exit 1
  fi
  printf "."; sleep 5; WAITED=$((WAITED + 5))
done
echo ""
ok "Elasticsearch healthy"
echo ""

# ── Step 4: Start Wazuh stack ─────────────────────────────────────────────────

if [ "$SKIP_WAZUH" = true ]; then
  warn "Skipping Wazuh stack (--skip-wazuh)"
else
  hr; info "Starting Wazuh stack (docker-compose.wazuh.yml)…"; hr
  docker compose -f docker-compose.wazuh.yml up -d
  ok "Wazuh stack started (takes ~60 s to fully initialise)"
fi
echo ""

# ── Step 5: Pull LLM model if using Ollama ────────────────────────────────────

if [ "$LLM_BACKEND" = "ollama" ]; then
  hr; info "LLM_BACKEND=ollama — pulling llama3.2:3b (~2 GB)…"; hr
  docker exec soc_ollama ollama pull llama3.2:3b
  ok "Ollama model ready"
  echo ""
else
  ok "LLM_BACKEND=${LLM_BACKEND} — no Ollama model pull required"
  echo ""
fi

# ── Step 6: Data setup ────────────────────────────────────────────────────────

if [ "$SKIP_DATA" = true ]; then
  warn "Skipping data ingest / model training / enrichment (--skip-data)"
  echo ""
else
  hr; info "Ingesting Mordor datasets into Elasticsearch…"; hr
  docker exec soc_jupyter \
    python3 /home/jovyan/work/src/ingest/load_mordor.py
  ok "Mordor datasets indexed"
  echo ""

  hr; info "Training Isolation Forest model (full retrain, ~3 min)…"; hr
  docker exec soc_jupyter \
    python3 /home/jovyan/work/src/models/model_runner.py --model if
  ok "Model trained and scored"
  echo ""

  hr; info "LLM enrichment — top 20 anomalies (backend: ${LLM_BACKEND})…"; hr
  docker exec soc_jupyter \
    python3 /home/jovyan/work/src/enrichment/alert_explainer.py --limit 20
  ok "Enrichment complete"
  echo ""
fi

# ── Step 7: Service URLs ──────────────────────────────────────────────────────

printf "${GREEN}${BOLD}┌──────────────────────────────────────────────────────────────┐\n"
printf "│  Lab is ready!  Service URLs                                 │\n"
printf "└──────────────────────────────────────────────────────────────┘${NC}\n"
printf "\n  ${BOLD}Always-on services:${NC}\n"
printf "  %-30s %s\n" "Streamlit dashboard:"   "http://localhost:8501"
printf "  %-30s %s\n" "Jupyter Lab:"           "http://localhost:8888"
printf "  %-30s %s\n" "Elasticsearch:"         "http://localhost:9200"
printf "  %-30s %s\n" "Ollama:"                "http://localhost:11434"
printf "  %-30s %s\n" "MLflow:"                "http://localhost:5000"
printf "  %-30s %s\n" "Shuffle SOAR:"          "http://localhost:3001"

if [ "$SKIP_WAZUH" = false ]; then
  printf "\n  ${BOLD}Wazuh (started):${NC}\n"
  printf "  %-30s %s\n" "Wazuh dashboard:"    "https://localhost  (admin / admin)"
  printf "  %-30s %s\n" "Wazuh API:"          "https://localhost:55000"
fi

printf "\n  ${BOLD}Optional stacks (start separately):${NC}\n"
if [ "$SKIP_WAZUH" = true ]; then
  printf "  %-30s %s\n" "Wazuh (not started):" \
    "docker compose -f docker-compose.wazuh.yml up -d"
fi
printf "  %-30s %s\n" "CALDERA (not started):" \
  "docker compose -f docker-compose.caldera.yml up -d  → http://localhost:8889"
printf "\n  Run ${BOLD}make status${NC} to check every service at any time.\n\n"
