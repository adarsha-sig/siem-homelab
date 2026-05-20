# bootstrap.ps1 — Windows PowerShell equivalent of bootstrap.sh
#
# Usage:
#   .\bootstrap.ps1                        # full setup
#   .\bootstrap.ps1 -SkipWazuh            # omit Wazuh stack (saves ~2 GB RAM)
#   .\bootstrap.ps1 -SkipData             # skip ingest/train/enrich
#   .\bootstrap.ps1 -SkipWazuh -SkipData
#
# Prerequisites: Docker Desktop 4.x+ with WSL2, Git, Python 3.11+ (optional)
# See WINDOWS_SETUP.md for step-by-step Docker Desktop + WSL2 setup.

param(
    [switch]$SkipWazuh,
    [switch]$SkipData,
    [switch]$Help
)

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

if ($Help) {
    Get-Content $PSCommandPath | Select-Object -First 12 | ForEach-Object { $_ -replace "^# ?","" }
    exit 0
}

# ── Colour helpers ────────────────────────────────────────────────────────────

function Ok   { param($msg) Write-Host "✓ $msg" -ForegroundColor Green }
function Warn { param($msg) Write-Host "! $msg" -ForegroundColor Yellow }
function Err  { param($msg) Write-Host "✗ $msg" -ForegroundColor Red }
function Info { param($msg) Write-Host "→ $msg" -ForegroundColor Cyan }
function Hr   { Write-Host "──────────────────────────────────────────────" -ForegroundColor Blue }

Write-Host ""
Write-Host "┌──────────────────────────────────────────────┐" -ForegroundColor Blue
Write-Host "│  SOC ML Lab — Bootstrap (Windows)            │" -ForegroundColor Blue
Write-Host "└──────────────────────────────────────────────┘" -ForegroundColor Blue
Write-Host ""

# ── Step 1: Prerequisites ─────────────────────────────────────────────────────

Hr; Info "Checking prerequisites…"; Hr
$prereqFail = $false

# Docker Desktop
try {
    $null = docker info 2>&1
    $dockerVer = (docker --version 2>&1) -replace ".*version ([0-9]+\.[0-9]+).*",'$1'
    Ok "Docker Desktop running ($dockerVer)"
} catch {
    Err "Docker Desktop is not running — start it and re-run bootstrap.ps1"
    $prereqFail = $true
}

# docker compose v2
try {
    $null = docker compose version 2>&1
    Ok "docker compose v2 available"
} catch {
    Err "docker compose v2 not found — update Docker Desktop to 4.x+"
    $prereqFail = $true
}

# Git
try {
    $gitVer = (git --version) -replace "git version ",""
    Ok "Git $gitVer"
} catch {
    Err "Git not found — install from https://git-scm.com/download/win"
    $prereqFail = $true
}

# Python 3.11+ (host-side tests)
try {
    $pyVer = python --version 2>&1
    if ($pyVer -match "3\.(\d+)") {
        $minor = [int]$Matches[1]
        if ($minor -ge 11) { Ok "Python $($pyVer -replace 'Python ','')" }
        else { Warn "Python $($pyVer -replace 'Python ','') — 3.11+ recommended for host-side tests" }
    }
} catch {
    Warn "Python not found on PATH — host-side tests must run inside the container"
}

# Node.js (optional — only for bare-metal CALDERA, not Docker install)
try {
    $nodeVer = node --version 2>&1
    Ok "Node.js $nodeVer (optional — CALDERA runs in Docker)"
} catch {
    Warn "Node.js not found — not required (CALDERA runs in Docker)"
}

# Free disk space ≥ 30 GB
try {
    $drive = Split-Path -Qualifier (Get-Location).Path
    $disk  = Get-PSDrive -Name ($drive -replace ':','')
    $freeGB = [math]::Round($disk.Free / 1GB, 1)
    if ($freeGB -ge 30) { Ok "${freeGB} GB free disk" }
    else { Warn "${freeGB} GB free disk — 30 GB recommended" }
} catch {
    Warn "Could not determine free disk space"
}

# RAM ≥ 12 GB
try {
    $ramGB = [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 1)
    if ($ramGB -ge 12)    { Ok "${ramGB} GB RAM" }
    elseif ($ramGB -ge 8) { Warn "${ramGB} GB RAM — use -SkipWazuh to reduce pressure" }
    else                  { Warn "${ramGB} GB RAM — may be insufficient; use -SkipWazuh -SkipData" }
} catch {
    Warn "Could not determine RAM"
}

if ($prereqFail) {
    Write-Host ""
    Err "Required prerequisites missing. Fix them and re-run."
    exit 1
}
Write-Host ""

# ── Step 2: .env check ────────────────────────────────────────────────────────

Info "Checking .env…"
if (-not (Test-Path ".env")) {
    Copy-Item ".env.example" ".env"
    Warn ".env not found — created from .env.example."
    Warn "Edit .env: set GROQ_API_KEY (or LLM_BACKEND=ollama), SHUFFLE_DEFAULT_PASSWORD,"
    Warn "CALDERA_API_KEY, and CALDERA_CRYPT_SALT. Then re-run bootstrap.ps1."
    exit 0
}
Ok ".env present"

# Read LLM_BACKEND from .env
$llmBackend = "groq"
Get-Content ".env" | Where-Object { $_ -match "^LLM_BACKEND=" } | ForEach-Object {
    $llmBackend = ($_ -split "=",2)[1].Trim()
}
Write-Host ""

# ── Step 3: Start main stack ──────────────────────────────────────────────────

Hr; Info "Starting main stack (docker-compose.yml)…"; Hr
docker compose up -d

Info "Waiting for Elasticsearch to be healthy (up to 120 s)…"
$maxWait = 120; $waited = 0
do {
    Start-Sleep 5; $waited += 5
    try {
        $health = Invoke-RestMethod "http://localhost:9200/_cluster/health" -ErrorAction SilentlyContinue
        if ($health.status -in @("green","yellow")) { break }
    } catch {}
    Write-Host -NoNewline "."
    if ($waited -ge $maxWait) {
        Write-Host ""
        Err "Elasticsearch did not become healthy after ${maxWait} s"
        Err "Check logs: docker compose logs elasticsearch"
        exit 1
    }
} while ($true)
Write-Host ""
Ok "Elasticsearch healthy"
Write-Host ""

# ── Step 4: Start Wazuh stack ─────────────────────────────────────────────────

if ($SkipWazuh) {
    Warn "Skipping Wazuh stack (-SkipWazuh)"
} else {
    Hr; Info "Starting Wazuh stack (docker-compose.wazuh.yml)…"; Hr
    docker compose -f docker-compose.wazuh.yml up -d
    Ok "Wazuh stack started (takes ~60 s to fully initialise)"
}
Write-Host ""

# ── Step 5: Pull LLM model if using Ollama ────────────────────────────────────

if ($llmBackend -eq "ollama") {
    Hr; Info "LLM_BACKEND=ollama — pulling llama3.2:3b (~2 GB)…"; Hr
    docker exec soc_ollama ollama pull llama3.2:3b
    Ok "Ollama model ready"
    Write-Host ""
} else {
    Ok "LLM_BACKEND=$llmBackend — no Ollama model pull required"
    Write-Host ""
}

# ── Step 6: Data setup ────────────────────────────────────────────────────────

if ($SkipData) {
    Warn "Skipping data ingest / model training / enrichment (-SkipData)"
    Write-Host ""
} else {
    Hr; Info "Ingesting Mordor datasets into Elasticsearch…"; Hr
    docker exec soc_jupyter python3 /home/jovyan/work/src/ingest/load_mordor.py
    Ok "Mordor datasets indexed"
    Write-Host ""

    Hr; Info "Training Isolation Forest model (full retrain, ~3 min)…"; Hr
    docker exec soc_jupyter python3 /home/jovyan/work/src/models/model_runner.py --model if
    Ok "Model trained and scored"
    Write-Host ""

    Hr; Info "LLM enrichment — top 20 anomalies (backend: $llmBackend)…"; Hr
    docker exec soc_jupyter python3 /home/jovyan/work/src/enrichment/alert_explainer.py --limit 20
    Ok "Enrichment complete"
    Write-Host ""
}

# ── Step 7: Service URLs ──────────────────────────────────────────────────────

Write-Host "┌──────────────────────────────────────────────────────────────┐" -ForegroundColor Green
Write-Host "│  Lab is ready!  Service URLs                                 │" -ForegroundColor Green
Write-Host "└──────────────────────────────────────────────────────────────┘" -ForegroundColor Green
Write-Host ""
Write-Host "  Always-on services:" -ForegroundColor White
Write-Host "  Streamlit dashboard    : http://localhost:8501"
Write-Host "  Jupyter Lab            : http://localhost:8888"
Write-Host "  Elasticsearch          : http://localhost:9200"
Write-Host "  Ollama                 : http://localhost:11434"
Write-Host "  MLflow                 : http://localhost:5000"
Write-Host "  Shuffle SOAR           : http://localhost:3001"

if (-not $SkipWazuh) {
    Write-Host ""
    Write-Host "  Wazuh (started):" -ForegroundColor White
    Write-Host "  Wazuh dashboard        : https://localhost  (admin / admin)"
    Write-Host "  Wazuh API              : https://localhost:55000"
}

Write-Host ""
Write-Host "  Optional stacks (start separately):" -ForegroundColor White
if ($SkipWazuh) {
    Write-Host "  Wazuh (not started)    : docker compose -f docker-compose.wazuh.yml up -d"
}
Write-Host "  CALDERA (not started)  : docker compose -f docker-compose.caldera.yml up -d"
Write-Host "                           → http://localhost:8889"
Write-Host ""
Write-Host "  Run 'make status' (or see WINDOWS_SETUP.md) to check every service." -ForegroundColor Cyan
Write-Host ""
