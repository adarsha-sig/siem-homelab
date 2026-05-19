# Windows Setup Guide

The entire lab runs inside Docker containers, so the only things you install
directly on Windows are Docker Desktop and Git. Everything else — Python, the ML
stack, Elasticsearch, Ollama — lives inside Linux containers.

## Prerequisites

| Tool | Version | Download |
|------|---------|----------|
| Windows | 10 22H2+ or 11 | — |
| Docker Desktop | 4.x+ | https://www.docker.com/products/docker-desktop/ |
| Git for Windows | any recent | https://git-scm.com/download/win |
| WSL2 | bundled with Docker Desktop | enable during Docker Desktop install |

> **Why WSL2?** Docker Desktop uses WSL2 as its Linux kernel. Without it,
> container performance is poor and bind-mounted volumes (the `./src:/app/src`
> lines in docker-compose.yml) may not reflect file changes in real time.

---

## Step 1 — Enable WSL2

Open PowerShell as Administrator and run:

```powershell
wsl --install
```

Restart when prompted. If you already have WSL2, verify with:

```powershell
wsl --status
# Should show: Default Version: 2
```

---

## Step 2 — Install Docker Desktop

1. Download and run the Docker Desktop installer.
2. During setup, choose **"Use WSL2 instead of Hyper-V"** (recommended).
3. After installation, open Docker Desktop and go to **Settings → General** and
   confirm *"Use WSL2 based engine"* is checked.
4. Verify from PowerShell:

```powershell
docker --version       # Docker version 25+
docker compose version # Docker Compose version v2+
```

---

## Step 3 — Clone the repository

In PowerShell (or Windows Terminal):

```powershell
git clone https://github.com/adarsha-sig/siem-homelab.git
cd siem-homelab
```

> The `.gitattributes` file in this repo enforces LF line endings for all text
> files. Git for Windows will check them out with LF automatically — do not
> convert them to CRLF or the Python scripts and Dockerfiles may break.

---

## Step 4 — Start the stack

```powershell
docker compose up -d
```

First run downloads ~6 GB of images (Elasticsearch, Jupyter, Ollama). Grab a
coffee. Subsequent starts take < 10 seconds.

Verify all four containers are running:

```powershell
docker compose ps
```

Expected output:

```
NAME                IMAGE                  STATUS
soc_elasticsearch   elasticsearch:8.14.0   Up (healthy)
soc_ollama          ollama/ollama           Up
soc_jupyter         homelabsiem-jupyter     Up
soc_dashboard       homelabsiem-streamlit   Up
```

---

## Step 5 — Pull the LLM model (one-time)

```powershell
docker exec soc_ollama ollama pull llama3.2:3b
```

This downloads ~2 GB. Run it once; the model is stored in a named Docker volume
and survives `docker compose down`.

---

## Step 6 — Download and ingest Mordor datasets

```powershell
# Download datasets (curl.exe is built-in on Windows 10/11)
$base = "https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows"
$raw  = ".\data\raw"

curl.exe -fsSL -o "$raw\empire_wmi_lateral.zip"        "$base/lateral_movement/host/empire_wmi_dcerpc_wmi_IWbemServices_ExecMethod.zip"
curl.exe -fsSL -o "$raw\empire_psexec_lateral.zip"     "$base/lateral_movement/host/empire_psexec_dcerpc_tcp_svcctl.zip"
curl.exe -fsSL -o "$raw\empire_psremoting_lateral.zip" "$base/lateral_movement/host/empire_psremoting_stager.zip"
curl.exe -fsSL -o "$raw\empire_mimikatz_creds.zip"     "$base/credential_access/host/empire_mimikatz_logonpasswords.zip"
curl.exe -fsSL -o "$raw\empire_dcsync_creds.zip"       "$base/credential_access/host/empire_dcsync_dcerpc_drsuapi_DsGetNCChanges.zip"
curl.exe -fsSL -o "$raw\empire_launcher_exec.zip"      "$base/execution/host/empire_launcher_vbs.zip"

# Index into Elasticsearch
docker exec soc_jupyter python3 /home/jovyan/work/src/ingest/load_mordor.py
```

Expected: `Total: 30,033 documents from 6 files`

---

## Step 7 — Train the model

```powershell
docker exec soc_jupyter python3 /home/jovyan/work/src/models/isolation_forest.py
```

Takes ~3 minutes. Writes 30,033 scored documents to `security-scores-if`.

---

## Step 8 — Open the services

| Service | URL |
|---------|-----|
| Streamlit dashboard | http://localhost:8501 |
| Jupyter Lab | http://localhost:8888 |
| Elasticsearch | http://localhost:9200 |
| Ollama API | http://localhost:11434 |

---

## Common PowerShell equivalents

Every `make` command has a direct PowerShell equivalent. Use whichever you prefer.

| Task | PowerShell |
|------|-----------|
| Start stack | `docker compose up -d` |
| Stop stack | `docker compose down` |
| View logs | `docker compose logs -f` |
| Full retrain | `docker exec soc_jupyter python3 /home/jovyan/work/src/models/isolation_forest.py` |
| Score-only (new events) | `docker exec soc_jupyter python3 /home/jovyan/work/src/models/isolation_forest.py --score-only` |
| Dry-run retrain | `docker exec soc_jupyter python3 /home/jovyan/work/src/scheduler/nightly_retrain.py --run-now retrain --dry-run` |
| LLM enrichment | `docker exec soc_jupyter python3 /home/jovyan/work/src/enrichment/alert_explainer.py --limit 50` |
| Unit tests | `python -m pytest tests/ -v -m "not integration"` |

---

## Troubleshooting

**"Docker Desktop — WSL kernel out of date"**
```powershell
wsl --update
```

**Ports 9200, 8501, 8888, 11434 already in use**

Find and stop the conflicting process, or change the host-side port in
`docker-compose.yml` (e.g. `"19200:9200"`) and update `ELASTIC_URL` in your
environment. Everything inside the containers uses the internal Docker network
port and is unaffected.

**Elasticsearch container exits immediately**
Docker Desktop's default memory limit (2 GB) is too low for Elasticsearch.
Go to **Docker Desktop → Settings → Resources → Memory** and set it to at least
**4 GB**.

**Volume mounts not reflecting file edits**
Ensure WSL2 integration is enabled for your distro: **Docker Desktop → Settings
→ Resources → WSL Integration → Enable for your distro**.

**`curl.exe` downloads fail with SSL errors**
Add `-k` to skip certificate verification (not recommended for production) or
install the latest Windows root certificates:
```powershell
certutil -generateSSTFromWU roots.sst
```

**`make` not found**
`make` is not installed by default on Windows. Either:
- Use the PowerShell equivalents shown above.
- Install make via winget: `winget install GnuWin32.Make`
- Run commands from inside WSL2 where make is available.

**Python import errors when running tests on the host**
The Jupyter container has the correct pinned packages. Run tests from the host
only for unit tests (no ES/Ollama needed):
```powershell
pip install pytest scikit-learn pyod pandas numpy ollama elasticsearch
python -m pytest tests/ -v -m "not integration"
```
For integration tests, run inside the container:
```powershell
docker exec soc_jupyter python3 -m pytest /home/jovyan/work/tests/ -v
```
