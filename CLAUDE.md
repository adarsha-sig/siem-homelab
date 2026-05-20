# SOC ML Lab — Claude Code operating instructions

This file is the single source of truth for this project. A new Claude Code session
must be able to pick up exactly where the last one left off using only this document.

---

## 1. WHAT THIS PROJECT IS

A home-lab security ML research environment that layers a custom Isolation Forest
anomaly detector and LLM-based semantic triage on top of a conventional SIEM and
SOAR stack. Its distinguishing capability is the IF→LLM handoff: the model scores
every event against the environment's own baseline, then the LLM translates the
statistical rarity into analyst-readable ATT&CK context, a false-positive assessment
calibrated to that specific host/user/process combination, and three concrete
investigation steps — producing triage that is both environment-specific (the IF
baseline) and semantically meaningful (the LLM explanation). The lab is emphatically
not a platform replacement exercise: Wazuh does agent telemetry and rule-based
detection, Elasticsearch stores and queries data, Shuffle automates incident response
workflows, and CALDERA runs adversary emulation. The custom Python code does only
what those platforms cannot: unsupervised anomaly scoring across the full event
stream and LLM-mediated contextualisation of the resulting scores.

---

## 2. ARCHITECTURE DECISION LOG

| Decision | Chosen | Alternative | Reason |
|---|---|---|---|
| Anomaly model | Isolation Forest (unsupervised) | Supervised classifier | No labeled data available; IF trains on normal behaviour and finds structural rarity without needing attack labels |
| LLM backend default | Groq (cloud, llama-3.1-8b-instant) | Ollama (local) | ~0.5 s/alert vs ~6 min on CPU; real-time triage requires sub-second responses; Ollama kept as privacy-preserving fallback |
| LLM_BACKEND env var | Three-way switch (groq/claude/ollama) | Hardcoded backend | Portability: cloud Groq for daily ops, Claude for weekly high-accuracy sweep, Ollama for air-gapped or GPU-enabled installs |
| Evidently for drift | Custom Evidently reports | Wazuh built-in statistics | Evidently gives per-feature distribution shift with HTML artifact; Wazuh has no Python-accessible drift API |
| Shuffle SOAR | Shuffle (self-hosted) | PagerDuty / Jira webhook | Open-source, no SaaS dependency, workflow logic visible in the UI; `shuffle_notifier.py` is ~90 lines vs a full playbook engine |
| APScheduler → ofelia | ofelia (container-level cron) | APScheduler inside Python | No long-running process inside the container; schedule is version-controlled as docker-compose labels; `restart: unless-stopped` gives free retry semantics |
| Dashboard tabs | 2 tabs (Alert Queue + Coverage Gap) | 4 tabs (original) | Model Metrics and Dataset Summary removed — MLflow provides better experiment tracking; the two remaining tabs are the analyst workflow, not debug dashboards |
| feature_engineering.py | Custom (13 features) | Platform feature extraction | Rarity scoring (proc_rarity, parent_child_rarity) requires a training-set frequency table that no platform computes; this is our core IP |
| alert_explainer.py | Custom IF→LLM handoff | Platform LLM integration | The handoff requires injecting IF score, percentile rank, and top z-score contributors into the prompt — no platform can produce this context |
| load_mordor.py | Kept as evaluation baseline | Remove after training | Mordor provides labeled ATT&CK scenarios to verify the IF flags known-bad events; removing it destroys the evaluation ground truth |
| CALDERA deployment | Docker (docker-compose.caldera.yml) | Native Python install | Docker guarantees identical behaviour across Mac/Windows/Linux; entrypoint.sh injects credentials from .env at startup so no config file needs editing |
| Two-path enrichment | Path A (Wazuh ATT&CK label) + Path B (full LLM) | Single prompt always | Wazuh rules encode ATT&CK technique mappings written by a threat research team; asking the LLM to reclassify wastes tokens and introduces noise; Path A prompt is ~60% shorter |
| ml.if_llm_disagreement | Explicit boolean field | No disagreement tracking | IF↔LLM disagreement is the most research-valuable output: cases where the model found structural rarity but the LLM assessed low threat probability expose either spurious model patterns or LLM blind spots |
| LF line endings | Enforced via .gitattributes | Platform default | Dockerfiles and Python scripts break silently on Windows CRLF; .gitattributes prevents checkout corruption regardless of Git client settings |
| Painless script write-back | Painless partial update | Doc-level update | Doc-level update replaces the entire `_source`; a Painless script patches only named fields, preserving `ml.anomaly_score` and `ml.is_anomaly` set by model_runner.py |

---

## 3. WHAT TO KEEP CUSTOM — DO NOT REPLACE WITH PLATFORMS

### 3a. `src/models/feature_engineering.py`

**What it does:** Converts raw Windows security event dicts into a 13-column numeric
DataFrame. The core insight is *rarity scoring*: for each event it computes how often
that specific process, parent→child process pair, and user appear in the training set.
Rare combinations score higher. Other features encode command-line threat indicators
(base64 encoding, download cradles), event category, Windows channel, EventID, and hour.

**Why no platform replicates it:** Rarity scoring requires a frequency table built
from the specific environment's training set. A frequency table computed on one
environment means nothing on another. No SIEM computes per-process rarity against a
continuously-updated baseline and exposes it as a numeric feature for a downstream ML
model. This table is the core IP of the detection layer.

**What would be lost:** Without `feature_engineering.py`, the IF has no meaningful
signal — raw event fields are categorical strings that the model cannot compare. The
rarity features are what make the IF environment-calibrated rather than generic.

### 3b. `src/enrichment/alert_explainer.py`

**What it does:** For each flagged anomaly it constructs a prompt that includes the
IF anomaly score, the event's percentile rank within the scored batch, the top-3
z-score feature contributors, and the raw event fields. It calls the configured LLM
backend, parses the structured JSON response (ATT&CK technique, tactic, FP assessment,
reasoning, investigation steps), computes a geometric-mean combined confidence score,
and writes everything back to `security-scores-if` via a Painless partial update.

**Why no platform replicates it:** No platform takes an IF score + percentile rank
as LLM prompt context. The enrichment is specifically designed to give the LLM the
statistical context it needs to distinguish a 0.92 score at the 99th percentile (very
rare in this environment) from a 0.92 score at the 70th percentile (moderately unusual).
Without this context, LLM assessments are generic threat intel, not environment-specific
triage.

**What would be lost:** The combined_confidence score, the if_llm_disagreement flag,
and the routing_decision (which drives Shuffle forwarding) would all disappear. Analysts
would have raw IF scores with no semantic context and no prioritisation signal.

### 3c. `src/redblue/caldera_monitor.py`

**What it does:** Polls the CALDERA REST API for completed technique execution links,
opens a 90-second detection window per technique on the target host in `security-scores-if`,
and records whether the IF flagged an anomaly in that window. Writes a per-technique
detection scorecard (`data/runs/live_detection_YYYY-MM-DD.json`) with detection rate,
average latency, and the list of missed ATT&CK techniques.

**Why no platform replicates it:** CALDERA and the Isolation Forest have no native
integration. The correlation — "technique T was executed at time T₀ on host H; did
the ML model flag anything on H in the 90 seconds after T₀?" — requires querying both
the CALDERA API and Elasticsearch with a coordinated time window. This is the entire
point of the red/blue loop: a measurable, technique-level detection coverage score.

**What would be lost:** Without `caldera_monitor.py` there is no way to answer
"which ATT&CK techniques does our Isolation Forest actually detect?" The Coverage Gap
tab in the Streamlit dashboard would show only the placeholder stub chart.

---

## 4. PLATFORMS — DO NOT REWRITE IN PYTHON

| Platform | Role | URL | Replaces | Do NOT |
|---|---|---|---|---|
| **Elasticsearch 8.14** | Event storage, ML score store, query engine | http://localhost:9200 | Any custom database or log store | Write a Python storage layer or time-series store |
| **Wazuh 4.14.5** | Agent telemetry, rule-based alerting, ATT&CK tagging | https://localhost (dashboard) | UEBA scripting, rule engine, log collection | Write a Python UEBA module or custom rule engine — Wazuh handles these |
| **Shuffle SOAR** | Incident response workflow automation | http://localhost:3001 | A Python playbook engine or notification dispatcher | Write a Python playbook engine; write email/Slack integrations |
| **MLflow** | Experiment tracking, model artifact store | http://localhost:5000 | Any custom metrics database or model registry | Write Python metric logging that bypasses MLflow |
| **Evidently** | Data drift and quality reports | HTML in data/runs/ | A custom drift detector | Write a Python drift detector; Evidently already does this |
| **CALDERA** | Adversary emulation, ATT&CK ability library | http://localhost:8889 | Red-team scripting | Write custom adversary simulation scripts — use CALDERA's ability library |
| **Ollama** | Local LLM inference (privacy-preserving fallback) | http://localhost:11434 | Any custom model server | Write a custom inference server or call the model weights directly |

---

## 5. FULL STACK AND PORTS

All services share the Docker network `${COMPOSE_PROJECT_NAME:-homelabsiem}_soc_net`.

### Main stack — `docker compose up -d`

| Container | Image | Host port | Role |
|---|---|---|---|
| `soc_elasticsearch` | elasticsearch:8.14.0 | 9200 | Event store + ML score store |
| `soc_jupyter` | custom (docker/jupyter/) | 8888 | ML pipeline, notebooks |
| `soc_dashboard` | custom (docker/streamlit/) | 8501 | Streamlit analyst UI |
| `soc_ollama` | ollama/ollama:latest | 11434 | Local LLM inference |
| `soc_mlflow` | ghcr.io/mlflow/mlflow:latest | 5000 | Experiment tracking |
| `soc_cron` | mcuadros/ofelia:latest | — | Cron scheduler (reads Docker labels) |
| `shuffle_database` | opensearch:2.14.0 | internal only | Shuffle's private OpenSearch |
| `shuffle_backend` | shuffle-backend:latest | 5001 | Shuffle API + webhook receiver |
| `shuffle_frontend` | shuffle-frontend:latest | 3001 (HTTP), 3443 (HTTPS) | Shuffle web UI |
| `shuffle_orborus` | shuffle-orborus:latest | — | Shuffle workflow executor |

### Wazuh stack — `docker compose -f docker-compose.wazuh.yml up -d`

| Container | Image | Host port | Role |
|---|---|---|---|
| `wazuh_manager` | wazuh/wazuh-manager:4.14.5 | 1514/udp (events), 1515 (registration), 514/udp (syslog), 55000 (API) | Manager + filebeat → ES |
| `wazuh_dashboard` | wazuh/wazuh-dashboard:4.14.5 | 443 | Dashboard (OpenSearch Dashboards + Wazuh plugin) |

### CALDERA stack — `docker compose -f docker-compose.caldera.yml up -d`

| Container | Image | Host port | Role |
|---|---|---|---|
| `soc_caldera` | mitre/caldera:latest | **8889** → 8888 internal | Adversary emulation server (8888 taken by Jupyter) |

Note: `caldera_monitor.py` running on the host uses `http://localhost:8889`; running
inside `soc_jupyter` uses `http://caldera:8888` (container hostname on soc_net).

---

## 6. ENVIRONMENT VARIABLES

All variables live in `.env` (never committed). Copy from `.env.example`.

| Variable | Default | What it controls | Where to get |
|---|---|---|---|
| `LLM_BACKEND` | `groq` | Selects enrichment provider: `groq` / `claude` / `ollama` | Set directly |
| `GROQ_API_KEY` | *(required if groq)* | Groq cloud auth | console.groq.com → API Keys (free tier, no credit card) |
| `ANTHROPIC_API_KEY` | *(required if claude)* | Anthropic auth | console.anthropic.com → API Keys |
| `ELASTIC_URL` | `http://localhost:9200` | ES connection for host-side scripts | Set directly |
| `OLLAMA_URL` | `http://localhost:11434` | Ollama connection for host-side scripts | Set directly |
| `MLFLOW_TRACKING_URI` | `http://localhost:5000` | MLflow server for host-side scripts | Set directly |
| `SHUFFLE_DEFAULT_USERNAME` | `admin` | Shuffle first-run admin account | Set directly (change via UI after) |
| `SHUFFLE_DEFAULT_PASSWORD` | *(required)* | Shuffle first-run password | Set a strong password; used only once |
| `SHUFFLE_ENCRYPTION_MODIFIER` | *(required)* | Encrypts credentials stored in Shuffle | `python3 -c "import secrets; print(secrets.token_hex(32))"` — set once, never change |
| `SHUFFLE_WEBHOOK_URL` | *(required for notifier)* | Webhook URL for ML alert forwarding | Shuffle UI → Workflow → Webhook trigger → copy URI; use container hostname `http://shuffle-backend:5001/api/v1/hooks/…` |
| `CALDERA_API_KEY` | *(required)* | Injected into `conf/local.yml`; used as `KEY:` header by caldera_monitor.py | `python3 -c "import secrets; print(secrets.token_hex(20))"` |
| `CALDERA_URL` | `http://localhost:8889` | CALDERA API base URL for caldera_monitor.py | Host: `http://localhost:8889`; inside jupyter: `http://caldera:8888` |
| `CALDERA_CRYPT_SALT` | *(required)* | Internal CALDERA encryption — set stable value | `python3 -c "import secrets; print(secrets.token_hex(16))"` — set once |
| `CALDERA_ENCRYPTION_KEY` | *(required)* | Internal CALDERA encryption — set stable value | Same as above |
| `CALDERA_CONTACT_URL` | `http://0.0.0.0:8888` | Callback URL embedded in Sandcat agents | Mac LAN IP + host port 8889, e.g. `http://192.168.1.100:8889` |
| `CALDERA_RED_PASSWORD` | `redpassword` | CALDERA red-team UI login | Override in .env if desired |
| `CALDERA_BLUE_PASSWORD` | `bluepassword` | CALDERA blue-team UI login | Override in .env if desired |
| `COMPOSE_PROJECT_NAME` | `homelabsiem` | Docker network prefix (all stacks share `${name}_soc_net`) | Set once; changing it requires recreating all stacks |

**Critical:** `SHUFFLE_ENCRYPTION_MODIFIER` must never change after first use — Shuffle
cannot decrypt stored credentials if it changes. `CALDERA_CRYPT_SALT` and
`CALDERA_ENCRYPTION_KEY` must be stable for CALDERA operation data to survive restarts.

---

## 7. INDICES

| Index | Written by | Purpose |
|---|---|---|
| `security-events-mordor` | `load_mordor.py` | Immutable evaluation set — 30,033 labeled Windows events from OTRF Mordor ATT&CK scenarios. Never delete or reindex. |
| `security-scores-if` | `model_runner.py` (scoring), `alert_explainer.py` (enrichment), `shuffle_notifier.py` (notified flag) | ML output: every scored event with `ml.*` fields. The primary operational index. |
| `security-events-wazuh` | `wazuh_bridge.py` | ECS-normalised copy of Wazuh alerts for the ML pipeline. Re-created on each bridge run. |
| `wazuh-alerts-4.x-*` | Wazuh manager filebeat | Raw Wazuh alerts — do not query from Python; use `security-events-wazuh` instead. |
| `siem-logs` | `ingest.py`, `anomaly.py`, `llm_analyst.py` | Legacy index from early prototyping. Not used in the main pipeline. |

Do not modify the mapping of `security-scores-if` without asking first.
Do not delete or modify `security-events-mordor` — it is the evaluation ground truth.

---

## 8. ML FIELD REFERENCE (`security-scores-if`)

All custom fields live under the `ml` object. Two sets of fields exist:
**model_runner fields** (set at scoring time) and **alert_explainer fields** (set after
LLM enrichment). Do not use a doc-level update to write these fields — always use a
Painless partial-update script to avoid wiping fields set by the other component.

### Fields set by `model_runner.py`

| Field | Type | What it means |
|---|---|---|
| `ml.anomaly_score` | float [0,1] | Raw IF decision function, normalised. 1.0 = maximally anomalous. |
| `ml.is_anomaly` | boolean | True if score ≥ contamination threshold (default 5%). |
| `ml.model` | keyword | Always `"isolation_forest_v1"` — identifies the model version. |
| `ml.scored_at` | date | ISO-8601 timestamp when this event was scored. |
| `ml.anomaly_percentile` | float [0,100] | Percentile rank within the scored batch. 99 = more anomalous than 99% of all events in this run. |
| `ml.top_features` | list[{feature, z_score}] | Top-3 feature contributors by absolute z-score. z > 0 = above training mean; z < 0 = below. |
| `ml.routing_decision` | keyword | IF-only coarse triage: **`tier-1`** (score ≥ 0.8) / **`tier-2`** (0.5–0.8) / **`auto-close`** (< 0.5 or not anomalous). *Overwritten* by alert_explainer after enrichment. |

### Fields set by `alert_explainer.py` (present only on enriched events)

| Field | Type | What it means |
|---|---|---|
| `ml.enriched` | boolean | True once LLM enrichment has been written. Used to skip re-enrichment. |
| `ml.enrichment_path` | keyword | `"A"` (Wazuh-backed) or `"B"` (full LLM classification). See §9. |
| `ml.llm_triage` | object | Structured LLM output — keys: `attack_technique`, `attack_tactic`, `description`, `fp_assessment` (low/medium/high), `fp_reasoning`, `investigation_steps` (list). |
| `ml.llm_confidence` | float [0,1] | TP confidence derived from fp_assessment: low FP → 1.0; medium → 0.6; high → 0.2. |
| `ml.combined_confidence` | float [0,1] | Geometric mean of anomaly_score × pct_norm × llm_confidence. See §10. |
| `ml.routing_decision` | keyword | **Replaces** the IF routing after enrichment: **`high_priority`** (combined ≥ 0.7) / **`analyst_review`** (0.4–0.7) / **`auto-close`** (< 0.4). Drives Shuffle forwarding. |
| `ml.if_llm_disagreement` | boolean | **True when IF score > 0.8 AND llm_confidence < 0.3.** The model found extreme structural rarity but the LLM assessed high false-positive probability. These are the most research-valuable events — see below. |

### `ml.if_llm_disagreement` — the most interesting output

`if_llm_disagreement = True` fires on events where the Isolation Forest and the LLM
reach opposite conclusions. The IF scored the event at > 0.8 (structurally rare in
this environment — more anomalous than ~95% of training data), but the LLM assessed
`fp_assessment = "high"` (likely a false positive given the contextual details).

**Why this matters:** There are exactly two explanations for each disagreement case:
1. The IF learned a spurious pattern. The training data contained a routine but rare
   event (e.g., a one-off admin script) that the model treats as anomalous, but the
   LLM correctly recognises as benign.
2. The LLM is missing domain context. The event is a genuine novel attack that the
   LLM has not seen described in its training data, so it defaults to a low-threat
   assessment even though the IF correctly detected structural rarity.

Both cases are actionable: case 1 identifies training set contamination or model
calibration issues; case 2 identifies attacks that evade semantic detection. Disagreement
cases are surfaced first in the Streamlit Alert Queue tab under the "⚠️ Needs analyst
review" expander.

---

## 9. THE TWO-PATH ENRICHMENT RULE

`alert_explainer.py` routes each alert to one of two prompting strategies before
calling the LLM, controlled by the presence of `wazuh.rule.id` in the event source.

**Path A — Wazuh-assisted (ml.enrichment_path = "A")**

Condition: `wazuh.rule.id` is present (event came through the Wazuh bridge).

Wazuh's rule matching already provides a verified ATT&CK technique mapping (from
`event.mitre.technique` set by `wazuh_bridge.py`). Asking the LLM to reclassify the
technique is wasteful and noisy — it may disagree with the Wazuh research team's
mapping for no good reason. Path A uses a shorter prompt (~60% fewer tokens) that
tells the LLM the technique is already known and asks only: "Is this a true or false
positive in this specific context?" and "What are the three most important investigation
steps?"

**Path B — ML-only (ml.enrichment_path = "B")**

Condition: no Wazuh rule ID (event came from Mordor ingest or a non-Wazuh source).

The full prompt is used: all event fields, the percentile rank, the top z-score
features, and the request for ATT&CK technique classification from scratch.

**Why `ml.enrichment_path` matters for research:**

`path = "B"` and `ml.is_anomaly = True` identifies events that the Isolation Forest
flagged as structurally unusual in this environment but that Wazuh's rule library
did not recognise. These are the cases where the ML model is adding genuine detection
value beyond the rule-based platform. A high proportion of B-path anomalies means the
ML is finding things Wazuh misses. A low proportion means the ML is mostly confirming
what Wazuh already knew.

---

## 10. COMBINED CONFIDENCE SCORING

`compute_combined_confidence(if_score, percentile, fp_assessment)` in
`alert_explainer.py` fuses three signals:

```
combined = (if_score × pct_norm × llm_conf) ^ (1/3)

where:
  pct_norm  = percentile / 100.0  (or if_score if percentile unavailable)
  llm_conf  = {low: 1.0, medium: 0.6, high: 0.2}[fp_assessment]
```

**Geometric mean semantics:** All three signals must agree for a high combined score.
A very high IF score cannot override a strong LLM FP assessment. An event scoring
0.95 (IF) at the 99th percentile with fp_assessment="high" gives combined =
(0.95 × 0.99 × 0.2)^(1/3) ≈ 0.58 → `analyst_review`. This is correct: the model
found something statistically rare but the LLM thinks it is benign; a human should
look at it, but it should not page anyone.

**Routing thresholds after enrichment:**

| `ml.routing_decision` | Condition | Analyst action |
|---|---|---|
| `high_priority` | combined ≥ 0.7 | Forwarded to Shuffle SOAR immediately; requires analyst review within SLA |
| `analyst_review` | 0.4 ≤ combined < 0.7 | Queued in Streamlit Alert Queue; review at next shift |
| `auto-close` | combined < 0.4 | Logged, not forwarded; re-examine if detection rate drops |

`ml.if_llm_disagreement` fires separately when `if_score > 0.8 AND llm_conf < 0.3`
(regardless of combined score), placing the event in the analyst review expander.

---

## 11. CODING CONVENTIONS

- **All scripts** accept `--dry-run` (no ES writes, prints results) and `--verbose` flags.
- **ES connections**: always `os.getenv("ELASTIC_URL", "http://localhost:9200")`.
  Never hardcode a URL or IP address.
- **Ollama connections**: always `ollama.Client(host=os.getenv("OLLAMA_URL", "…"))`.
  Never call `ollama.chat()` without an explicit host — the ollama library silently
  ignores `OLLAMA_URL` if you use the module-level function instead of the Client class.
- **MLflow**: `os.getenv("MLFLOW_TRACKING_URI", "http://localhost:5000")`. Wrap all
  MLflow calls in try/except — a down tracking server must never block a retrain.
- **LLM_BACKEND**: `os.getenv("LLM_BACKEND", "groq")` — never hardcode a backend.
- **ES writes for `ml.*` fields**: always use a Painless partial-update script.
  A doc-level update silently replaces the entire `_source` and wipes `ml.anomaly_score`.
- **Logging**: use the Python `logging` module (not `print`) for all diagnostic output.
  CLI results (summaries, scorecard tables) may use `print`.
- **Line endings**: LF only. `.gitattributes` enforces this. Never commit CRLF files.
- **Docstrings**: one sentence explaining the security intuition (why this catches
  this threat), not just what the code does mechanically.
- **Importable AND runnable**: every script must work as `python3 script.py` AND as
  `from src.x.script import func`. Use `if __name__ == "__main__": main()`.
- **File paths**: use `pathlib.Path` and construct paths relative to `__file__`.
  Never hardcode absolute paths; the repo must work on any machine.
- **Tests required**: every new `src/` file must have a corresponding `tests/test_*.py`.
  Unit tests must not require ES or Ollama (use `--dry-run` / mocks).

---

## 12. TESTING

```bash
make test        # unit tests only — no ES, Ollama, or CALDERA required (host Python)
make test-all    # all tests including integration — runs inside soc_jupyter container
                 # (requires running stack with data in security-events-mordor)
```

**Why `make test-all` runs inside the container:** The host may have elasticsearch-py
9.x while the server is ES 8.14. The container has `elasticsearch==8.13.0` (pinned).
Client/server version mismatch causes `BadRequestError(400)` on the host for integration
tests. Always use `docker exec soc_jupyter python3 -m pytest /home/jovyan/work/tests/ -v`
for integration tests.

**Test counts (current):**

| File | Unit | Integration | Total |
|---|---|---|---|
| `tests/test_alert_explainer.py` | 36 | 2 | 38 |
| `tests/test_caldera_monitor.py` | 39 | 0 | 39 |
| `tests/test_model_runner.py` | 35 | 2 | 37 |
| `tests/test_nightly_retrain.py` | 18 | 2 | 20 |
| **Total** | **128** | **6** | **134** |

**Integration test requirements:**
- `test_model_runner` integration: ES running with `security-events-mordor` populated.
- `test_alert_explainer` integration: ES running with `security-scores-if` populated;
  live LLM test skips automatically if `GROQ_API_KEY` is a placeholder.
- `test_nightly_retrain` integration: ES running.
- `test_caldera_monitor`: all unit tests, no external dependencies.

---

## 13. THE RED/BLUE LOOP

The complete adversary emulation → ML detection → coverage gap → improve cycle:

```
1. SIMULATE   make caldera-up
              Open http://localhost:8889 (red / redpassword)
              Deploy Sandcat agent to Windows VM (Agents → Deploy → PowerShell one-liner)
              Create operation (Operations → New → choose adversary → Start)
              Copy operation UUID from the URL bar

2. MONITOR    python3 src/redblue/caldera_monitor.py \
                --operation-id <UUID> \
                --poll-interval 30 \
                --verbose
              # Or from inside jupyter: make caldera-monitor OP=<UUID>
              Output: data/runs/live_detection_YYYY-MM-DD.json

3. REVIEW     Open Streamlit :8501 → Coverage Gap tab
              KPIs: detection_rate, avg_detection_latency_seconds
              Table: per-technique detected (green) / missed (red)
              For each missed technique: LLM one-sentence improvement suggestion

4. IMPROVE    For each missed technique:
              a. Follow the LLM suggestion in Tab 2
              b. Edit src/models/feature_engineering.py (add feature)
                 OR add a Wazuh rule in the Wazuh UI
              c. make retrain-now   (full retrain, ~3 min)
              d. make score-only    (incremental re-score with new model)
              e. MLflow at :5000 records the run — compare detection metrics

5. REPEAT     Run another CALDERA operation and compare detection_rate
              to the previous scorecard file in data/runs/
```

**Demo mode** (no live CALDERA required):
```bash
python3 src/redblue/caldera_monitor.py --demo
# Writes a synthetic 3-technique scorecard so the Coverage Gap tab
# can be tested without a running CALDERA instance.
```

**Detection window:** A technique is "detected" if any event from the target host
scores `ml.anomaly_score ≥ 0.5` within 90 seconds of the CALDERA link completing.
Override: `--detection-threshold 0.3 --detect-window 120`.

---

## 14. WINDOWS / GPU MIGRATION

### Moving to a new Windows PC with more RAM

1. Install Docker Desktop 4.x+ with WSL2 (see `WINDOWS_SETUP.md` §1–2).
2. `git clone` the repo onto the new machine.
3. Copy your `.env` file (or recreate from `.env.example` — re-enter all keys).
4. `data/raw/` (Mordor ZIPs) and `data/processed/` travel with the repo via git.
   `data/models/isolation_forest.pkl` also travels — copy it or run `make train`.
   `es_data` (the Docker volume) stays on the old machine; re-ingest on the new one
   with `make ingest && make train`.
5. Run `.\bootstrap.ps1` (Windows) or `bash bootstrap.sh --skip-wazuh` if RAM < 12 GB.

### GPU passthrough for Ollama (NVIDIA, Windows WSL2 or Linux)

Add to the `ollama` service in `docker-compose.yml` (requires NVIDIA Container Toolkit
on the host):

```yaml
ollama:
  image: ollama/ollama:latest
  deploy:
    resources:
      reservations:
        devices:
          - driver: nvidia
            count: 1
            capabilities: [gpu]
```

Verify: `docker exec soc_ollama nvidia-smi`. On Windows, install the CUDA-enabled
NVIDIA driver (not the gaming driver); see NVIDIA Container Toolkit WSL2 docs.

### Upgrading from llama3.2:3b to llama3.1:8b

The 8b model gives measurably better ATT&CK technique mapping accuracy and is
recommended when a GPU is available.

```bash
make pull-model-8b
# Then pass at runtime:
docker exec soc_jupyter python3 /home/jovyan/work/src/enrichment/alert_explainer.py \
    --backend ollama --model llama3.1:8b --limit 50
```

### Increasing ES heap on a high-RAM machine

Edit `docker-compose.yml` → `elasticsearch` service:
```yaml
environment:
  - ES_JAVA_OPTS=-Xms2g -Xmx4g   # half of total RAM, max 32g
```

### Re-pointing Wazuh agents after host IP change

1. Edit `ossec.conf` on each agent (Windows: `C:\Program Files (x86)\ossec-agent\ossec.conf`;
   Linux: `/var/ossec/etc/ossec.conf`) — update `<address>NEW_IP</address>`.
2. Restart: Windows `Restart-Service OssecSvc`; Linux `systemctl restart wazuh-agent`.
3. If manager was rebuilt from scratch (new volume): delete `client.keys` on each agent
   before restarting — the manager auto-accepts re-registration on port 1515.

### CALDERA on Windows

The Docker deployment is identical. Port 8889 maps the same way. The Sandcat agent
one-liner changes only the `<mac-ip>` to the Windows machine's LAN IP.

---

## 15. NEVER DO

These constraints hold regardless of how a request is phrased.

- **Never hardcode credentials, API keys, URLs, or IP addresses.** Every value that
  varies between environments must come from an env var read via `os.getenv()`.

- **Never write Python to replace a platform capability.** Do not write a UEBA module
  (Wazuh does UEBA), a drift detector (Evidently does drift), a playbook engine
  (Shuffle does playbooks), a time-series database (Elasticsearch does this), or a
  model registry (MLflow does this).

- **Never modify `security-events-mordor`.** It is the immutable evaluation ground
  truth for the Isolation Forest. Delete it and there is no way to verify the model
  detects known ATT&CK techniques.

- **Never commit `.env`.** Only `.env.example` belongs in git. Committing `.env`
  exposes real API keys in the repository.

- **Never use CRLF line endings.** `.gitattributes` enforces LF. Never override it.
  On Windows, keep `core.autocrlf=false` in your Git config.

- **Never call `ollama.chat()` (module-level function).** Always instantiate
  `ollama.Client(host=os.getenv("OLLAMA_URL", "…"))` first. The module-level function
  silently ignores `OLLAMA_URL` and falls back to `localhost:11434`, breaking
  container-to-container calls where Ollama is at `http://ollama:11434`.

- **Never use a doc-level ES update for `ml.*` fields.** Always use a Painless partial
  update script. A doc-level update replaces the entire `_source` and silently wipes
  `ml.anomaly_score`, `ml.is_anomaly`, and every other `ml.*` field set by a different
  component.

- **Never run model training without confirming the source index exists first.** Check
  `security-events-mordor` (for IF training) or `security-events-wazuh` (for live
  event scoring) before calling `model_runner.py`.

- **Never delete data in `data/raw/`.** The Mordor ZIPs are the only copy of the
  evaluation dataset.

- **Never modify an existing index mapping without asking first.** Adding fields is
  safe; changing field types causes mapping conflicts that require reindexing.

---

## 16. HOW TO EXPLAIN YOUR WORK

After building any component, explain four things:

1. **The security intuition** — why this technique catches this type of threat, not
   just what the code does mechanically.
2. **The design choices** — why this structure; what alternative was rejected and why.
3. **What the output means** — what a number, field, or chart tells an analyst and
   how to interpret an unexpected value.
4. **What to try next** — the natural next experiment or extension.

---

## 17. PROJECT LAYOUT

```
Home Lab SIEM/
├── CLAUDE.md                    ← you are here (single source of truth)
├── SPEC.md                      ← original feature spec
├── BUILD_PLAN.md                ← completed phase log
├── WHAT_CHANGED.md              ← architectural decision history
├── WINDOWS_SETUP.md             ← Windows Docker Desktop + WSL2 guide
├── bootstrap.sh                 ← one-shot lab setup (macOS/Linux)
├── bootstrap.ps1                ← one-shot lab setup (Windows PowerShell)
├── Makefile                     ← all common tasks (make help for list)
├── docker-compose.yml           ← main stack (ES, Jupyter, Streamlit, Shuffle, cron)
├── docker-compose.wazuh.yml     ← Wazuh stack (shares soc_net)
├── docker-compose.caldera.yml   ← CALDERA stack (shares soc_net, port 8889)
├── docker/
│   ├── jupyter/Dockerfile       ← Python 3.11 + ML stack
│   ├── streamlit/Dockerfile     ← slim Streamlit image
│   └── caldera/entrypoint.sh   ← generates conf/local.yml from env vars at startup
├── src/
│   ├── ingest/
│   │   ├── load_mordor.py       ← downloads + indexes 6 Mordor ATT&CK scenario ZIPs
│   │   └── wazuh_bridge.py      ← copies wazuh-alerts-4.x-* → security-events-wazuh (ECS)
│   ├── models/
│   │   ├── feature_engineering.py  ← 13-feature rarity scoring (our core IP)
│   │   └── model_runner.py         ← IF training, scoring, MLflow logging
│   ├── enrichment/
│   │   └── alert_explainer.py   ← Path A/B enrichment, combined confidence, routing
│   ├── dashboard/
│   │   └── app.py               ← Streamlit: Tab 1 Alert Queue, Tab 2 Coverage Gap
│   ├── redblue/
│   │   └── caldera_monitor.py   ← CALDERA polling + detection scorecard
│   ├── response/
│   │   └── shuffle_notifier.py  ← polls security-scores-if → POSTs to Shuffle webhook
│   ├── monitoring/
│   │   └── evidently_monitor.py ← drift + quality HTML reports
│   └── scheduler/
│       └── nightly_retrain.py   ← retrain + enrichment sweep jobs (called by ofelia)
├── docs/
│   ├── caldera_setup.md         ← CALDERA Docker start + Windows agent deploy guide
│   └── shuffle_workflow_setup.md
├── tests/
│   ├── test_alert_explainer.py  ← 38 tests (36 unit, 2 integration)
│   ├── test_caldera_monitor.py  ← 39 tests (all unit)
│   ├── test_model_runner.py     ← 37 tests (35 unit, 2 integration)
│   └── test_nightly_retrain.py  ← 20 tests (18 unit, 2 integration)
├── data/
│   ├── raw/                     ← Mordor ZIPs (never delete, never modify)
│   ├── processed/               ← feature-engineered outputs
│   ├── models/                  ← isolation_forest.pkl + scaler
│   └── runs/                    ← scorecard JSON, cursor JSON, drift HTML (NOT audit trail)
└── notebooks/                   ← Jupyter exploration (not production)
```
