# Shuffle SOAR Workflow Setup

This guide walks through creating a two-branch Shuffle workflow that receives
ML alert payloads from `shuffle_notifier.py` and routes them for automated
response or analyst queuing.

---

## 1. Start Shuffle

```bash
docker compose up -d shuffle-database shuffle-backend shuffle-frontend shuffle-orborus
```

Wait ~60 seconds for OpenSearch to initialise, then open:

```
http://localhost:3001
```

On first visit Shuffle will prompt you to create an admin account. Set a
username and password — there is no default credential.

---

## 2. Create the webhook trigger

1. In the Shuffle UI click **Workflows** → **New workflow**
2. Name it `SOC ML Alert Triage`
3. In the left panel open **Triggers** and drag a **Webhook** node onto the canvas
4. Click the Webhook node — the sidebar shows a **Webhook URI** like:

   ```
   http://localhost:5001/api/v1/hooks/webhook_abc123def456
   ```

5. Copy this URI. This is your `SHUFFLE_WEBHOOK_URL`.

---

## 3. Configure SHUFFLE_WEBHOOK_URL

Add it to your environment (or a `.env` file you source before running Docker):

```bash
# For scripts running on the host (standalone testing)
export SHUFFLE_WEBHOOK_URL=http://localhost:5001/api/v1/hooks/webhook_abc123def456

# For ofelia inside Docker — use the internal service name
# (set this in docker-compose.yml jupyter environment block)
SHUFFLE_WEBHOOK_URL=http://shuffle-backend:5001/api/v1/hooks/webhook_abc123def456
```

Add to the `jupyter` service's `environment` in `docker-compose.yml`:

```yaml
environment:
  - SHUFFLE_WEBHOOK_URL=http://shuffle-backend:5001/api/v1/hooks/webhook_abc123def456
```

Then restart the jupyter container:

```bash
docker compose up -d jupyter
```

---

## 4. Build the two-branch workflow

The payload sent by `shuffle_notifier.py` looks like:

```json
{
  "alert_id": "eUc6P54B...",
  "routing_decision": "high_priority",
  "combined_confidence": 0.918,
  "anomaly_score": 0.88,
  "enrichment_path": "B",
  "timestamp": "2020-09-21T22:59:29Z",
  "host": "MORDORDC.theshire.local",
  "alert": { ... full ES document ... }
}
```

### Add a Condition node

1. From **Apps** drag a **Condition** node and connect it after the Webhook trigger
2. Set the condition:
   - **Field**: `{{ $exec.routing_decision }}`
   - **Condition**: `equals`
   - **Value**: `high_priority`

This creates two branches: **True** (high_priority) and **False** (analyst_review).

### Branch A — high_priority

Add actions for immediate automated response:

| Step | App | Action | Notes |
|------|-----|--------|-------|
| 1 | **Slack** (or **Email**) | Send message | Alert `{{ $exec.host }}` — confidence `{{ $exec.combined_confidence }}` |
| 2 | **HTTP** | POST | Optional: call a block-list API or firewall rule API |
| 3 | **Wazuh** | Create active response | Block the source IP via Wazuh AR if available |

### Branch B — analyst_review

Add actions to queue for human triage:

| Step | App | Action | Notes |
|------|-----|--------|-------|
| 1 | **Shuffle Tools** | Create case | Opens a case in Shuffle's built-in case management |
| 2 | **Slack** (or **Email**) | Send message to SOC channel | Lower urgency message with investigation steps from `{{ $exec.alert.ml.llm_triage.investigation_steps }}` |

### Connect and save

1. Connect the Condition node's two branches to their respective action chains
2. Click **Save** in the top toolbar
3. Click **Run** → **Test** to verify the workflow executes without errors

---

## 5. Test with a real alert

Manually set `routing_decision=high_priority` on one indexed alert and run the
notifier to confirm Shuffle receives the webhook:

```bash
# Step 1 — tag a document (replace DOCUMENT_ID with a real _id from your index)
curl -X POST "http://localhost:9200/security-scores-if/_update/DOCUMENT_ID" \
  -H "Content-Type: application/json" \
  -d '{
    "script": {
      "source": "ctx._source.ml.routing_decision = '\''high_priority'\''; ctx._source.ml.shuffle_notified = false;",
      "lang": "painless"
    }
  }'

# Step 2 — run the notifier once (with SHUFFLE_WEBHOOK_URL set)
SHUFFLE_WEBHOOK_URL=http://localhost:5001/api/v1/hooks/webhook_abc123def456 \
  python src/response/shuffle_notifier.py --verbose

# Step 3 — confirm the alert was marked notified
curl "http://localhost:9200/security-scores-if/_doc/DOCUMENT_ID" | python3 -m json.tool | grep shuffle_notified
```

In Shuffle UI go to **Workflows** → **SOC ML Alert Triage** → **Executions** to
see the workflow run and inspect the received payload.

Check the local audit log:

```bash
tail -5 data/runs/notified_alerts.json | python3 -m json.tool
```

---

## 6. Useful Shuffle apps for security workflows

| App | Use case |
|-----|----------|
| **Wazuh** | Query agent status, trigger active response |
| **VirusTotal** | Enrich IPs/hashes before deciding to escalate |
| **Slack / Email** | Analyst notifications |
| **HTTP** | Call any REST API (firewall, ITSM, ticketing) |
| **Shuffle Tools** | Case management, data transformation |

Install apps from **Apps** → **Browse apps** in the Shuffle UI.
