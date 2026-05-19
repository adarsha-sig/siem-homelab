# SOC ML Lab — feature specification

## Core goal
Build a pipeline that: ingests security event data → trains ML anomaly
detection models → scores live/historical events → enriches alerts with
LLM triage → surfaces everything in a Streamlit dashboard.

## Data layer
- Primary index: security-events-{source} (e.g. security-events-mordor)
- Schema: ECS-aligned. Required fields: @timestamp, process.name,
  process.parent.name, process.command_line, user.name, host.name,
  event.category
- Scores index: security-scores-{model} (e.g. security-scores-if)
  Additional fields: ml.anomaly_score, ml.is_anomaly, ml.model,
  ml.scored_at, ml.llm_triage (object, added by enrichment step)

## Models to implement (in order)
1. Isolation Forest on process events (baseline anomaly detection)
2. LOF (Local Outlier Factor) on network events (beaconing / unusual comms)
3. LSTM sequence model for attack chain prediction (requires labelled data)
4. Graph analytics for lateral movement (auth event graph)

## LLM enrichment
- Model: llama3.1:8b via Ollama REST API
- For each anomaly: produce ATT&CK mapping, plain-english explanation,
  FP assessment (high/medium/low confidence true positive), 3 investigation steps
- Write enrichment back to ml.llm_triage field in the scores index

## Dashboard panels (Streamlit)
1. Alert queue — sortable table of anomalies with score, lineage, user, host
2. LLM triage panel — full enrichment for selected alert
3. Model metrics — score distribution histogram, anomaly rate over time
4. Dataset summary — index stats, event counts by category

## Scheduler
- Nightly retrain at 02:00 — fetch 7-day window, retrain all models,
  save to data/models/, score last 24h, write run summary JSON
- Weekly LLM enrichment sweep — enrich any anomaly not yet enriched

## Acceptance criteria for each component
Each component is done when:
- It runs without errors end-to-end
- It has a --dry-run mode
- It has at least one pytest test
- CLAUDE.md "explain your work" section has been completed in the run log