"""
SOC ML Lab — Streamlit dashboard.

Two tabs:
  1. Alert Queue     — sortable anomaly table with percentile + routing columns;
                       click a row to see LLM triage inline.
  2. Coverage Gap    — stub panel for future CALDERA adversary emulation coverage.

Run: streamlit run src/dashboard/app.py
     (or via docker-compose: http://localhost:8501)
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st
from elasticsearch import Elasticsearch

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

ES_URL       = os.getenv("ELASTIC_URL", "http://localhost:9200")
SCORES_INDEX = "security-scores-if"
REFRESH_SEC  = 60

# ── Page config ───────────────────────────────────────────────────────────────

st.set_page_config(
    page_title="SOC ML Lab",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)
st.title("🛡️ SOC ML Lab — Anomaly Dashboard")


# ── ES client ─────────────────────────────────────────────────────────────────

@st.cache_resource
def get_client() -> Elasticsearch:
    return Elasticsearch(ES_URL)


# ── Data loading ──────────────────────────────────────────────────────────────

@st.cache_data(ttl=REFRESH_SEC)
def load_alert_queue(threshold: float, limit: int) -> tuple[list[dict], pd.DataFrame]:
    """
    Fetch scored events above the threshold. Returns raw hits (for the triage
    panel) and a flat DataFrame (for st.dataframe rendering).
    """
    client = get_client()
    try:
        resp = client.search(
            index=SCORES_INDEX,
            body={
                "query": {"range": {"ml.anomaly_score": {"gte": threshold}}},
                "sort":  [{"ml.anomaly_score": "desc"}],
                "size":  limit,
                "_source": [
                    "@timestamp", "host.name", "user.name",
                    "process.name", "process.parent.name", "process.command_line",
                    "event.category", "event.channel", "source_dataset",
                    "ml.anomaly_score", "ml.anomaly_percentile",
                    "ml.is_anomaly", "ml.routing_decision",
                    "ml.enriched", "ml.llm_triage", "ml.top_features",
                    "ml.combined_confidence", "ml.llm_confidence",
                    "ml.if_llm_disagreement",
                ],
            },
        )
    except Exception as exc:
        st.error(f"Elasticsearch error: {exc}")
        return [], pd.DataFrame()

    hits = resp["hits"]["hits"]
    if not hits:
        return [], pd.DataFrame()

    rows = []
    for h in hits:
        s   = h["_source"]
        ml  = s.get("ml") or {}
        ev  = s.get("event") or {}
        pr  = s.get("process") or {}
        par = pr.get("parent") or {}
        rows.append({
            "_id":              h["_id"],
            "score":            round(ml.get("anomaly_score", 0), 4),
            "percentile":       ml.get("anomaly_percentile"),
            "combined":         ml.get("combined_confidence"),
            "routing":          ml.get("routing_decision", "—"),
            "disagreement":     ml.get("if_llm_disagreement", False),
            "enriched":         ml.get("enriched", False),
            "category":         ev.get("category", ""),
            "process":          pr.get("name", ""),
            "parent":           par.get("name", ""),
            "user":             (s.get("user") or {}).get("name", ""),
            "host":             (s.get("host") or {}).get("name", ""),
            "dataset":          s.get("source_dataset", ""),
        })

    return hits, pd.DataFrame(rows)


@st.cache_data(ttl=REFRESH_SEC)
def load_kpi_stats() -> dict:
    """Aggregate stats for the KPI row."""
    client = get_client()
    try:
        resp = client.search(
            index=SCORES_INDEX,
            body={
                "size": 0,
                "aggs": {
                    "total_anomalies": {"filter": {"term": {"ml.is_anomaly": True}}},
                    "enriched_count":  {"filter": {"term": {"ml.enriched": True}}},
                    "score_stats":     {"stats": {"field": "ml.anomaly_score"}},
                },
            },
        )
    except Exception as exc:
        st.error(f"Elasticsearch error: {exc}")
        return {}
    return resp.get("aggregations", {})


# ── Sidebar ───────────────────────────────────────────────────────────────────

with st.sidebar:
    st.header("Controls")

    threshold = st.slider(
        "Score threshold", 0.0, 1.0, 0.70, 0.05,
        help="Show events with anomaly_score ≥ this value.",
    )
    alert_limit = st.select_slider(
        "Alerts to load", options=[50, 100, 200, 500], value=100,
    )

    st.divider()
    st.subheader("LLM Triage")
    # llama3.2:3b — ~2 GB RAM, ~2 s/response; good for interactive use.
    # llama3.1:8b — ~5 GB RAM, ~8 s/response; better ATT&CK mapping accuracy.
    llm_model = st.selectbox(
        "Model",
        options=["llama3.2:3b", "llama3.1:8b"],
        index=0,
        help="3b is faster for real-time triage; 8b gives more accurate ATT&CK mapping.",
    )

    st.divider()
    if st.button("🔄 Refresh data"):
        st.cache_data.clear()
        st.rerun()

    st.caption(f"Index: `{SCORES_INDEX}`")
    st.caption(f"ES: `{ES_URL}`")


# ── KPI row (always visible) ──────────────────────────────────────────────────

kpi = load_kpi_stats()
total_events    = (kpi.get("score_stats") or {}).get("count", 0)
total_anomalies = (kpi.get("total_anomalies") or {}).get("doc_count", 0)
enriched_count  = (kpi.get("enriched_count") or {}).get("doc_count", 0)
avg_score       = (kpi.get("score_stats") or {}).get("avg", 0) or 0

k1, k2, k3, k4 = st.columns(4)
k1.metric("Total Events",    f"{total_events:,}")
k2.metric("Anomalies",       f"{total_anomalies:,}",
          f"{100*total_anomalies/max(total_events,1):.1f}%")
k3.metric("Enriched Alerts", f"{enriched_count:,}",
          f"{100*enriched_count/max(total_anomalies,1):.1f}% of anomalies")
k4.metric("Avg Score",       f"{avg_score:.3f}")

st.divider()


# ── Tabs ──────────────────────────────────────────────────────────────────────

tab_queue, tab_coverage = st.tabs(["🚨 Alert Queue", "🗺️ Coverage Gap"])


# ══ Tab 1: Alert Queue ════════════════════════════════════════════════════════

with tab_queue:
    raw_hits, alert_df = load_alert_queue(threshold, alert_limit)

    if alert_df.empty:
        st.info(f"No events with score ≥ {threshold:.2f}. Lower the threshold or refresh.")
    else:
        # ── Disagreement expander (analyst priority queue) ─────────────────────
        disagree_df = alert_df[alert_df["disagreement"] == True]
        if not disagree_df.empty:
            with st.expander(
                f"⚠️ Needs analyst review — {len(disagree_df)} IF↔LLM disagreement(s)",
                expanded=True,
            ):
                st.caption(
                    "**What is IF↔LLM disagreement?**  "
                    "The Isolation Forest scored these events very highly (structural rarity > 0.8) "
                    "but the LLM assessed them as likely false positives (fp_assessment = high). "
                    "These are the cases where the model and the language model disagree most strongly. "
                    "They require a human analyst to decide: is the IF detecting a genuine rare attack "
                    "the LLM doesn't recognise, or did the IF learn a spurious pattern?",
                    help=(
                        "ml.if_llm_disagreement = True when ml.anomaly_score > 0.8 "
                        "AND ml.llm_confidence < 0.3 (derived from fp_assessment = 'high'). "
                        "These cases expose the fundamental tension between statistical rarity "
                        "and contextual false-positive reasoning."
                    ),
                )
                st.dataframe(
                    disagree_df[["score", "percentile", "combined", "routing",
                                 "category", "process", "dataset"]],
                    use_container_width=True,
                    hide_index=True,
                    column_config={
                        "score":    st.column_config.ProgressColumn("IF Score", min_value=0, max_value=1, format="%.4f"),
                        "combined": st.column_config.NumberColumn("Combined", format="%.4f"),
                    },
                )

        st.caption(
            f"Showing top {len(alert_df):,} events with score ≥ {threshold:.2f} — "
            "click a row to see LLM triage"
        )

        display_df = alert_df[[
            "score", "percentile", "combined", "routing", "disagreement", "enriched",
            "category", "process", "parent", "user", "host", "dataset",
        ]].copy()

        selection = st.dataframe(
            display_df,
            use_container_width=True,
            hide_index=True,
            selection_mode="single-row",
            on_select="rerun",
            column_config={
                "score":        st.column_config.ProgressColumn(
                    "IF Score", min_value=0, max_value=1, format="%.4f", width="small",
                ),
                "percentile":   st.column_config.NumberColumn(
                    "Pctile", format="%.1f", width="small",
                    help="Percentile rank within the scored batch (100 = most anomalous)",
                ),
                "combined":     st.column_config.NumberColumn(
                    "Combined", format="%.4f", width="small",
                    help="Combined confidence: geometric mean of IF score, percentile, and LLM TP confidence. Higher = more suspicious.",
                ),
                "routing":      st.column_config.TextColumn("Routing", width="small"),
                "disagreement": st.column_config.CheckboxColumn(
                    "⚠️ Disagree", width="small",
                    help="True when IF score > 0.8 but LLM has low TP confidence (fp_assessment=high). Requires human review.",
                ),
                "enriched":     st.column_config.CheckboxColumn("Triaged", width="small"),
                "category":   st.column_config.TextColumn("Category"),
                "process":    st.column_config.TextColumn("Process"),
                "parent":     st.column_config.TextColumn("Parent"),
                "user":       st.column_config.TextColumn("User"),
                "host":       st.column_config.TextColumn("Host"),
                "dataset":    st.column_config.TextColumn("Dataset"),
            },
        )

        # ── LLM Triage panel ──────────────────────────────────────────────────
        selected_rows = selection.selection.rows
        if selected_rows:
            idx = selected_rows[0]
            hit = raw_hits[idx]
            src = hit["_source"]
            ml  = src.get("ml") or {}

            st.divider()
            proc   = (src.get("process") or {}).get("name", "unknown")
            score  = ml.get("anomaly_score", 0)
            pct    = ml.get("anomaly_percentile")
            pct_str = f"  ·  {pct:.1f}th percentile" if pct is not None else ""

            st.subheader(f"LLM Triage — `{proc}`  (score {score:.4f}{pct_str})")

            # Top features (if available from model_runner.py)
            top_feats = ml.get("top_features")
            if top_feats:
                feat_cols = st.columns(min(len(top_feats), 3))
                for i, feat in enumerate(top_feats[:3]):
                    feat_cols[i].metric(
                        feat["feature"],
                        f"z={feat['z_score']:+.2f}",
                        help="Signed z-score — how many standard deviations from the training mean. "
                             "High absolute value = primary driver of the anomaly score.",
                    )

            triage = ml.get("llm_triage")
            if triage:
                fp        = triage.get("fp_assessment", "medium").lower()
                fp_colour = {"low": "🟢", "medium": "🟡", "high": "🔴"}.get(fp, "⚪")

                col_a, col_b = st.columns([1, 2])
                with col_a:
                    st.markdown(f"**Technique**  \n`{triage.get('attack_technique','—')}`")
                    st.markdown(f"**Tactic**  \n{triage.get('attack_tactic','—')}")
                    st.markdown(
                        f"**FP Assessment**  \n{fp_colour} {fp.capitalize()} "
                        f"— {triage.get('fp_reasoning','')}"
                    )
                with col_b:
                    st.markdown(f"**Summary**  \n{triage.get('description','—')}")
                    steps = triage.get("investigation_steps") or []
                    if steps:
                        st.markdown("**Investigation steps**")
                        for i, step in enumerate(steps, 1):
                            st.markdown(f"{i}. {step}")
            else:
                st.info("This alert has not been LLM-enriched yet.")
                if st.button(f"Enrich now with {llm_model}", key="enrich_btn"):
                    with st.spinner(f"Calling {llm_model}…"):
                        try:
                            from src.enrichment.alert_explainer import (
                                build_prompt, call_llm, parse_response,
                                write_triage, client_from_env,
                            )
                            import ollama as _ollama
                            oc     = _ollama.Client(
                                host=os.getenv("OLLAMA_URL", "http://localhost:11434")
                            )
                            result = parse_response(call_llm(build_prompt(src), llm_model, oc))
                            if result:
                                write_triage(client_from_env(), hit["_id"], result)
                                st.cache_data.clear()
                                st.success("Enriched! Refreshing…")
                                st.rerun()
                            else:
                                st.error("LLM returned an unparseable response.")
                        except Exception as exc:
                            st.error(f"Enrichment failed: {exc}")

            with st.expander("Raw event fields"):
                ev = src.get("event") or {}
                pr = src.get("process") or {}
                st.json({
                    "@timestamp":       src.get("@timestamp"),
                    "host":             src.get("host"),
                    "user":             src.get("user"),
                    "process.name":     pr.get("name"),
                    "process.parent":   (pr.get("parent") or {}).get("name"),
                    "process.cmd":      pr.get("command_line"),
                    "event.category":   ev.get("category"),
                    "event.channel":    ev.get("channel"),
                    "event.id":         ev.get("id"),
                    "source_dataset":   src.get("source_dataset"),
                    "ml.anomaly_score": score,
                    "ml.percentile":    ml.get("anomaly_percentile"),
                    "ml.routing":       ml.get("routing_decision"),
                    "ml.model":         ml.get("model"),
                    "ml.top_features":  top_feats,
                })


# ══ Tab 2: Coverage Gap ═══════════════════════════════════════════════════════

# ── LLM suggestion for missed techniques (Coverage Gap) ───────────────────────

def _suggest_for_missed(technique_id: str) -> str:
    """
    Ask the configured LLM for a one-sentence feature/rule suggestion for a
    missed ATT&CK technique.

    Security intuition: when the Isolation Forest misses a technique, the gap
    is usually that the relevant telemetry either is not being collected or does
    not look statistically unusual in the training data. The LLM knows the
    ATT&CK technique catalogue and can suggest the most distinctive observable
    (e.g. 'monitor for file deletion of event logs' for T1070.004), pointing
    the analyst toward the right Wazuh rule or feature engineering target.
    """
    prompt = (
        f"You are a SOC detection engineer. The Isolation Forest model missed "
        f"ATT&CK technique {technique_id}. In one sentence, what specific "
        f"Windows event log field, process behaviour, or Wazuh rule would most "
        f"reliably catch this technique? Be concrete — name the event ID or "
        f"feature name if possible."
    )
    backend = os.getenv("LLM_BACKEND", "groq")
    try:
        if backend == "groq":
            from groq import Groq
            client = Groq(api_key=os.getenv("GROQ_API_KEY"))
            resp = client.chat.completions.create(
                model="llama-3.1-8b-instant",
                messages=[{"role": "user", "content": prompt}],
                temperature=0,
                max_tokens=150,
            )
            return resp.choices[0].message.content.strip()
        if backend == "claude":
            import anthropic
            client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
            resp = client.messages.create(
                model="claude-haiku-4-5-20251001",
                max_tokens=150,
                messages=[{"role": "user", "content": prompt}],
            )
            return resp.content[0].text.strip()
        # ollama fallback
        import ollama as _ollama
        oc   = _ollama.Client(host=os.getenv("OLLAMA_URL", "http://localhost:11434"))
        resp = oc.chat(
            model=os.getenv("OLLAMA_MODEL", "llama3.2:3b"),
            messages=[{"role": "user", "content": prompt}],
            options={"temperature": 0},
        )
        return resp["message"]["content"].strip()
    except Exception as exc:
        return f"(LLM unavailable: {exc})"


def load_latest_scorecard() -> Optional[dict]:
    """
    Read the most recent live_detection_YYYY-MM-DD.json from data/runs/.

    Returns None if no scorecard exists yet. Picking the alphabetically
    last filename gives the most recent date without parsing every file.
    """
    runs_dir = Path(__file__).resolve().parents[2] / "data" / "runs"
    files    = sorted(runs_dir.glob("live_detection_*.json"))
    if not files:
        return None
    try:
        return json.loads(files[-1].read_text())
    except Exception:
        return None


with tab_coverage:
    import json
    st.subheader("Coverage Gap — Live CALDERA Scorecard")

    scorecard = load_latest_scorecard()

    if scorecard is None:
        st.info(
            "No CALDERA scorecard found yet.\n\n"
            "Run a CALDERA operation and then:\n"
            "```\npython src/redblue/caldera_monitor.py --operation-id <UUID>\n```\n"
            "Or try the demo:\n"
            "```\npython src/redblue/caldera_monitor.py --demo\n```"
        )
        stub = pd.DataFrame({
            "Tactic":    ["Initial Access", "Execution", "Persistence",
                          "Privilege Escalation", "Defense Evasion",
                          "Credential Access", "Lateral Movement"],
            "Techniques": [3, 8, 5, 4, 7, 6, 4],
            "Covered":    [0, 3, 0, 1, 2, 4, 2],
        })
        stub["Gap"] = stub["Techniques"] - stub["Covered"]
        fig = px.bar(
            stub, x="Tactic", y=["Covered", "Gap"],
            title="ATT&CK Coverage by Tactic (placeholder — run CALDERA to populate)",
            labels={"value": "Techniques", "variable": ""},
            color_discrete_map={"Covered": "#2ecc71", "Gap": "#e74c3c"},
            barmode="stack",
        )
        fig.update_layout(xaxis_tickangle=-20)
        st.plotly_chart(fig, use_container_width=True)

    else:
        # ── Summary KPIs ──────────────────────────────────────────────────────
        op_name  = scorecard.get("operation_name", scorecard.get("operation", "—"))
        gen_at   = scorecard.get("generated_at", "")
        n_exec   = scorecard.get("techniques_executed", 0)
        n_det    = scorecard.get("detected", 0)
        n_miss   = scorecard.get("missed", 0)
        rate     = scorecard.get("detection_rate", 0)
        avg_lat  = scorecard.get("avg_detection_latency_seconds")
        is_demo  = scorecard.get("demo", False)

        if is_demo:
            st.caption("Demo scorecard — run a real CALDERA operation to replace this.")

        st.caption(f"Operation: **{op_name}** · Generated: {gen_at[:19].replace('T', ' ')} UTC")

        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Techniques Run",    n_exec)
        c2.metric("Detected",          n_det,
                  f"{rate:.0%}",
                  delta_color="normal")
        c3.metric("Missed",            n_miss,
                  f"-{n_miss}" if n_miss else "0",
                  delta_color="inverse")
        c4.metric("Avg Detection Latency",
                  f"{avg_lat:.1f} s" if avg_lat is not None else "—")

        st.divider()

        # ── Per-technique table ───────────────────────────────────────────────
        tech_results = scorecard.get("technique_results", [])
        if tech_results:
            rows = []
            for r in tech_results:
                rows.append({
                    "Technique":  r["technique_id"],
                    "Ability":    r["ability_name"],
                    "Host":       r["hostname"],
                    "Detected":   r["detected"],
                    "Max Score":  r["max_score"] if r["detected"] else None,
                    "Latency (s)": r["detection_latency_seconds"],
                    "Events":     r["detecting_events"],
                })
            tech_df = pd.DataFrame(rows)

            st.dataframe(
                tech_df,
                use_container_width=True,
                hide_index=True,
                column_config={
                    "Technique": st.column_config.TextColumn("Technique", width="small"),
                    "Ability":   st.column_config.TextColumn("Ability"),
                    "Host":      st.column_config.TextColumn("Host", width="small"),
                    "Detected":  st.column_config.CheckboxColumn(
                        "Detected",
                        width="small",
                        help="Green = ML model flagged an anomaly within the detection window.",
                    ),
                    "Max Score": st.column_config.ProgressColumn(
                        "Max Score", min_value=0, max_value=1, format="%.4f",
                    ),
                    "Latency (s)": st.column_config.NumberColumn(
                        "Latency (s)", format="%.1f",
                        help="Seconds from technique execution to first ML detection.",
                    ),
                    "Events": st.column_config.NumberColumn("Events", width="small"),
                },
            )

        # ── Coverage pie chart ────────────────────────────────────────────────
        if n_exec > 0:
            pie_df = pd.DataFrame({
                "Status": ["Detected", "Missed"],
                "Count":  [n_det, n_miss],
            })
            fig = px.pie(
                pie_df, names="Status", values="Count",
                color="Status",
                color_discrete_map={"Detected": "#2ecc71", "Missed": "#e74c3c"},
                title=f"Detection Coverage — {rate:.0%} of techniques detected",
            )
            st.plotly_chart(fig, use_container_width=True)

        # ── Missed-technique LLM suggestions ─────────────────────────────────
        missed = scorecard.get("missed_techniques", [])
        if missed:
            st.divider()
            st.subheader(f"Coverage Gap — {len(missed)} missed technique(s)")
            st.caption(
                "For each missed technique the LLM suggests one feature or rule "
                "that would most likely catch it. Use these as prioritised items "
                "for your next detection engineering sprint."
            )
            for tid in missed:
                with st.expander(f"🔴 {tid} — improvement suggestion", expanded=True):
                    # Find the ability name from technique_results
                    ability = next(
                        (r["ability_name"] for r in tech_results if r["technique_id"] == tid),
                        "",
                    )
                    if ability:
                        st.caption(f"Ability: {ability}")
                    cache_key = f"suggest_{tid}"
                    if cache_key not in st.session_state:
                        with st.spinner(f"Asking LLM about {tid}…"):
                            st.session_state[cache_key] = _suggest_for_missed(tid)
                    st.markdown(f"> {st.session_state[cache_key]}")
        else:
            st.success("All techniques were detected — no coverage gaps in this operation.")
