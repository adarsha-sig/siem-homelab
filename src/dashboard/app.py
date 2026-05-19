"""
SOC ML Lab — Streamlit dashboard.

Four panels (as tabs):
  1. Alert Queue   — sortable anomaly table; click a row to see LLM triage
  2. Model Metrics — score distribution, anomaly rate by category
  3. Dataset Summary — event counts by dataset and category

Run: streamlit run src/dashboard/app.py
     (or via docker-compose: http://localhost:8501)
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st
from elasticsearch import Elasticsearch

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

ES_URL        = os.getenv("ELASTIC_URL", "http://localhost:9200")
SCORES_INDEX  = "security-scores-if"
REFRESH_SEC   = 60

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
    Fetch scored events above the threshold, return raw hits + flat DataFrame.

    Raw hits are needed so the triage panel can access ml.llm_triage without
    a second ES round-trip. The flat DataFrame is what st.dataframe renders.
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
                    "ml.anomaly_score", "ml.is_anomaly", "ml.enriched", "ml.llm_triage",
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
            "_id":          h["_id"],
            "score":        round(ml.get("anomaly_score", 0), 4),
            "is_anomaly":   ml.get("is_anomaly", False),
            "enriched":     ml.get("enriched", False),
            "category":     ev.get("category", ""),
            "process":      pr.get("name", ""),
            "parent":       par.get("name", ""),
            "user":         (s.get("user") or {}).get("name", ""),
            "host":         (s.get("host") or {}).get("name", ""),
            "dataset":      s.get("source_dataset", ""),
            "@timestamp":   s.get("@timestamp", ""),
        })

    df = pd.DataFrame(rows)
    return hits, df


@st.cache_data(ttl=REFRESH_SEC)
def load_score_distribution() -> dict:
    """Aggregations for the Model Metrics panel."""
    client = get_client()
    try:
        resp = client.search(
            index=SCORES_INDEX,
            body={
                "size": 0,
                "aggs": {
                    "score_hist": {
                        "histogram": {"field": "ml.anomaly_score", "interval": 0.05}
                    },
                    "anomaly_by_category": {
                        "filter": {"term": {"ml.is_anomaly": True}},
                        "aggs": {
                            "cats": {"terms": {"field": "event.category", "size": 20}}
                        },
                    },
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


@st.cache_data(ttl=REFRESH_SEC)
def load_dataset_summary() -> dict:
    """Aggregations for the Dataset Summary panel."""
    client = get_client()
    try:
        resp = client.search(
            index=SCORES_INDEX,
            body={
                "size": 0,
                "aggs": {
                    "by_dataset":  {"terms": {"field": "source_dataset", "size": 20}},
                    "by_category": {"terms": {"field": "event.category",  "size": 25}},
                    "total":       {"value_count": {"field": "ml.anomaly_score"}},
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
        help="Only show events with anomaly_score ≥ this value.",
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
        help="3b is faster for real-time triage; 8b gives more accurate ATT&CK technique mapping.",
    )

    st.divider()
    if st.button("🔄 Refresh data"):
        st.cache_data.clear()
        st.rerun()

    st.caption(f"Index: `{SCORES_INDEX}`")
    st.caption(f"ES: `{ES_URL}`")


# ── Load data ─────────────────────────────────────────────────────────────────

raw_hits, alert_df = load_alert_queue(threshold, alert_limit)
agg_stats          = load_score_distribution()
dataset_agg        = load_dataset_summary()

total_events   = (agg_stats.get("score_stats") or {}).get("count", 0)
total_anomalies = (agg_stats.get("total_anomalies") or {}).get("doc_count", 0)
enriched_count  = (agg_stats.get("enriched_count") or {}).get("doc_count", 0)
avg_score       = (agg_stats.get("score_stats") or {}).get("avg", 0) or 0


# ── Top KPI row (always visible) ──────────────────────────────────────────────

k1, k2, k3, k4 = st.columns(4)
k1.metric("Total Events",    f"{total_events:,}")
k2.metric("Anomalies",       f"{total_anomalies:,}",
          f"{100*total_anomalies/max(total_events,1):.1f}%")
k3.metric("Enriched Alerts", f"{enriched_count:,}",
          f"{100*enriched_count/max(total_anomalies,1):.1f}% of anomalies")
k4.metric("Avg Score",       f"{avg_score:.3f}")

st.divider()


# ── Tabs ──────────────────────────────────────────────────────────────────────

tab_queue, tab_metrics, tab_datasets = st.tabs(
    ["🚨 Alert Queue", "📊 Model Metrics", "🗂️ Dataset Summary"]
)


# ══ Tab 1: Alert Queue ════════════════════════════════════════════════════════

with tab_queue:
    if alert_df.empty:
        st.info(f"No events with score ≥ {threshold:.2f}. Lower the threshold or refresh.")
    else:
        st.caption(
            f"Showing top {len(alert_df):,} events with score ≥ {threshold:.2f} — "
            "click a row to see LLM triage"
        )

        display_df = alert_df[[
            "score", "is_anomaly", "enriched",
            "category", "process", "parent",
            "user", "host", "dataset",
        ]].copy()

        selection = st.dataframe(
            display_df,
            use_container_width=True,
            hide_index=True,
            selection_mode="single-row",
            on_select="rerun",
            column_config={
                "score":      st.column_config.ProgressColumn(
                    "Score", min_value=0, max_value=1, format="%.4f", width="small",
                ),
                "is_anomaly": st.column_config.CheckboxColumn("Anomaly", width="small"),
                "enriched":   st.column_config.CheckboxColumn("Triaged", width="small"),
                "category":   st.column_config.TextColumn("Category"),
                "process":    st.column_config.TextColumn("Process"),
                "parent":     st.column_config.TextColumn("Parent"),
                "user":       st.column_config.TextColumn("User"),
                "host":       st.column_config.TextColumn("Host"),
                "dataset":    st.column_config.TextColumn("Dataset"),
            },
        )

        # ── LLM Triage panel (shown when a row is selected) ───────────────────
        selected_rows = selection.selection.rows
        if selected_rows:
            idx = selected_rows[0]
            hit = raw_hits[idx]
            src = hit["_source"]
            ml  = src.get("ml") or {}

            st.divider()
            proc  = (src.get("process") or {}).get("name", "unknown")
            score = ml.get("anomaly_score", 0)

            st.subheader(f"LLM Triage — `{proc}`  (score {score:.4f})")

            triage = ml.get("llm_triage")

            if triage:
                fp = triage.get("fp_assessment", "medium").lower()
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
                            oc     = _ollama.Client(host=os.getenv("OLLAMA_URL", "http://localhost:11434"))
                            prompt = build_prompt(src)
                            raw    = call_llm(prompt, llm_model, oc)
                            result = parse_response(raw)
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
                    "@timestamp":     src.get("@timestamp"),
                    "host":           src.get("host"),
                    "user":           src.get("user"),
                    "process.name":   pr.get("name"),
                    "process.parent": (pr.get("parent") or {}).get("name"),
                    "process.cmd":    pr.get("command_line"),
                    "event.category": ev.get("category"),
                    "event.channel":  ev.get("channel"),
                    "event.id":       ev.get("id"),
                    "source_dataset": src.get("source_dataset"),
                    "ml.anomaly_score": score,
                    "ml.model":       ml.get("model"),
                })


# ══ Tab 2: Model Metrics ══════════════════════════════════════════════════════

with tab_metrics:
    if not agg_stats:
        st.warning("Could not load aggregations from Elasticsearch.")
    else:
        # Score distribution histogram
        hist_buckets = (agg_stats.get("score_hist") or {}).get("buckets", [])
        if hist_buckets:
            hist_df = pd.DataFrame(hist_buckets).rename(
                columns={"key": "Score bucket", "doc_count": "Events"}
            )
            fig_hist = px.bar(
                hist_df, x="Score bucket", y="Events",
                title="Anomaly Score Distribution",
                color="Events",
                color_continuous_scale="Reds",
                labels={"Score bucket": "Anomaly Score (lower bound)"},
            )
            fig_hist.add_vline(
                x=threshold, line_dash="dash", line_color="crimson",
                annotation_text=f"threshold {threshold:.2f}",
                annotation_position="top right",
            )
            st.plotly_chart(fig_hist, use_container_width=True)

        # Anomalies by event category
        cat_buckets = (
            (agg_stats.get("anomaly_by_category") or {})
            .get("cats", {})
            .get("buckets", [])
        )
        if cat_buckets:
            cat_df = pd.DataFrame(cat_buckets).rename(
                columns={"key": "Category", "doc_count": "Anomalies"}
            ).sort_values("Anomalies", ascending=True)

            fig_cat = px.bar(
                cat_df, x="Anomalies", y="Category",
                orientation="h",
                title="Anomalies by Event Category",
                color="Anomalies",
                color_continuous_scale="Oranges",
            )
            st.plotly_chart(fig_cat, use_container_width=True)
        else:
            st.info("No anomaly-by-category data available yet.")


# ══ Tab 3: Dataset Summary ════════════════════════════════════════════════════

with tab_datasets:
    if not dataset_agg:
        st.warning("Could not load dataset aggregations.")
    else:
        col_ds, col_cat = st.columns(2)

        # Events by dataset
        ds_buckets = (dataset_agg.get("by_dataset") or {}).get("buckets", [])
        with col_ds:
            if ds_buckets:
                ds_df = pd.DataFrame(ds_buckets).rename(
                    columns={"key": "Dataset", "doc_count": "Events"}
                ).sort_values("Events", ascending=False)
                fig_ds = px.bar(
                    ds_df, x="Dataset", y="Events",
                    title="Events by ATT&CK Dataset",
                    color="Events",
                    color_continuous_scale="Blues",
                )
                fig_ds.update_layout(xaxis_tickangle=-30)
                st.plotly_chart(fig_ds, use_container_width=True)

        # Events by category
        cat_buckets_all = (dataset_agg.get("by_category") or {}).get("buckets", [])
        with col_cat:
            if cat_buckets_all:
                ac_df = pd.DataFrame(cat_buckets_all).rename(
                    columns={"key": "Category", "doc_count": "Events"}
                ).sort_values("Events", ascending=False).head(15)
                fig_ac = px.bar(
                    ac_df, x="Events", y="Category",
                    orientation="h",
                    title="Top 15 Event Categories",
                    color="Events",
                    color_continuous_scale="Greens",
                )
                st.plotly_chart(fig_ac, use_container_width=True)

        # Enrichment progress
        st.divider()
        prog_col1, prog_col2, prog_col3 = st.columns(3)
        prog_col1.metric("Total indexed events", f"{total_events:,}")
        prog_col2.metric("Flagged anomalies",    f"{total_anomalies:,}")
        prog_col3.metric(
            "LLM-enriched",
            f"{enriched_count:,}",
            f"{total_anomalies - enriched_count:,} remaining",
        )

        if total_anomalies > 0:
            pct = enriched_count / total_anomalies
            st.progress(pct, text=f"Enrichment progress: {pct*100:.1f}%")
