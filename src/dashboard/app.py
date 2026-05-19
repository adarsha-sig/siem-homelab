"""
Streamlit SIEM dashboard.
Run: streamlit run src/dashboard/app.py
"""

import os
import sys
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st
from elasticsearch import Elasticsearch

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

ES_HOST = os.getenv("ELASTIC_URL", "http://localhost:9200")
INDEX = "siem-logs"
REFRESH_SECONDS = 30

st.set_page_config(page_title="Security ML Lab", layout="wide", page_icon="🔐")
st.title("Security ML Lab — Live Anomaly Dashboard")


@st.cache_resource
def get_client():
    return Elasticsearch(ES_HOST)


@st.cache_data(ttl=REFRESH_SECONDS)
def load_events(hours: int = 24) -> pd.DataFrame:
    client = get_client()
    resp = client.search(
        index=INDEX,
        query={"range": {"timestamp": {"gte": f"now-{hours}h"}}},
        sort=[{"anomaly_score": "desc"}],
        size=500,
        _source=["timestamp", "source_ip", "event_type", "anomaly_score", "raw"],
    )
    rows = [h["_source"] for h in resp["hits"]["hits"]]
    if not rows:
        return pd.DataFrame(columns=["timestamp", "source_ip", "event_type", "anomaly_score", "raw"])
    df = pd.DataFrame(rows)
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df["anomaly_score"] = pd.to_numeric(df["anomaly_score"], errors="coerce")
    return df


# --- Sidebar controls ---
with st.sidebar:
    st.header("Controls")
    hours = st.slider("Lookback (hours)", 1, 168, 24)
    threshold = st.slider("Anomaly threshold", 0.0, 1.0, 0.75, 0.05)
    run_llm = st.button("Run LLM Triage")

df = load_events(hours)

# --- KPI row ---
col1, col2, col3, col4 = st.columns(4)
col1.metric("Total Events", len(df))
col2.metric("High Anomalies", int((df["anomaly_score"] >= threshold).sum()))
col3.metric(
    "Avg Score",
    f"{df['anomaly_score'].mean():.3f}" if not df.empty else "—",
)
col4.metric(
    "Unique Source IPs",
    df["source_ip"].nunique() if not df.empty else 0,
)

# --- Time-series chart ---
st.subheader("Anomaly Score Over Time")
if not df.empty and "timestamp" in df.columns:
    fig = px.scatter(
        df,
        x="timestamp",
        y="anomaly_score",
        color="event_type",
        hover_data=["source_ip", "raw"],
        title="Events coloured by type",
    )
    fig.add_hline(y=threshold, line_dash="dash", line_color="red", annotation_text="Threshold")
    st.plotly_chart(fig, use_container_width=True)
else:
    st.info("No data in this time window.")

# --- Events table ---
st.subheader(f"Top Anomalies (score ≥ {threshold})")
flagged = df[df["anomaly_score"] >= threshold].sort_values("anomaly_score", ascending=False)
st.dataframe(flagged[["timestamp", "source_ip", "event_type", "anomaly_score", "raw"]], use_container_width=True)

# --- LLM triage panel ---
if run_llm:
    with st.spinner("Asking local LLM for triage..."):
        try:
            from src.models.llm_analyst import analyse
            triage = analyse()
        except Exception as exc:
            triage = f"LLM triage failed: {exc}"
    st.subheader("LLM Triage")
    st.markdown(triage)
