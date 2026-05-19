"""
Anomaly detection models for SIEM event scoring.
Trains unsupervised models on recent ES data and writes scores back to the index.
"""

from __future__ import annotations

import os

import numpy as np
import pandas as pd
from elasticsearch import Elasticsearch
from loguru import logger
from pyod.models.lof import LOF
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

ES_HOST = os.getenv("ELASTIC_URL", "http://localhost:9200")
INDEX = "siem-logs"
SCROLL = "2m"
BATCH = 1000


def fetch_features(client: Elasticsearch, hours: int = 24) -> pd.DataFrame:
    """Pull recent docs from ES and extract numeric features for scoring."""
    query = {
        "range": {
            "timestamp": {"gte": f"now-{hours}h", "lte": "now"}
        }
    }
    resp = client.search(
        index=INDEX,
        query=query,
        size=BATCH,
        _source=["_id", "source_ip", "event_type"],
    )
    hits = resp["hits"]["hits"]
    if not hits:
        return pd.DataFrame()

    rows = []
    for h in hits:
        src = h["_source"]
        rows.append({"_id": h["_id"], **src})

    df = pd.DataFrame(rows)
    # Encode categoricals as integer codes — expand as your schema grows
    for col in ["event_type", "source_ip"]:
        if col in df.columns:
            df[col] = pd.Categorical(df[col]).codes
    return df


def score_isolation_forest(df: pd.DataFrame, contamination: float = 0.05) -> np.ndarray:
    feature_cols = [c for c in df.columns if c != "_id"]
    X = StandardScaler().fit_transform(df[feature_cols].fillna(0))
    model = IsolationForest(contamination=contamination, random_state=42, n_jobs=-1)
    raw = model.fit_predict(X)          # -1 = anomaly, 1 = normal
    scores = model.score_samples(X)     # more negative = more anomalous
    # Normalise to [0, 1] where 1 is most anomalous
    normalised = 1 - (scores - scores.min()) / (scores.max() - scores.min() + 1e-9)
    return normalised


def score_lof(df: pd.DataFrame, contamination: float = 0.05) -> np.ndarray:
    feature_cols = [c for c in df.columns if c != "_id"]
    X = StandardScaler().fit_transform(df[feature_cols].fillna(0))
    model = LOF(contamination=contamination)
    model.fit(X)
    return model.decision_scores_  # higher = more anomalous (already normalised by PyOD)


def write_scores(client: Elasticsearch, ids: list[str], scores: np.ndarray) -> None:
    ops = []
    for doc_id, score in zip(ids, scores):
        ops.append({"update": {"_index": INDEX, "_id": doc_id}})
        ops.append({"doc": {"anomaly_score": float(score)}})
    if ops:
        client.bulk(operations=ops)
        logger.info(f"Wrote anomaly scores for {len(ids)} documents")


def run(hours: int = 24, method: str = "isolation_forest") -> None:
    client = Elasticsearch(ES_HOST)
    df = fetch_features(client, hours=hours)
    if df.empty:
        logger.warning("No documents found in the time window — skipping scoring")
        return

    ids = df["_id"].tolist()
    df = df.drop(columns=["_id"])

    if method == "lof":
        scores = score_lof(df)
    else:
        scores = score_isolation_forest(df)

    write_scores(client, ids, scores)
    logger.info(f"Anomaly scoring complete ({method}): {len(ids)} docs processed")


if __name__ == "__main__":
    import sys
    method = sys.argv[1] if len(sys.argv) > 1 else "isolation_forest"
    run(method=method)
