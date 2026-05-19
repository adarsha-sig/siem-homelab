"""
Feature engineering for security event anomaly detection.

Security intuition: raw Windows events are categorical (process names, channels,
EventIDs). The ML model needs numeric representations that capture *rarity* —
rare process names, unusual parent→child relationships, uncommon EventIDs.
Rarity is the primary signal for unsupervised anomaly detection because attackers
almost always do things that legitimate software never does.

All functions in this module are pure (no ES dependency) so they can be unit-
tested with synthetic data and reused across multiple model scripts.
"""

from __future__ import annotations

import re
from collections import Counter
from datetime import timezone

import numpy as np
import pandas as pd

# Regex for detecting base64 blobs ≥ 40 chars in command lines.
# Common in PowerShell -EncodedCommand payloads (T1059.001).
_B64_RE = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")

# Patterns that indicate download-cradle activity (T1105, T1059.001).
_DOWNLOAD_RE = re.compile(
    r"(DownloadString|DownloadFile|WebClient|Invoke-WebRequest|wget|curl\.exe|bitsadmin)",
    re.IGNORECASE,
)

# Ordinal encoding for event categories — higher = rarer/more interesting.
_CATEGORY_RANK = {
    "authentication":    1,
    "object_access":     2,
    "account_management":3,
    "network_share":     4,
    "file_create":       5,
    "dns_query":         6,
    "registry_event":    7,
    "network_connection":8,
    "pipe_event":        9,
    "process_termination":10,
    "wmi_activity":      11,
    "process_access":    12,
    "image_load":        13,
    "create_remote_thread":14,
    "script_execution":  15,
    "process_creation":  16,
    "credential_access": 17,
    "process_tamper":    18,
    "file_delete":       19,
    "file_create_stream_hash": 20,
}

# Ordinal encoding for channels.
_CHANNEL_RANK = {
    "Windows PowerShell":                           1,
    "System":                                       2,
    "Microsoft-Windows-TaskScheduler/Operational":  3,
    "Security":                                     4,
    "security":                                     4,
    "Microsoft-Windows-PowerShell/Operational":     5,
    "Microsoft-Windows-WMI-Activity/Operational":   6,
    "Microsoft-Windows-Sysmon/Operational":         7,
}

FEATURE_NAMES = [
    "event_category_rank",
    "channel_rank",
    "event_id",
    "proc_rarity",
    "parent_proc_rarity",
    "parent_child_rarity",
    "user_rarity",
    "host_event_rarity",
    "has_cmd",
    "cmd_len",
    "cmd_has_encoding",
    "cmd_has_download",
    "hour",
]


# ── Frequency tables ──────────────────────────────────────────────────────────

def build_frequency_tables(events: list[dict]) -> dict[str, Counter]:
    """
    Build inverse-frequency lookup tables from the corpus.

    Security intuition: frequency is the inverse of suspicion for unsupervised
    detection. 'cmd.exe' appearing 5,000 times is baseline. 'msbuild.exe'
    appearing 3 times demands scrutiny. We compute counts here and convert to
    rarity scores per-event in extract_row() so the transformation is reusable.
    """
    proc_counter:       Counter = Counter()
    parent_counter:     Counter = Counter()
    parent_child:       Counter = Counter()
    user_counter:       Counter = Counter()
    host_event:         Counter = Counter()

    for e in events:
        src = e.get("_source", e)
        proc  = (src.get("process") or {}).get("name")
        par   = (src.get("process") or {}).get("parent", {}).get("name")
        user  = (src.get("user") or {}).get("name")
        host  = (src.get("host") or {}).get("name")
        cat   = (src.get("event") or {}).get("category")

        if proc:
            proc_counter[proc] += 1
        if par:
            parent_counter[par] += 1
        if proc and par:
            parent_child[(par, proc)] += 1
        if user:
            user_counter[user] += 1
        if host and cat:
            host_event[(host, cat)] += 1

    return {
        "proc":         proc_counter,
        "parent":       parent_counter,
        "parent_child": parent_child,
        "user":         user_counter,
        "host_event":   host_event,
    }


def _rarity(key, counter: Counter, n_events: int) -> float:
    """
    Convert a raw count to a log-rarity score.

    log1p(n / count) grows quickly for rare items and is bounded, preventing
    singleton events from dominating the feature space entirely.
    """
    if not key:
        return 0.0
    count = counter.get(key, 0)
    if count == 0:
        return float(np.log1p(n_events))  # unseen = maximally rare
    return float(np.log1p(n_events / count))


# ── Per-event feature extraction ──────────────────────────────────────────────

def extract_row(event: dict, freq: dict[str, Counter], n_events: int) -> dict:
    """
    Extract a numeric feature vector from a single ECS-aligned event dict.

    The event dict may have its ECS fields at top level (when used from tests)
    or nested under '_source' (when fetched from Elasticsearch). Both forms
    are handled.
    """
    src = event.get("_source", event)

    # Safely navigate nested dicts produced by our ECS mapping.
    proc_block   = src.get("process") or {}
    parent_block = proc_block.get("parent") or {}
    event_block  = src.get("event") or {}
    user_block   = src.get("user") or {}
    host_block   = src.get("host") or {}

    proc   = proc_block.get("name")
    parent = parent_block.get("name")
    cmd    = proc_block.get("command_line") or ""
    user   = user_block.get("name")
    host   = host_block.get("name")
    cat    = event_block.get("category", "")
    ch     = event_block.get("channel", "")

    try:
        event_id = int(event_block.get("id", 0))
    except (TypeError, ValueError):
        event_id = 0

    ts = src.get("@timestamp", "")
    try:
        hour = pd.to_datetime(ts, utc=True).hour
    except Exception:
        hour = 0

    cmd_stripped = cmd.strip()
    has_cmd      = int(bool(cmd_stripped))
    cmd_len      = min(len(cmd_stripped), 4096)   # cap to avoid extreme outliers

    return {
        "event_category_rank": _CATEGORY_RANK.get(cat, 0),
        "channel_rank":        _CHANNEL_RANK.get(ch, 0),
        "event_id":            event_id,
        "proc_rarity":         _rarity(proc, freq["proc"], n_events),
        "parent_proc_rarity":  _rarity(parent, freq["parent"], n_events),
        "parent_child_rarity": _rarity(
            (parent, proc) if parent and proc else None,
            freq["parent_child"], n_events
        ),
        "user_rarity":         _rarity(user, freq["user"], n_events),
        "host_event_rarity":   _rarity(
            (host, cat) if host and cat else None,
            freq["host_event"], n_events
        ),
        "has_cmd":             has_cmd,
        "cmd_len":             cmd_len,
        "cmd_has_encoding":    int(bool(_B64_RE.search(cmd_stripped))),
        "cmd_has_download":    int(bool(_DOWNLOAD_RE.search(cmd_stripped))),
        "hour":                hour,
    }


# ── Full pipeline ──────────────────────────────────────────────────────────────

def build_feature_matrix(events: list[dict]) -> pd.DataFrame:
    """
    Convert a list of ECS event dicts into a numeric feature DataFrame.

    Rows correspond 1-to-1 with the input list so callers can zip events with
    scores without index alignment issues.

    Security intuition: the resulting matrix captures both what happened
    (event category, channel, EventID) and how unusual it is relative to the
    rest of the corpus (rarity scores). Isolation Forest splits on individual
    feature dimensions, so having both types of signal lets it isolate events
    that are unusual in *multiple* ways simultaneously — the fingerprint of a
    real attack.
    """
    if not events:
        return pd.DataFrame(columns=FEATURE_NAMES)

    freq = build_frequency_tables(events)
    n    = len(events)
    rows = [extract_row(e, freq, n) for e in events]
    return pd.DataFrame(rows, columns=FEATURE_NAMES)
