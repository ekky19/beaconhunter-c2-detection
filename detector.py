# detector.py
# Detects beaconing behavior across all destination IPs for each source IP

import pandas as pd
import numpy as np
from collections import Counter
from datetime import datetime


def load_known_c2_ips(path="known_c2_list.txt"):
    try:
        with open(path) as f:
            return set(line.strip() for line in f if line.strip())
    except FileNotFoundError:
        return set()


def detect_beaconing(df: pd.DataFrame, known_c2_ips=None):
    if known_c2_ips is None:
        known_c2_ips = set()

    results = []
    c2_only_connections = []

    for src, group in df.groupby("source_address"):
        group_sorted = group.sort_values("timestamp")
        time_diffs = group_sorted["timestamp"].diff().dropna().dt.total_seconds().tolist()

        if len(time_diffs) < 3:
            dests = sorted(group["destination_address"].dropna().unique())
            matched_c2s = [ip for ip in dests if ip in known_c2_ips]

            # Capture non-beaconing C2 traffic
            for ip in matched_c2s:
                timestamps = group_sorted[group_sorted['destination_address'] == ip]['timestamp'].tolist()
                c2_only_connections.append({
                    "source_address": src,
                    "destination_address": ip,
                    "timestamps": timestamps
                })

            results.append({
                "source_address": src,
                "total_events": len(group),
                "status": "NOT ENOUGH DATA",
                "destination_address": None,
                "asset": None,
                "user": None,
                "mode_interval": None,
                "percent_consistent": None,
                "anomaly_score": None,
                "start_time": None,
                "end_time": None,
                "is_known_c2": bool(matched_c2s),
                "matched_c2_ips": ", ".join(matched_c2s)
            })
            continue

        mode = Counter(time_diffs).most_common(1)[0][0]
        jittered = [i for i in time_diffs if abs(i - mode) <= 10]
        percent_consistent = (len(jittered) / len(time_diffs)) * 100

        dests = sorted(group["destination_address"].dropna().unique())
        matched_c2s = [ip for ip in dests if ip in known_c2_ips]

        first_row = group.iloc[0]
        asset_user = f"[{first_row['asset']},{first_row['user']}]"

        start_time = group_sorted["timestamp"].min()
        end_time = group_sorted["timestamp"].max()

        status = "BEACONING DETECTED" if percent_consistent >= 80 else "NOT DETECTED"
        anomaly_score = round(percent_consistent / mode, 2) if percent_consistent and mode else 0

        if status == "NOT DETECTED" and matched_c2s:
            for ip in matched_c2s:
                timestamps = group_sorted[group_sorted['destination_address'] == ip]['timestamp'].tolist()
                c2_only_connections.append({
                    "source_address": src,
                    "destination_address": ip,
                    "timestamps": timestamps
                })

        results.append({
            "source_address": src,
            "total_events": len(group),
            "status": status,
            "destination_address": ", ".join(dests),
            "asset": asset_user,
            "user": None,
            "mode_interval": round(mode, 2),
            "percent_consistent": round(percent_consistent, 1),
            "anomaly_score": anomaly_score,
            "start_time": start_time,
            "end_time": end_time,
            "is_known_c2": bool(matched_c2s),
            "matched_c2_ips": ", ".join(matched_c2s)
        })

    return pd.DataFrame(results), c2_only_connections
