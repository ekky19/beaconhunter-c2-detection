# scorer.py
# Calculates enhanced anomaly scores for detected beaconing patterns

import pandas as pd
import math


def calculate_anomaly_scores(df: pd.DataFrame) -> pd.DataFrame:
    """
    Adds an 'anomaly_score' column to the DataFrame.

    Enhanced scoring:
    - For short intervals (< 5s), use a higher weight multiplier (15)
    - Otherwise, apply standard ceil formula
    """
    def score(row):
        base_score = row['mode_interval'] * row['percent_consistent'] / 100
        if row['mode_interval'] < 5:
            return math.ceil(base_score * 15)
        else:
            return math.ceil(base_score)

    df['anomaly_score'] = df.apply(score, axis=1)
    return df
