# scorer.py
# Calculates anomaly scores for detected beaconing patterns

import pandas as pd

def calculate_anomaly_scores(df: pd.DataFrame) -> pd.DataFrame:
    """
    Adds an 'anomaly_score' column to the DataFrame.

    Anomaly Score = Consistency (%) / Interval (s)
    - Higher scores indicate more suspicious (frequent + consistent) communication.
    """
    def score(row):
        interval = row.get('mode_interval', 0)
        consistency = row.get('percent_consistent', 0)
        if interval > 0:
            return round(consistency / interval, 2)
        else:
            return 0

    df['anomaly_score'] = df.apply(score, axis=1)
    return df
