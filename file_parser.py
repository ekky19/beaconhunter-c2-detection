# file_parser.py
# Loads and cleans input CSV files for BeaconHunter

import pandas as pd
import os

def load_csv_files(file_list, specific_ip=None):
    all_rows = []

    for file in file_list:
        if not os.path.exists(file):
            print(f"File not found: {file}")
            continue

        try:
            df = pd.read_csv(file)

            # Try to detect and standardize a timestamp column
            possible_ts_cols = [col for col in df.columns if 'time' in col.lower()]
            if possible_ts_cols:
                df.rename(columns={possible_ts_cols[0]: 'timestamp'}, inplace=True)

            if 'timestamp' in df.columns:
                df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
                df['timestamp'] = df['timestamp'].dt.tz_localize(None)  # Normalize timestamps

            # Clean up and standardize all column names
            df.columns = [col.strip().lower().replace(' ', '_') for col in df.columns]
            all_rows.append(df)

        except Exception as e:
            print(f"Error reading {file}: {e}")

    if not all_rows:
        raise ValueError("No valid data found in input files.")

    full_df = pd.concat(all_rows, ignore_index=True)

    if specific_ip:
        full_df = full_df[full_df['source_address'] == specific_ip]

    return full_df
