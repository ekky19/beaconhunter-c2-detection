# beaconhunter.py
# Main entry point for BeaconHunter tool

import os
import sys
from file_parser import load_csv_files
from detector import detect_beaconing, load_known_c2_ips
from scorer import calculate_anomaly_scores
from reporter import generate_reports
from c2_updater import update_c2_list

def main():
    if len(sys.argv) > 1 and sys.argv[1].lower() == "updatec2list":
        update_c2_list()
        return

    # Step 1: Load input data from all CSVs in the "CSVs" folder
    input_dir = "CSVs"
    output_dir = "OUTPUT"
    input_files = [os.path.join(input_dir, f) for f in os.listdir(input_dir) if f.endswith(".csv")]

    if not input_files:
        print("❌ No CSV files found in the 'CSVs' folder.")
        return

    all_data = load_csv_files(input_files)

    # Step 2: Load known C2 IPs from local list
    known_c2_ips = load_known_c2_ips()

    # Step 3: Detect beaconing and extract non-beaconing C2 hits
    beaconing_results, non_beaconing_c2 = detect_beaconing(all_data, known_c2_ips)

    # Step 4: Score results
    scored_results = calculate_anomaly_scores(beaconing_results)

    # Step 5: Generate reports and print summary
    generate_reports(scored_results, output_dir, non_beaconing_c2=non_beaconing_c2)


if __name__ == "__main__":
    main()
