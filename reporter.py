import pandas as pd
import json
import os
from datetime import datetime
from colorama import Fore, init
import ipaddress

init(autoreset=True)

def is_public_ip(ip):
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False

def make_osint_link(ip):
    return f"<a href='../OSINT.HTML?ip={ip}' target='_blank'>{ip}</a>"

def generate_reports(df: pd.DataFrame, output_dir: str, non_beaconing_c2: list = None):
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    df = df[df['status'] == 'BEACONING DETECTED'].copy()

    if df.empty:
        print(f"\n{Fore.CYAN}📊 Beaconing Detection Summary:")
        print(f"{Fore.YELLOW}⚠️  No beaconing detected or not enough data to determine patterns.")
        print(f"\n{Fore.CYAN}✅ Reports saved to: {os.path.abspath(output_dir)}")
        return

    df['Start Time'] = df['start_time']
    df['End Time'] = df['end_time']

    print(f"\n{Fore.CYAN}📊 Beaconing Detection Summary:")
    for _, row in df.iterrows():
        print(f"\n{Fore.GREEN}Source IP:        {row['source_address']}")
        print(f"Destination IPs:  {row['destination_address']}")
        print(f"Asset/User:       {row['asset']}")
        print(f"Interval:         {row['mode_interval']}s ({row['percent_consistent']}% consistent)")
        print(f"Anomaly Score:    {row['anomaly_score']}")
        if row.get("is_known_c2"):
            print(f"{Fore.RED}⚠️  Matches Known C2 IPs: {row.get('matched_c2_ips')}")
        print(f"Timeframe:        {row['Start Time']} to {row['End Time']}")

    df['Destination IPs'] = df['destination_address'].apply(
        lambda x: "<br>".join([
            make_osint_link(ip.strip()) if ip.strip() else "Unknown" for ip in x.split(', ')
        ])
    )

    if 'asset' in df.columns:
        df[['asset_clean', 'user_clean']] = df['asset'].str.extract(r'\[(.*?),(.*?)\]')
        df['Asset'] = df['asset_clean']
        df['User'] = df['user_clean']

    df['Source IP'] = df['source_address']
    df['Interval (s)'] = df['mode_interval']
    df['Consistency (%)'] = df['percent_consistent']
    df['Anomaly Score'] = df['anomaly_score']
    df['Total Events'] = df['total_events']
    df['C2 Match'] = df['matched_c2_ips'].apply(
        lambda val: "<br>".join([make_osint_link(ip.strip()) for ip in val.split(', ') if ip.strip()])
    )

    cols_order = ['Source IP', 'Destination IPs', 'Asset', 'User', 'Interval (s)',
                  'Consistency (%)', 'Anomaly Score', 'Start Time', 'End Time', 'Total Events', 'C2 Match']
    display_df = df[cols_order].copy()
    
    # Store original column names for tooltips
    original_cols = display_df.columns.tolist()

    # Convert for display (visual only)
    display_df.columns = [col.upper() for col in display_df.columns]

    
    tooltip_map = {
        "Source IP": "The internal IP that initiated the connection",
        "Destination IPs": "All external IPs contacted by the source",
        "Asset": "The asset name or hostname",
        "User": "The associated username",
        "Interval (s)": "Most common interval between connections",
        
        "Consistency (%)": "🔍 Consistency (%) measures how regularly a host communicates.\n\nIt’s based on how many connection intervals match the most common interval (±10s).\n\nExample:\nIf timestamps are:\n08:00:00, 08:01:00, 08:02:00, 08:03:00, 08:06:00\n\nIntervals = [60s, 60s, 60s, 180s]\nMode = 60s\nMatches within ±10s = 3 out of 4\n\n✅ Consistency = (3/4) × 100 = 75%",

        
        "Anomaly Score": "Anomaly Score reflects how suspiciously regular the beaconing pattern is.\n\nIt’s calculated as:\nAnomaly Score = Consistency (%) / Interval (s)\n\nExample:\nIf a source sends packets every 60 seconds, with 90% consistency:\nAnomaly Score = 90 / 60 = 1.5\n\n🔎 Higher score = more suspicious (frequent and highly consistent communication).",

        
        "Start Time": "Time of first connection",
        "End Time": "Time of last connection",
        "Total Events": "Total number of observed connections",
        "C2 Match": "Known C2 IPs from threat feeds"
    }

    html_table = "<table class='styled'><thead><tr>" + \
    "".join([f"<th title='{tooltip_map.get(orig, '')}'>{col}</th>" for orig, col in zip(original_cols, display_df.columns)]) + \
    "</tr></thead><tbody>" + \
    display_df.to_html(index=False, escape=False, header=False).split("<tbody>")[1]


    json_path = os.path.join(output_dir, f"beaconing_report_{timestamp}.json")
    display_df.to_json(json_path, orient="records", indent=2)

    # Known C2 IPs contacted without beaconing
    non_beaconing_html = ""
    if non_beaconing_c2:
        known_summary = {}
        for entry in non_beaconing_c2:
            src = entry.get("source_address", "Unknown")
            dst = entry.get("destination_address", "Unknown")
            ts_list = entry.get("timestamps", [])
            first_ts = ts_list[0] if ts_list else "Unknown"
            known_summary[(src, dst)] = first_ts

        print(f"\n{Fore.YELLOW}⚠️  Known C2 IPs contacted without beaconing:")
        print(f"{'SOURCE':<20}{'DESTINATION':<20}{'FIRST CONNECTION'}")
        print("-" * 65)
        for (src, dst), first_ts in known_summary.items():
            print(f"{src:<20}{dst:<20}{first_ts}")

        rows = "\n".join([
            f"<tr><td>{src}</td><td>{make_osint_link(dst)}</td><td>{first_ts}</td></tr>"
            for (src, dst), first_ts in known_summary.items()
        ])
        non_beaconing_html = f"""
        <h3 style='color:#d32f2f;text-align:center;margin-top:40px;'>⚠️ Known C2 IPs Contacted Without Beaconing</h3>
        <table class='styled'>
            <thead>
                <tr><th>SOURCE</th><th>DESTINATION</th><th>FIRST CONNECTION</th></tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
        """

    html_path = os.path.join(output_dir, f"beaconing_report_{timestamp}.html")

    full_html = f"""
    <html>
    <head>
        <style>
            body {{
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background-color: #f0f2f5;
                color: #333;
                padding: 30px;
            }}
            h2 {{
                text-align: center;
                color: #1a237e;
            }}
            .styled {{
                width: 95%;
                margin: 20px auto;
                border-collapse: collapse;
                box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            }}
            .styled th {{
                background-color: #3f51b5;
                color: white;
                padding: 10px;
                font-size: 14px;
                text-align: center;
            }}
            .styled td {{
                padding: 10px;
                border: 1px solid #ccc;
                font-size: 13px;
                background-color: #fff;
                text-align: center;
            }}
            .styled tr:nth-child(even) td {{
                background-color: #f9f9f9;
            }}
            a {{
                color: #0073e6;
                text-decoration: none;
            }}
            a:hover {{
                text-decoration: underline;
            }}
        </style>
    </head>
    <body>
        <h2>Beaconing Detection Report - {timestamp}</h2>
        {html_table}
        {non_beaconing_html}
    </body>
    </html>
    """
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(full_html)

    print(f"\n{Fore.CYAN}✅ Reports saved to: {os.path.abspath(output_dir)}")
