# c2_updater.py
# Downloads latest known C2 IPs from ThreatFox and saves to local file

import requests
import zipfile
import io
import json

def update_c2_list(output_path="known_c2_list.txt"):
    print("🔄 Downloading ThreatFox ZIP archive...")
    url = "https://threatfox.abuse.ch/export/json/full/"

    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()

        zip_content = zipfile.ZipFile(io.BytesIO(response.content))
        json_file = next((f for f in zip_content.namelist() if f.endswith(".json")), None)

        if not json_file:
            print("❌ No JSON file found in ZIP.")
            return

        data = json.loads(zip_content.read(json_file))
        c2_ips = set()

        for entries in data.values():
            for item in entries:
                if item["ioc_type"] in ("ip", "ip:port"):
                    ip = item["ioc_value"].split(":")[0]
                    c2_ips.add(ip)

        with open(output_path, "w") as f:
            for ip in sorted(c2_ips):
                f.write(f"{ip}\n")

        print(f"✅ C2 list updated with {len(c2_ips)} IPs.")
    except Exception as e:
        print(f"❌ Failed to update C2 list: {e}")
