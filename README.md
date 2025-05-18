# 🛰️ BeaconHunter
**BeaconHunter** is an advanced offline Python tool designed to detect beaconing Command and Control (C2) traffic from network logs. It flags suspicious communication patterns such as consistent intervals and known malicious IPs, and generates a beautiful, interactive HTML report for threat analysis.

---

## 📅 Example Usage

```bash
python beaconhunter.py
```

* Scans all CSVs in the `CSVs/` folder
* Generates detailed and modernized reports
---

![image](https://github.com/user-attachments/assets/2e184ec1-294e-4d2e-bf7b-ebe5b13cdf21)

![image](https://github.com/user-attachments/assets/1bf6e382-b4cf-407c-9e73-7ef76eba7bd3)

![image](https://github.com/user-attachments/assets/c82e3712-6509-4719-996f-715d3dc229c4)

---

## 🚀 Purpose

To analyze firewall logs or CSV-based network data and identify whether certain source-destination IP pairs are **beaconing** — i.e., communicating at consistent time intervals that may indicate C2 (Command & Control) traffic.

---

## 🧐 Common Use Case

You're a SOC analyst reviewing outbound connections from internal assets. You want to quickly identify:

* ✅ Highly regular intervals suggesting beaconing
* ⚠️ Traffic to known C2 IPs (from abuse.ch)
* 🔍 Users/assets involved in suspicious traffic
* 🛁 Destinations that may warrant deeper OSINT pivoting

---

## 📁 CSV Input Format

CSV files should be placed inside the `CSVs/` directory.

### ✅ Format (7 Columns)

| timestamp           | source\_address | source\_port | destination\_address | destination\_port | asset  | user  |
| ------------------- | --------------- | ------------ | -------------------- | ----------------- | ------ | ----- |
| 2025-05-08T08:00:00 | 192.168.1.10    | 12345        | 8.8.8.8              | 443               | PC-001 | alice |

---

## ⚙️ Script Features

* ✅ **Automatic Jitter Detection** (±10s tolerance)
* ✅ **Multi-IP Grouping** (per source)
* ✅ **Anomaly Scoring** (interval/consistency based)
* ✅ **Known C2 Feed Integration** (from [abuse.ch](https://threatfox.abuse.ch))
* ✅ **JSON + Modern HTML Reporting**
* ✅ **Clickable OSINT Pivot Links**
* ✅ **Non-Beaconing C2 Traffic Reporting**

---

## 🗃️ Reports

After running, you’ll find:

* 📄 `OUTPUT/beaconing_report_<timestamp>.html`
* 📄 `OUTPUT/beaconing_report_<timestamp>.json`

### Terminal Output:

* Beaconing Summary per Source IP
* Known C2 Contact Alerts (even if no beaconing)

### HTML Report:

* Modern, styled table of beaconing activity
* Separate section for “Known C2 IPs Contacted Without Beaconing”
* Clickable C2 IPs → open `OSINT.HTML` with prefilled query

---

## 🔗 OSINT Integration

When you click on any C2 IP in the HTML report, the `OSINT.HTML` tool will:

* Autofill the IP into the search bar
* Auto-click the “ADD” button
* Populate over 60+ OSINT services for pivoting

> ✅ No API keys required — all lookups are via public web links

---

## 🔄 Updating Known C2 List

Run this command to fetch the latest malicious IP indicators:

```bash
python beaconhunter.py updatec2list
```

This will:

* Download ThreatFox feed from `abuse.ch`
* Extract valid ip C2 IOCs
* Save to local `known_c2_list.txt`

---

## 💡 Detection Logic

* **Mode**: Most frequent interval between events
* **Jitter Tolerance**: ±10 seconds
* **Beaconing Threshold**: ≥80% of intervals match mode

---

## 🔍 Anomaly Scoring

### 📈 What is Anomaly Score?

The **Anomaly Score** is a custom metric designed to represent how “beacon-like” a communication pattern is — combining **consistency** and **interval timing** into a single value.

#### 💡 Formula:

```plaintext
Anomaly Score = (Consistency % / Mode Interval)
```

* **Consistency %**: Percentage of intervals that match the most common timing (within ±10s jitter).
* **Mode Interval**: The most frequently observed time gap (in seconds) between connections.

#### 🧪 Example:

| Intervals (seconds) | \[60, 60, 59, 60, 61] |
| ------------------- | --------------------- |
| Mode Interval       | 60                    |
| Consistency         | 100%                  |
| Anomaly Score       | 100 / 60 = **1.66**   |



### 🔍 How to interpret:

* **Higher = more suspicious** (tight, regular patterns)
* **Lower = less likely to be beaconing**
* Scores above `1.0` often indicate **highly consistent, frequent communication** — common in malware beacons

---

## 📌 Classification Tags

* `✅ BEACONING DETECTED`
* `⚠️ NOT ENOUGH DATA` (fewer than 4 timestamps)
* `❌ NOT DETECTED`

---

## ❓ FAQ

**Q:** Can beaconing happen at random times?
**A:** No — beaconing implies regular intervals. Jitter is allowed to a point.

**Q:** How are “non-beaconing but known C2 contacts” handled?
**A:** They are logged in a separate section if the source contacted a known C2 IP but didn’t meet the beaconing threshold.

---
### Key Differences
Here’s a breakdown of the key differences between the Python-based BeaconHunter and the previous PowerShell version I built:

## 1. Detection Capabilities
   
| Feature                                | PowerShell Version        | Python Version (Current)       |
| -------------------------------------- | ------------------------  | ------------------------------ |
| Basic interval-based beacon detection  | ✅                        | ✅                              |
| Automatic jitter tolerance             | ✅                        | ✅ (±10s variation built-in)    |
| Multi-destination grouping             | ❌ (single dst per cycle) | ✅                              |
| Known C2 match logic                   | ❌                        | ✅ Uses ThreatFox JSON feeds    |
| Non-beaconing but known C2 connections | ❌                        | ✅                              |
| Anomaly scoring                        | ❌                        | ✅ Interval & consistency based |
| Timeline analysis                      | Basic                     | ✅ More detailed + timestamps   |

## 2. Usability & Output

| Feature                          | PowerShell Version  | Python Version (Current)            |
| -------------------------------- | ------------------  | ----------------------------------- |
| JSON / HTML reporting            | ❌                  | ✅ Beautiful & interactive           |
| Clickable VirusTotal/OSINT links | ❌                  | ✅ Integrated via HTML               |
| Terminal summary                 | ✅                  | ✅ Enhanced with color and C2 alerts |
| Filtering & structured view      | ❌                  | ✅ Column-based & sortable           |
| C2 enrichment auto-updater       | ❌                  | ✅ `beaconhunter.py updatec2list`    |

## 3. Flexibility & Extensibility
   
| Feature                               | PowerShell Version | Python Version                 |
| ------------------------------------- | ------------------ | ------------------------------ |
| Modular design (separate files)       | ❌ (single script)  | ✅ (detector, scorer, reporter) |
| Easy to expand with threat feeds      | ❌                  | ✅                              |
| GUI potential / future integration    | Limited            | ✅ Tkinter, PyQt options        |
| Multi-file batch support (CSV folder) | ❌                  | ✅                            |


## Summary
|                      | PowerShell BeaconHunter | Python BeaconHunter               |
| -------------------- | ----------------------- | --------------------------------- |
| Good for quick scans | ✅                       | ✅                                 |
| Threat intelligence  | ❌                       | ✅ Integrated with abuse.ch        |
| Reporting & UI       | ❌ Basic logs            | ✅ HTML + OSINT integration |
| Maintainability      | Harder to extend        | Modular and scalable              |

