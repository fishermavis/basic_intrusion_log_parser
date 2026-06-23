
# Android Intrusion Log Parser & Security Inspection Engine

`parse_intrusion_logs.py` is a unified forensic utility designed to ingest raw Android intrusion logs, structurally normalize telemetry data, and run multi-tier behavioral analysis. It isolates device persistence mechanisms, maps network infrastructure dependencies, catches physical device state deviations, and highlights anomalous timeline spikes using automated, inline temporal baselining.

---

## 🚀 Why Use This Script? (The Intelligence Dividend)

If you are sorting through thousands of lines of raw JSON mobile logs, you are looking at white noise. This script converts that noise into an immediate, high-fidelity security posture narrative. By downloading and deploying this tool, you bypass hours of manual data pivoting:

* **Instant Contextualization:** It doesn’t just tell you *what* happened; it flags *when* it happened relative to your threshold constraints, dropping anomalous event spikes directly into your crosshairs.
* **Executive-Ready Report:** It auto-generates a highly polished `security_summary.txt` triage report designed to give investigators, team leads, or stakeholders a comprehensive, actionable situational overview in seconds.
* **Zero Infrastructure Overhead:** No heavy database setups, no SIEM configurations, and no complex third-party dependencies required. Drop your logs into a folder, run a single command, and let the localized engine do the heavy lifting.

---

## 🛠️ Key Capabilities

* **Dynamic Process Promotion:** Automatically digs inside complex nested data structures like `extra_details` to extract and normalize Android process executions, application package installations, and uninstallation behaviors.
* **Inline Temporal Baselining:** Evaluates a single mixed folder of logs by automatically parsing historical data before a specified cut-off date to construct an in-memory trusted inventory profile, then flags rogue telemetry appearing after that split mark.
* **Signature Blacklist Engine:** References a local signature library (`blacklist.json`) to track and contextually tag forbidden application states into specific priority categories (*Executed*, *Installed*, *Anti-Forensics / Uninstalled*).
* **Physical Device Integrity Monitoring:** Audits physical lock screen states and decrypts lockscreen keyguard validation attempts (`BFU` vs `AFU` device states) to uncover localized attack patterns.

---

## 🗂️ File Requirements

To utilize the baseline and signature analysis capabilities, ensure your working environment contains the following files:

### 1. `blacklist.json`
Your signature block file mapping prohibited packages. It must follow the exact structure below:

```json
{
  "blacklisted_packages": [
    "com.malicious.spyware"
  ]
}

```

---

## 🎯 Threat Hunting Workflows & Commands

### Workflow Scenario: Mixed Timeline Single-Folder Analysis

**Objective:** You have a single repository folder containing mixed chronological logs. You need to establish a baseline of normal trusted activity before 3:00 PM on June 16, 2026, and flag any fresh application installs, remote connections, or unexpected rogue processes that materialized after that window.

1. **Formulate your split constraint string:** Step 1.
Convert 3:00 PM into military 24-hour syntax format: `"2026-06-16 15:00:00"`.


2. **Run the Single-Pass Engine:** Step 2.
Point the ingestion module at your log directory (`logs/`) and supply your threshold split parameter via the terminal:

```bash
    python parse_intrusion_logs.py logs/ -s "2026-06-16 15:00:00"

```


---

## 📊 Operational Outputs & Artifacts

After execution terminates successfully, the script generates highly critical output files inside your directory:

### 1. 📋 `security_summary.txt` (What to Expect)

This is the crown jewel of the script's output—a clean, human-readable forensic intelligence manifest. When you open this file, you can immediately expect:

* **Temporal Scope Validation:** Instantly maps out the definitive, chronological absolute bounds (Earliest Log Entry vs Latest Log Entry) parsed from your source logs to establish historical timeline validity.
* **High-Priority Threat Matrix:** Direct exposure of blacklisted application activity categorized by exactly how it interacted with the file system (*Executed* vs *Installed* vs *Anti Forensics - Uninstalled*).
* **Physical Attack Vectors:** Decoded lockscreen validation tracking. It translates raw strength levels into concrete device operational contexts like BFU (Before First Unlock) or AFU (After First Unlock) to flag localized, physical handling attempts.
* **Frequency Leaderboards:** Top statistical telemetry standings mapping out your loudest Destination IPs, Requested Domains, and active app processes for quick outlier spotting.

```text
==================================================
        ANDROID INTRUSION LOG ANALYTICS          
        Generated on: 2026-06-23 12:03:59 UTC
==================================================

📅 [LOG ANALYSIS TEMPORAL SCOPE]
--------------------------------------------------
Earliest Log Entry : 2026-06-16 11:24:02 UTC
Latest Log Entry   : 2026-06-16 17:45:10 UTC
--------------------------------------------------

🔍 [SECURITY INSIGHTS] FORBIDDEN BLACKLISTED SOFTWARE DETECTED
--------------------------------------------------
CRITICAL: Found 3 instances of blacklisted software activity:

Timestamp                | Source Log File           | Line  | Blacklisted App Package             | Trigger Event
-------------------------------------------------------------------------------------------------------------------
2026-06-16 15:14:02.114  | device_log.txt            | 412   | com.malicious.spyware           | Blacklisted app executed
2026-06-16 15:30:11.892  | device_log.txt            | 485   | com.malicious.spyware           | Blacklisted app installed
2026-06-16 15:45:00.002  | device_log.txt            | 530   | com.malicious.spyware           | Anti Forensics - Blacklisted app uninstalled

🔒 [SECURITY INSIGHTS] PHYSICAL AUTHENTICATION FAILURES
--------------------------------------------------
Total Intrusive Unlock Failures Identified: 1

Timestamp                | Source Log File           | Line  | Decoded Attack Context
-------------------------------------------------------------------------------------------------------------------
2026-06-16 15:18:22.001  | device_log.txt            | 445   | Bad Pin - Phone state AFU
2026-06-16 15:49:00.002  | device_log.txt            | 600   | Bad Pin - Phone state BFU

📊 [1/3] DESTINATION IP ADDRESS FREQUENCY
--------------------------------------------------
8.8.8.8              | 142            
1.1.1.1              | 98             

```

### 2. 🛡️ `security_alerts.csv`

The core incident list sheet. Any anomaly found after the split threshold or matching a signature is isolated here for instant parsing or spreadsheet filtering. The generated spreadsheet maps out across the following schema structure:

| timestamp | source_file | line_number | event_id | alert_type | triggered_value | description |
| --- | --- | --- | --- | --- | --- | --- |
| `2026-06-16 15:14:02.114 UTC` | `device_log.txt` | `412` | `100482` | `BLACKLISTED_APP_FOUND` | `com.malicious.spyware` | Blacklisted app executed |
| `2026-06-16 15:30:11.892 UTC` | `device_log.txt` | `485` | `100490` | `BLACKLISTED_APP_FOUND` | `com.malicious.spyware` | Blacklisted app installed |
| `2026-06-16 15:45:00.002 UTC` | `device_log.txt` | `530` | `100502` | `BLACKLISTED_APP_FOUND` | `com.malicious.spyware` | Anti Forensics - Blacklisted app uninstalled |

```

```
