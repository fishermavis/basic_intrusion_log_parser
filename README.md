# 🛡️ Android Intrusion Log Analytics Engine

A lightweight, Python-based digital forensics and incident response (DFIR) utility designed to parse raw Android JSON logs, build dynamic or pre-compiled behavior baselines, and flag security anomalies in post-cutoff events.

---

## 🔑 Key Features

* **Dual-Phase Baseline Filtering**: Establish normal system behavior using historical log data or load a pre-compiled JSON baseline file (`-l`) to isolate strictly new, unseen activity.
* **Temporal Cutoff Processing (`-s`)**: Filter logs against a precise split timestamp (`YYYY-MM-DD HH:MM:SS`). Only events occurring strictly **after** the threshold are processed for alerts and exported.
* **Security Anomaly Detection**:
  * **Unrecognized Processes**: Flags newly executed app packages or system processes not present in the baseline.
  * **Unlisted Network Activity**: Identifies new outbound IP connections and DNS domain lookups.
  * **Physical Authentication Failures**: Decodes lock screen unlock attempts (Pin/Pattern/Password failures) and identifies device state context (`AFU` vs `BFU`).
  * **Signature Blacklist Scanner**: Compares running, installed, or uninstalled packages against a signature database (`blacklist.json`).
* **Flexible Export Capabilities**:
  * Clean, tabular CSV dumps of filtered network and execution events.
  * Dedicated incident alert spreadsheet (`security_alerts.csv`).
  * Structured human-readable summary text report (`security_summary.txt`).
  * Exportable baseline profile mappings in JSON format (`-b`).

---

## 🚀 Quick Start & Usage

### Basic Execution Syntax

```bash
python log_parser.py <input_directory> [OPTIONS]
```

### Options & Arguments

| Argument | Long Flag | Description |
| :--- | :--- | :--- |
| `input_directory` | N/A | Path to directory containing raw `.txt` log files. |
| `-o` | `--output` | Main exported CSV filename *(Default: `combined_network_report.csv`)*. |
| `-a` | `--alerts` | Security alert CSV filename *(Default: `security_alerts.csv`)*. |
| `-l` | `--load-baseline` | Path to an existing `baseline.json` file to evaluate logs against. |
| `-s` | `--split-time` | Cutoff timestamp (`YYYY-MM-DD HH:MM:SS`). Exports only post-cutoff data. |
| `-b` | `--baseline-export` | File path to export the newly compiled baseline to a JSON file. |

---

## 🛠️ Operational Workflows

### Workflow A: Single-Folder Dynamic Baseline Split

Parse a single directory of logs where entries **on or before** the split timestamp build the baseline profile, and entries **after** the timestamp are evaluated against it:

```bash
python log_parser.py /path/to/android_logs \
  -s "2026-06-18 14:30:00" \
  -o post_split_report.csv \
  -a security_alerts.csv
```

### Workflow B: Two-Step Decoupled Baseline Workflow

#### Step 1: Generate a Reusable Baseline from Known Safe Logs
Parse historical/safe log directory (`Folder_A`) and export the whitelist profile into a reusable JSON file:

```bash
python log_parser.py /path/to/folder_A_historical -b baseline_june18.json
```

#### Step 2: Review Target Logs Against the Saved Baseline
Parse target log directory (`Folder_B`) using the saved `baseline.json` file and filter events occurring after a given split time:

```bash
python log_parser.py /path/to/folder_B_target \
  -l baseline_june18.json \
  -s "2026-06-18 14:30:00" \
  -o post_split_report.csv \
  -a security_alerts.csv
```

> **Note:** When `-l` is used, **only new entities and activity not present in the baseline** will be exported to `post_split_report.csv` and tallied in `security_summary.txt`.

---

## 📋 Generated Output Artifacts

1. **Main CSV Report (`combined_network_report.csv`)**  
   Contains normalized, structured rows of post-split events that fall outside the baseline profile.
   
   *Headers:* `source_file`, `event_id`, `event_type`, `utc_time`, `package_or_process`, `hostname`, `ip_addresses`, `port`, `extra_details`

2. **Security Incident Alerts (`security_alerts.csv`)**  
   Itemized security alerts triggered by anomalies, authentication failures, or blacklisted apps.
   
   *Alert Types:* `UNRECOGNIZED_PROCESS`, `UNLISTED_DOMAIN_REQUEST`, `UNLISTED_IP_TRAFFIC`, `FAILED_AUTH_ATTEMPT`, `BLACKLISTED_APP_FOUND`

3. **Executive Analytics Summary (`security_summary.txt`)**  
   A structured text report containing unique entity counts, temporal scopes, critical findings, and frequency breakdowns for new domains, IPs, and processes.

---

## 📄 Configuration Files

### `blacklist.json` (Optional)
Place a `blacklist.json` file in the execution directory to scan for malicious, unwanted, or anti-forensic software:

```json
{
  "blacklisted_packages": [
    "com.malicious.spyware",
    "org.torproject.torbrowser",
    "com.topjohnwu.magisk"
  ]
}
```

---

## ⚙️ Requirements

* **Python**: 3.8+ (No third-party packages required; built using standard library modules).
