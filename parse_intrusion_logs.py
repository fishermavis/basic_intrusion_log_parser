import argparse
import csv
import json
import os
import sys
from datetime import datetime, timezone
import glob
from collections import Counter


def decode_timestamp(epoch):
    """Safely handles both millisecond (13-digit) and nanosecond (19-digit) epochs."""
    try:
        epoch_str = str(epoch)
        if len(epoch_str) >= 19:  # Nanoseconds
            seconds = epoch / 1_000_000_000.0
        elif len(epoch_str) >= 13:  # Milliseconds
            seconds = epoch / 1000.0
        else:  # Standard seconds
            seconds = epoch

        return datetime.fromtimestamp(seconds, tz=timezone.utc)
    except Exception:
        return None


def parse_split_time(time_str):
    """Parses a user-stipulated split time string into a UTC datetime object."""
    if not time_str:
        return None
    formats = [
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%d"
    ]
    for fmt in formats:
        try:
            dt = datetime.strptime(time_str.strip(), fmt)
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    
    print(f"Error: Could not parse split time '{time_str}'. Use format 'YYYY-MM-DD HH:MM:SS'.", file=sys.stderr)
    sys.exit(1)


def load_blacklist(blacklist_path):
    """Loads malicious or forbidden app package identifiers from a JSON config file."""
    if not blacklist_path:
        return None
    if not os.path.isfile(blacklist_path):
        print(f"Note: Optional '{blacklist_path}' not found. Skipping signature checking.")
        return None
    try:
        with open(blacklist_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            blacklist_set = set(data.get("blacklisted_packages", [])) if isinstance(data, dict) else set(data)
            print(f"Loaded blacklist database from '{blacklist_path}' ({len(blacklist_set)} rules active).")
            return blacklist_set
    except Exception as e:
        print(f"Error loading blacklist: {e}. Proceeding without signature checking.", file=sys.stderr)
        return None


def parse_directory_to_csv(input_dir, output_file, baseline_file=None, split_time_str=None, blacklist_path="blacklist.json", alert_file="security_alerts.csv"):
    """Parses logs, building an inline baseline from early data and checking late data against it."""
    if not os.path.isdir(input_dir):
        print(f"Error: The directory '{input_dir}' does not exist.", file=sys.stderr)
        sys.exit(1)

    files_to_process = glob.glob(os.path.join(input_dir, "*.txt"))
    if not files_to_process:
        print(f"Error: No .txt files found in '{input_dir}'.", file=sys.stderr)
        sys.exit(1)

    split_threshold = parse_split_time(split_time_str)
    blacklist = load_blacklist(blacklist_path)

    # Dynamic inline baseline storage
    inline_whitelist = {"ips": set(), "domains": set(), "packages": set()}

    csv_headers = ["source_file", "event_id", "event_type", "utc_time", "package_or_process", "hostname", "ip_addresses", "port", "extra_details"]
    alert_headers = ["timestamp", "source_file", "line_number", "event_id", "alert_type", "triggered_value", "description"]

    total_row_count = 0
    ip_counter, domain_counter, process_counter = Counter(), Counter(), Counter()
    
    failed_auth_summary = []
    blacklist_matches_summary = []
    flagged_ips, flagged_domains, flagged_packages = set(), set(), set()

    earliest_time = None
    latest_time = None

    # PASS 1: Build baseline from older entries if an inline split date is requested
    if split_threshold:
        print(f" -> Phase 1: Building baseline from events on or before {split_time_str} UTC...")
        for file_path in sorted(files_to_process):
            with open(file_path, "r", encoding="utf-8") as infile:
                for line in infile:
                    line = line.strip()
                    if not line: continue
                    try:
                        data = json.loads(line)
                        event_type = list(data.keys())[0]
                        event = data[event_type]
                        dt_object = decode_timestamp(event.get("event_time", ""))
                        
                        # Only look at historical items for our baseline profile loop
                        if dt_object and dt_object <= split_threshold:
                            # Package extraction
                            pkg = event.get("package_name", event.get("process", ""))
                            if not pkg and "app_process_start" in event:
                                pkg = event["app_process_start"].get("process", "")
                            if pkg: inline_whitelist["packages"].add(pkg)
                            
                            # Network extraction
                            if event_type == "dns_event":
                                inline_whitelist["domains"].add(event.get("hostname", "").strip())
                                for ip in event.get("ip_addresses", []):
                                    inline_whitelist["ips"].add(ip.lstrip("/"))
                            elif event_type == "connect_event":
                                ip = event.get("ip_address", "").lstrip("/")
                                if ip: inline_whitelist["ips"].add(ip)
                    except Exception:
                        continue
        print(f" -> Baseline compiled: {len(inline_whitelist['packages'])} packages, {len(inline_whitelist['domains'])} domains, {len(inline_whitelist['ips'])} IPs indexed.")

    # PASS 2: Export Data & Alert on entries after the split line
    try:
        with open(output_file, "w", newline="", encoding="utf-8") as outfile, \
             open(alert_file, "w", newline="", encoding="utf-8") as alertfile:
             
            writer = csv.DictWriter(outfile, fieldnames=csv_headers)
            writer.writeheader()
            
            alert_writer = csv.DictWriter(alertfile, fieldnames=alert_headers)
            alert_writer.writeheader()

            print(" -> Phase 2: Processing and screening entire log table...")
            for file_path in sorted(files_to_process):
                filename = os.path.basename(file_path)
                
                with open(file_path, "r", encoding="utf-8") as infile:
                    for line_num, line in enumerate(infile, 1):
                        line = line.strip()
                        if not line: continue

                        try:
                            data = json.loads(line)
                            event_type = list(data.keys())[0]
                            event = data[event_type]

                            dt_object = decode_timestamp(event.get("event_time", ""))
                            
                            if dt_object:
                                if earliest_time is None or dt_object < earliest_time:
                                    earliest_time = dt_object
                                if latest_time is None or dt_object > latest_time:
                                    latest_time = dt_object

                            display_time = dt_object.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] + " UTC" if dt_object else "Invalid Timestamp"
                            row_id = event.get("event_id", "0")

                            row_data = {
                                "source_file": filename,
                                "event_id": row_id,
                                "event_type": event_type,
                                "utc_time": display_time,
                                "package_or_process": event.get("package_name", event.get("process", "")),
                                "hostname": "",
                                "ip_addresses": "",
                                "port": "",
                                "extra_details": "",
                            }

                            current_line_ips = []
                            current_line_domain = ""

                            if event_type == "dns_event":
                                current_line_ips = [ip.lstrip("/") for ip in event.get("ip_addresses", [])]
                                current_line_domain = event.get("hostname", "").strip()
                                row_data["hostname"] = current_line_domain
                                row_data["ip_addresses"] = ", ".join(current_line_ips)

                            elif event_type == "connect_event":
                                ip = event.get("ip_address", "").lstrip("/")
                                row_data["ip_addresses"] = ip
                                row_data["port"] = event.get("port", "")
                                if ip: current_line_ips = [ip]

                            details = {k: v for k, v in event.items() if k not in ["event_id", "event_time"]}
                            row_data["extra_details"] = json.dumps(details)

                            # UNIVERSAL PROCESS EXTRACTION
                            if not row_data["package_or_process"]:
                                for sub_key in ["app_process_start", "process_start"]:
                                    if sub_key in details and isinstance(details[sub_key], dict):
                                        row_data["package_or_process"] = details[sub_key].get("process", "")
                                for sub_key in ["package_installed", "package_uninstalled"]:
                                    if sub_key in details and isinstance(details[sub_key], dict):
                                        row_data["package_or_process"] = details[sub_key].get("package_name", "")
                                
                                if event_type in ["app_process_start", "process_start"]:
                                    row_data["package_or_process"] = event.get("process", "")
                                elif event_type in ["package_installed", "package_uninstalled"]:
                                    row_data["package_or_process"] = event.get("package_name", "")

                            # Auth State Inspection
                            if "keyguard_dismiss_auth_attempt" in details:
                                auth_info = details["keyguard_dismiss_auth_attempt"]
                                if auth_info.get("success") is False:
                                    strength = auth_info.get("method_strength")
                                    decoded_state = "Bad Pin - Phone state AFU" if strength == 0 else ("Bad Pin - Phone state BFU" if strength == 1 else f"Bad Pin - Context unknown ({strength})")
                                    failed_auth_summary.append({"time": display_time, "file": filename, "line": line_num, "state": decoded_state})
                                    alert_writer.writerow({
                                        "timestamp": display_time, "source_file": filename, "line_number": line_num, "event_id": row_id,
                                        "alert_type": "FAILED_AUTH_ATTEMPT", "triggered_value": f"strength_{strength}", "description": decoded_state
                                    })

                            # UNIVERSAL SIGNATURE-BASED BLACKLIST SCANNER
                            if blacklist:
                                extracted_apps = set()
                                if row_data["package_or_process"]: extracted_apps.add(row_data["package_or_process"])
                                if event.get("package_name"): extracted_apps.add(event.get("package_name"))
                                if event.get("process"): extracted_apps.add(event.get("process"))
                                
                                for sub_key, sub_val in details.items():
                                    if isinstance(sub_val, dict):
                                        for key_name in ["package_name", "process", "app_id"]:
                                            if key_name in sub_val and isinstance(sub_val[key_name], str):
                                                extracted_apps.add(sub_val[key_name])

                                matches = extracted_apps.intersection(blacklist)
                                if matches:
                                    desc_text = "Blacklisted software activity detected"
                                    if event_type == "package_installed" or "package_installed" in details:
                                        desc_text = "Blacklisted app installed"
                                    elif event_type in ["app_process_start", "process_start"] or "app_process_start" in details or "process_start" in details:
                                        desc_text = "Blacklisted app executed"
                                    elif event_type == "package_uninstalled" or "package_uninstalled" in details:
                                        desc_text = "Anti Forensics - Blacklisted app uninstalled"

                                    for blacklisted_app in matches:
                                        blacklist_matches_summary.append({
                                            "time": display_time, "file": filename, "line": line_num, "package": blacklisted_app, "event": desc_text
                                        })
                                        alert_writer.writerow({
                                            "timestamp": display_time, "source_file": filename, "line_number": line_num, "event_id": row_id,
                                            "alert_type": "BLACKLISTED_APP_FOUND", "triggered_value": blacklisted_app, "description": desc_text
                                        })

                            # Statistical Aggregations
                            pkg_proc = row_data["package_or_process"]
                            if pkg_proc: process_counter[pkg_proc] += 1
                            if current_line_domain: domain_counter[current_line_domain] += 1
                            for ip in current_line_ips:
                                if ip: ip_counter[ip] += 1

                            # --- WHITELIST EVALUATION (Only fires on elements AFTER split time threshold) ---
                            if split_threshold and dt_object and dt_object > split_threshold:
                                if pkg_proc and pkg_proc not in inline_whitelist["packages"] and pkg_proc not in flagged_packages:
                                    alert_writer.writerow({
                                        "timestamp": display_time, "source_file": filename, "line_number": line_num, "event_id": row_id,
                                        "alert_type": "UNRECOGNIZED_PROCESS", "triggered_value": pkg_proc, "description": "New process execution context discovered after baseline date split threshold."
                                    })
                                    flagged_packages.add(pkg_proc)
                                
                                if current_line_domain and current_line_domain not in inline_whitelist["domains"] and current_line_domain not in flagged_domains:
                                    alert_writer.writerow({
                                        "timestamp": display_time, "source_file": filename, "line_number": line_num, "event_id": row_id,
                                        "alert_type": "UNLISTED_DOMAIN_REQUEST", "triggered_value": current_line_domain, "description": f"New domain request outside baseline via process '{pkg_proc}'."
                                    })
                                    flagged_domains.add(current_line_domain)

                                for ip in current_line_ips:
                                    if ip and ip not in inline_whitelist["ips"] and ip not in flagged_ips:
                                        alert_writer.writerow({
                                            "timestamp": display_time, "source_file": filename, "line_number": line_num, "event_id": row_id,
                                            "alert_type": "UNLISTED_IP_TRAFFIC", "triggered_value": ip, "description": f"New outbound IP destination targeted via process '{pkg_proc}'."
                                        })
                                        flagged_ips.add(ip)

                            writer.writerow(row_data)
                            total_row_count += 1

                        except Exception as e:
                            print(f"    Warning: Skipping row abnormality in {filename} on line {line_num}: {e}", file=sys.stderr)

            range_start = earliest_time.strftime("%Y-%m-%d %H:%M:%S UTC") if earliest_time else "N/A"
            range_end = latest_time.strftime("%Y-%m-%d %H:%M:%S UTC") if latest_time else "N/A"

            print(f"\nSuccess! Table export complete ({total_row_count} total events mapped inside '{output_file}').")
            print(f"Master incident sheet exported safely to: '{alert_file}'")
            
            generate_summary_report(output_file, ip_counter, domain_counter, process_counter, failed_auth_summary, blacklist_matches_summary, range_start, range_end)

            # Export compile profile mapping file if explicitly requested by parameter -b
            if baseline_file:
                export_baseline_json(baseline_file, ip_counter, domain_counter, process_counter)

    except IOError as e:
        print(f"Error handling file I/O operations: {e}", file=sys.stderr)
        sys.exit(1)


def generate_summary_report(master_csv_path, ip_counts, domain_counts, process_counts, failed_auths, blacklist_matches, range_start, range_end):
    """Compiles metrics frequencies and highlights structural security insights inside text summary file."""
    base_dir = os.path.dirname(master_csv_path)
    summary_path = os.path.join(base_dir, "security_summary.txt") if base_dir else "security_summary.txt"

    with open(summary_path, "w", encoding="utf-8") as report:
        report.write("==================================================\n")
        report.write("        ANDROID INTRUSION LOG ANALYTICS          \n")
        report.write(f"        Generated on: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}\n")
        report.write("==================================================\n\n")

        report.write("📅 [LOG ANALYSIS TEMPORAL SCOPE]\n")
        report.write("--------------------------------------------------\n")
        report.write(f"Earliest Log Entry : {range_start}\n")
        report.write(f"Latest Log Entry   : {range_end}\n")
        report.write("--------------------------------------------------\n\n")

        report.write("🔍 [SECURITY INSIGHTS] FORBIDDEN BLACKLISTED SOFTWARE DETECTED\n")
        report.write("--------------------------------------------------\n")
        if not blacklist_matches:
            report.write("No blacklisted or forbidden software indicators discovered.\n\n")
        else:
            report.write(f"CRITICAL: Found {len(blacklist_matches)} instances of blacklisted software activity:\n\n")
            report.write(f"{'Timestamp':<24} | {'Source Log File':<25} | {'Line':<5} | {'Blacklisted App Package':<35} | {'Trigger Event'}\n")
            report.write("-" * 115 + "\n")
            for match in blacklist_matches:
                report.write(f"{match['time']:<24} | {match['file']:<25} | {match['line']:<5} | {match['package']:<35} | {match['event']}\n")
            report.write("\n")
        report.write("\n")

        report.write("🔒 [SECURITY INSIGHTS] PHYSICAL AUTHENTICATION FAILURES\n")
        report.write("--------------------------------------------------\n")
        if not failed_auths:
            report.write("No lock screen credential entry failures identified.\n\n")
        else:
            report.write(f"Total Intrusive Unlock Failures Identified: {len(failed_auths)}\n\n")
            report.write(f"{'Timestamp':<24} | {'Source Log File':<25} | {'Line':<5} | {'Decoded Attack Context'}\n")
            report.write("-" * 95 + "\n")
            for incident in failed_auths:
                report.write(f"{incident['time']:<24} | {incident['file']:<25} | {incident['line']:<5} | {incident['state']}\n")
            report.write("\n")
        report.write("\n")

        report.write("📊 [1/3] DESTINATION IP ADDRESS FREQUENCY\n")
        report.write("--------------------------------------------------\n")
        for ip, count in ip_counts.most_common():
            report.write(f"{ip:<20} | {count:<15}\n")
        report.write("\n\n")

        report.write("🌐 [2/3] REQUESTED DOMAIN FREQUENCY\n")
        report.write("--------------------------------------------------\n")
        for domain, count in domain_counts.most_common():
            report.write(f"{domain:<50} | {count:<15}\n")
        report.write("\n\n")

        report.write("📦 [3/3] PACKAGE / PROCESS ACTIVITY FREQUENCY\n")
        report.write("--------------------------------------------------\n")
        for proc, count in process_counts.most_common():
            report.write(f"{proc:<50} | {count:<15}\n")


def export_baseline_json(baseline_file, ip_counts, domain_counts, process_counts):
    """Exports structured telemetry snapshots for reusable whitelist mappings."""
    baseline_data = {
        "metadata": {"created_at": datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC'), "total_unique_ips": len(ip_counts), "total_unique_domains": len(domain_counts), "total_unique_packages": len(process_counts)},
        "known_ips": sorted(list(ip_counts.keys())), "known_domains": sorted(list(domain_counts.keys())), "known_packages": sorted(list(process_counts.keys()))
    }
    with open(baseline_file, "w", encoding="utf-8") as f:
        json.dump(baseline_data, f, indent=4)


def main():
    parser = argparse.ArgumentParser(description="Unified Android Intrusion Log Parser and Security Inspection Engine.")
    parser.add_argument("input_directory", help="The path to the folder containing your .txt log files")
    parser.add_argument("-o", "--output", default="combined_network_report.csv", help="The path for the generated main CSV dump")
    parser.add_argument("-a", "--alerts", default="security_alerts.csv", help="The path for the generated security alerts CSV sheet")
    parser.add_argument("-b", "--baseline", default=None, help="Export the cumulative parsed session profile baseline out to a external JSON file mapping")
    
    # New argument to split the baseline dynamically on an arbitrary timeline index
    parser.add_argument("-s", "--split-time", default=None, help="Split data inline. Entries before this date become the baseline; entries after are whitelisted against it. Format: 'YYYY-MM-DD HH:MM:SS'")

    args = parser.parse_args()
    
    parse_directory_to_csv(
        input_dir=args.input_directory, 
        output_file=args.output, 
        baseline_file=args.baseline, 
        split_time_str=args.split_time, 
        blacklist_path="blacklist.json", 
        alert_file=args.alerts
    )


if __name__ == "__main__":
    main()
