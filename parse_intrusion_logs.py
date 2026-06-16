import argparse
import csv
import json
import os
import sys
from datetime import datetime, timezone
import glob


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

        dt = datetime.fromtimestamp(seconds, tz=timezone.utc)
        return dt.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] + " UTC"
    except Exception:
        return "Invalid Timestamp"


def parse_directory_to_csv(input_dir, output_file):
    """Searches a directory for .txt log files, parses them row-by-row, and exports to CSV."""
    if not os.path.isdir(input_dir):
        print(f"Error: The directory '{input_dir}' does not exist.", file=sys.stderr)
        sys.exit(1)

    # Updated to specifically search for .txt files
    file_pattern = os.path.join(input_dir, "*.txt")
    files_to_process = glob.glob(file_pattern)

    if not files_to_process:
        print(f"Error: No .txt files found in '{input_dir}'.", file=sys.stderr)
        sys.exit(1)

    print(f"Found {len(files_to_process)} .txt log file(s) to process...")

    csv_headers = [
        "source_file",
        "event_id",
        "event_type",
        "utc_time",
        "package_or_process",
        "hostname",
        "ip_addresses",
        "port",
        "extra_details",
    ]

    total_row_count = 0

    try:
        with open(output_file, "w", newline="", encoding="utf-8") as outfile:
            writer = csv.DictWriter(outfile, fieldnames=csv_headers)
            writer.writeheader()

            for file_path in sorted(files_to_process):
                filename = os.path.basename(file_path)
                print(f" -> Processing: {filename}")
                
                with open(file_path, "r", encoding="utf-8") as infile:
                    for line_num, line in enumerate(infile, 1):
                        line = line.strip()
                        if not line:
                            continue

                        try:
                            data = json.loads(line)
                            if not data:
                                continue

                            # Extract event details dynamically
                            event_type = list(data.keys())[0]
                            event = data[event_type]

                            utc_time = decode_timestamp(event.get("event_time", ""))

                            row_data = {
                                "source_file": filename,
                                "event_id": event.get("event_id"),
                                "event_type": event_type,
                                "utc_time": utc_time,
                                "package_or_process": event.get("package_name", ""),
                                "hostname": "",
                                "ip_addresses": "",
                                "port": "",
                                "extra_details": "",
                            }

                            # --- Dynamic Parser Block ---
                            if event_type == "dns_event":
                                ips = [ip.lstrip("/") for ip in event.get("ip_addresses", [])]
                                row_data["hostname"] = event.get("hostname", "")
                                row_data["ip_addresses"] = ", ".join(ips)

                            elif event_type == "connect_event":
                                ip = event.get("ip_address", "").lstrip("/")
                                row_data["ip_addresses"] = ip
                                row_data["port"] = event.get("port", "")

                            elif event_type == "security_event":
                                details = {}
                                for key, value in event.items():
                                    if key not in ["event_id", "event_time"]:
                                        details[key] = value

                                for sub_key in ["app_process_start", "process_start"]:
                                    if sub_key in details and isinstance(details[sub_key], dict):
                                        row_data["package_or_process"] = details[sub_key].get("process", "")

                                row_data["extra_details"] = json.dumps(details)

                            else:
                                leftovers = {k: v for k, v in event.items() if k not in ["event_id", "event_time"]}
                                row_data["extra_details"] = json.dumps(leftovers)

                            writer.writerow(row_data)
                            total_row_count += 1

                        except json.JSONDecodeError:
                            print(f"    Warning: Skipping malformed JSON in {filename} on line {line_num}", file=sys.stderr)
                        except Exception as e:
                            print(f"    Warning: Error in {filename} on line {line_num}: {e}", file=sys.stderr)

            print(f"\nSuccess! Processed {total_row_count} total events and saved them to '{output_file}'.")

    except IOError as e:
        print(f"Error handling files: {e}", file=sys.stderr)
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="Batch convert a folder of Android .txt log files into a single unified CSV."
    )
    parser.add_argument(
        "input_directory",
        help="The path to the folder containing your .txt log files (e.g., ./logs_folder/)",
    )
    parser.add_argument(
        "-o",
        "--output",
        default="combined_network_report.csv",
        help="The path for the generated CSV file (default: combined_network_report.csv)",
    )

    args = parser.parse_args()
    parse_directory_to_csv(args.input_directory, args.output)


if __name__ == "__main__":
    main()