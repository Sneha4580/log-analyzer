import re
import json
import argparse
import os
from datetime import datetime, timedelta

# -------------------------
# REGEX to match SSH failed login attempts
# Example line:
# Jan 10 12:03:11 ubuntu sshd[1204]: Failed password for invalid user admin from 185.220.101.4 port 44512 ssh2
# -------------------------
LOG_PATTERN = re.compile(
    r'(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2}).*Failed password.*from (?P<ip>\d+\.\d+\.\d+\.\d+)'
)

MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4,
    "May": 5, "Jun": 6, "Jul": 7, "Aug": 8,
    "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12
}

def classify_severity(count):
    if count >= 13:
        return "High"
    elif count >= 8:
        return "Medium"
    else:
        return "Low"


# -------------------------
# Convert log timestamps to datetime objects
# -------------------------
def parse_timestamp(month, day, time):
    year = datetime.now().year
    hour, minute, second = map(int, time.split(":"))
    return datetime(year, MONTHS[month], int(day), hour, minute, second)

# -------------------------
# Analyze the log file and detect brute-force patterns
# -------------------------
def analyze_log(log_file, threshold=5, window_seconds=60):
    brute_force_ips = {}

    # Read the log file line by line
    with open(log_file, "r", encoding="utf-8", errors="ignore") as file:
        for line in file:
            match = LOG_PATTERN.search(line)
            if match:
                data = match.groupdict()
                ip = data["ip"]
                timestamp = parse_timestamp(data["month"], data["day"], data["time"])

                if ip not in brute_force_ips:
                    brute_force_ips[ip] = []

                brute_force_ips[ip].append(timestamp)

    # Detect brute-force attacks within a time window
    suspicious_ips = {}

    for ip, times in brute_force_ips.items():
        times.sort()
        for i in range(len(times)):
            window_start = times[i]
            window_end = window_start + timedelta(seconds=window_seconds)
            # Count how many attempts happened in this window
            count = sum(1 for t in times if window_start <= t <= window_end)

            if count >= threshold:
                severity = classify_severity(count)

                suspicious_ips[ip] = {
                    "failed_attempts": count,
                    "severity": severity,
                    "window_start": window_start.strftime("%Y-%m-%d %H:%M:%S"),
                    "window_end": window_end.strftime("%Y-%m-%d %H:%M:%S"),
                    "suggestion": "High severity. Immediate action recommended." if severity == "High"
                                  else "Monitor and consider blocking the IP." if severity == "Medium"
                                  else "Low severity. Review and keep monitoring."
                }

                break  # No need to check further windows for this IP

    return suspicious_ips

# -------------------------
# Write output to report file
# -------------------------
def save_report(report_data, output_path="reports/report.json"):
    # Make sure the reports folder exists
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=4)
    print("[+] Report saved to", output_path)

# -------------------------
# Main function: parse arguments and run analysis
# -------------------------
def main():
    parser = argparse.ArgumentParser(description="SSH Brute-Force Attack Log Analyzer")
    parser.add_argument("--log", required=True, help="Path to auth.log file")
    parser.add_argument("--threshold", type=int, default=5, help="Failed attempts threshold")
    parser.add_argument("--window", type=int, default=60, help="Time window in seconds")
    args = parser.parse_args()

    print("[*] Analyzing log file:", args.log)
    result = analyze_log(args.log, args.threshold, args.window)
    save_report(result)

    if result:
        print("\nSuspicious IPs detected:")
        for ip, info in result.items():
            print(f"→ {ip}")
            print(f"   Attempts: {info['failed_attempts']}")
            print(f"   Severity: {info['severity']}")
            print(f"   Time Window: {info['window_start']} → {info['window_end']}")
            print(f"   Suggestion: {info['suggestion']}\n")
    else:
        print("\nNo brute-force attempts detected.")


# -------------------------
# Entry point
# -------------------------
if __name__ == "__main__":
    main()
