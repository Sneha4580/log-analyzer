import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
import json
import re
from datetime import datetime, timedelta

# -------------------------
# Regex and month mapping
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

def parse_timestamp(month, day, time):
    year = datetime.now().year
    hour, minute, second = map(int, time.split(":"))
    return datetime(year, MONTHS[month], int(day), hour, minute, second)

def analyze_log(log_file, threshold=5, window_seconds=60):
    brute_force_ips = {}

    with open(log_file, "r", encoding="utf-8", errors="ignore") as file:
        for line in file:
            match = LOG_PATTERN.search(line)
            if match:
                data = match.groupdict()
                ip = data["ip"]
                ts = parse_timestamp(data["month"], data["day"], data["time"])

                if ip not in brute_force_ips:
                    brute_force_ips[ip] = []
                brute_force_ips[ip].append(ts)

    suspicious_ips = {}

    for ip, times in brute_force_ips.items():
        times.sort()
        for i in range(len(times)):
            start = times[i]
            end = start + timedelta(seconds=window_seconds)
            count = sum(1 for t in times if start <= t <= end)

            if count >= threshold:
                severity = classify_severity(count)
                suspicious_ips[ip] = {
                    "failed_attempts": count,
                    "severity": severity,
                    "window_start": start.strftime("%Y-%m-%d %H:%M:%S"),
                    "window_end": end.strftime("%Y-%m-%d %H:%M:%S"),
                    "suggestion": "High severity. Immediate action recommended." if severity == "High"
                    else "Monitor and consider blocking the IP." if severity == "Medium"
                    else "Low severity. Review and keep monitoring."
                }
                break

    with open("reports/report.json", "w") as f:
        json.dump(suspicious_ips, f, indent=4)

    return suspicious_ips


# -------------------------
# Tkinter GUI Setup
# -------------------------
def browse_file():
    path = filedialog.askopenfilename(title="Select Log File")
    entry_log_path.delete(0, tk.END)
    entry_log_path.insert(0, path)

def run_analysis():
    log_path = entry_log_path.get()
    if not log_path:
        messagebox.showerror("Error", "Please select a log file.")
        return

    try:
        threshold = int(entry_threshold.get())
        window = int(entry_window.get())
    except ValueError:
        messagebox.showerror("Error", "Threshold and window must be numbers.")
        return

    result = analyze_log(log_path, threshold, window)

    output_box.delete(1.0, tk.END)

    if result:
        for ip, info in result.items():
            output_box.insert(tk.END, f"→ {ip}\n")
            output_box.insert(tk.END, f"   Attempts: {info['failed_attempts']}\n")
            output_box.insert(tk.END, f"   Severity: {info['severity']}\n")
            output_box.insert(tk.END, f"   Time Window: {info['window_start']} → {info['window_end']}\n")
            output_box.insert(tk.END, f"   Suggestion: {info['suggestion']}\n\n")
    else:
        output_box.insert(tk.END, "No brute-force attempts detected.\n")


# ---------------------------------------
# MAIN WINDOW
# ---------------------------------------
root = tk.Tk()
root.title("SSH Brute-Force Log Analyzer (GUI)")
root.geometry("700x500")
root.resizable(False, False)

# Log file selection
tk.Label(root, text="Select Log File:").pack()
entry_log_path = tk.Entry(root, width=60)
entry_log_path.pack()

tk.Button(root, text="Browse", command=browse_file).pack(pady=5)

# Threshold and time window
tk.Label(root, text="Threshold (failed attempts):").pack()
entry_threshold = tk.Entry(root)
entry_threshold.insert(0, "5")
entry_threshold.pack()

tk.Label(root, text="Time Window (seconds):").pack()
entry_window = tk.Entry(root)
entry_window.insert(0, "60")
entry_window.pack()

# Run button
tk.Button(root, text="Run Analysis", command=run_analysis, bg="lightblue").pack(pady=10)

# Output box
output_box = scrolledtext.ScrolledText(root, width=80, height=15)
output_box.pack()

root.mainloop()
