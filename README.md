SSH Brute-Force Log Analyzer

A simple Python tool that scans Linux auth.log files to detect SSH brute-force login attacks.
It includes both a CLI version and a GUI version built using Tkinter.

Features

Detects repeated failed SSH login attempts

Classifies severity (Low / Medium / High)

Extracts IP, timestamp, and attack window

Generates a JSON report

GUI with file browser and easy controls

How to Run (CLI)
python analyzer.py --log logs/auth.log

How to Run (GUI)
python gui.py

Output

Suspicious IPs

Number of failed attempts

Severity level

Suggested action

JSON report saved in reports/report.json
