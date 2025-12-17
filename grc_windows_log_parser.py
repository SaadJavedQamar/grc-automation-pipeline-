import win32evtlog
import csv
from datetime import datetime
import argparse

# -------- CLI ARGUMENT --------
parser = argparse.ArgumentParser(description="GRC Automation Log Pipeline")
parser.add_argument("--limit", type=int, default=5, help="Number of logs per control")
args = parser.parse_args()

LOG_LIMIT = args.limit

SERVER = 'localhost'
LOG_TYPE = 'Security'

CONTROL_EVENTS = {
    "Access Control": [4624, 4625],
    "Privileged Access": [4672],
    "Audit Log Monitoring": [1102],
    "User Account Management": [4720, 4726]
}

ISO_MAPPING = {
    "Access Control": "A.5.15",
    "Privileged Access": "A.5.18",
    "Audit Log Monitoring": "A.8.16",
    "User Account Management": "A.8.9"
}

hand = win32evtlog.OpenEventLog(SERVER, LOG_TYPE)
flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

events_by_control = {control: [] for control in CONTROL_EVENTS}

while True:
    events = win32evtlog.ReadEventLog(hand, flags, 0)
    if not events:
        break

    for event in events:
        for control, ids in CONTROL_EVENTS.items():
            if event.EventID in ids:
                if len(events_by_control[control]) < LOG_LIMIT:
                    events_by_control[control].append({
                        "Time": event.TimeGenerated.Format(),
                        "EventID": event.EventID,
                        "Source": event.SourceName
                    })

# -------- EVIDENCE FILE --------
with open("windows_multi_control_evidence.csv", "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(["Control", "ISO Control", "EventID", "Time", "Source"])

    for control, events in events_by_control.items():
        for e in events:
            writer.writerow([
                control,
                ISO_MAPPING[control],
                e["EventID"],
                e["Time"],
                e["Source"]
            ])

# -------- COMPLIANCE + RISK --------
with open("compliance_report.csv", "w", newline="") as report:
    writer = csv.writer(report)
    writer.writerow([
        "ISO Control",
        "Control Name",
        "Compliance Status",
        "Risk Level",
        "Collected Logs",
        "Report Time"
    ])

    for control, events in events_by_control.items():
        count = len(events)

        if count == 0:
            status = "Non-Compliant"
            risk = "High"
        elif count < LOG_LIMIT:
            status = "Compliant"
            risk = "Medium"
        else:
            status = "Compliant"
            risk = "Low"

        writer.writerow([
            ISO_MAPPING[control],
            control,
            status,
            risk,
            count,
            datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ])

print("✅ Pipeline executed successfully")
print(f"📦 Logs collected per control: {LOG_LIMIT}")
