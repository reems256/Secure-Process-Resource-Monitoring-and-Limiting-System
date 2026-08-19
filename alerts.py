#alerts.py
import time
import json

# Time between each detection round
REFRESH_INTERVAL = 2

# Limits used to detect suspicious behavior
CPU_LIMIT = 50
MEMORY_LIMIT = 400
CHILDREN_LIMIT = 20
FILES_LIMIT = 50

# Trusted processes that should not be flagged easily
trusted_processes = [
    "systemd",
    "kthreadd",
    "lightdm",
    "xfce4-session",
    "Xorg"
]

LOG_FILE = "detection_logs.txt"

def write_log(message):
    # Add time to each log message
    current_time = time.strftime("%Y-%m-%d %H:%M:%S")
    full_message = f"[{current_time}] {message}"

    print(full_message)

    # Save the same message in a log file
    with open(LOG_FILE, "a") as file:
        file.write(full_message + "\n")

def load_process_data(filename="process_data.json"):
    try:
        # Read process data created by the monitoring module
        with open(filename, "r") as f:
            return json.load(f)

    except FileNotFoundError:
        print("[ERROR] process_data.json not found. Make sure the process monitoring module is running.\n")
        return None

    except json.JSONDecodeError:
        print("[ERROR] Could not read process_data.json right now. Trying again...\n")
        return None

def detect_suspicious_behavior(processes):
    alerts = []

    # Check each process against the limits
    for p in processes:
        pid = p["pid"]
        name = p["name"]
        cpu = p["cpu"]
        memory = p["memory"]
        children = p["children"]
        open_files = p["open_files"]

        is_trusted = name in trusted_processes

        if cpu > CPU_LIMIT and not is_trusted:
            message = f"ALERT: PID {pid} ({name}) exceeds CPU limit"
            write_log(message)
            alerts.append({
                "pid": pid,
                "name": name,
                "violation": "CPU Abuse"
            })

        if memory > MEMORY_LIMIT and not is_trusted:
            message = f"ALERT: PID {pid} ({name}) exceeds memory limit"
            write_log(message)
            alerts.append({
                "pid": pid,
                "name": name,
                "violation": "Memory Abuse"
            })

        if children > CHILDREN_LIMIT and not is_trusted:
            message = f"ALERT: PID {pid} ({name}) possible fork bomb"
            write_log(message)
            alerts.append({
                "pid": pid,
                "name": name,
                "violation": "Fork Bomb"
            })

        if open_files > FILES_LIMIT and not is_trusted:
            message = f"ALERT: PID {pid} ({name}) too many open files"
            write_log(message)
            alerts.append({
                "pid": pid,
                "name": name,
                "violation": "File Descriptor Abuse"
            })

    return alerts

def export_alerts(alerts, filename="alerts.json"):
    # Save alerts for the response module
    with open(filename, "w") as f:
        json.dump(alerts, f, indent=4)

def display_alerts(alerts):
    print("\nData to send to response module:")

    if len(alerts) == 0:
        print("No suspicious behavior detected.")
    else:
        for alert in alerts:
            print(alert)

if __name__ == "__main__":
    print("[START] Suspicious Behavior Detection Module Running...\n")

    while True:
        processes = load_process_data()

        if processes is not None:
            alerts = detect_suspicious_behavior(processes)
            export_alerts(alerts)
            display_alerts(alerts)
            print("\n----------------------\n")

        time.sleep(REFRESH_INTERVAL)


