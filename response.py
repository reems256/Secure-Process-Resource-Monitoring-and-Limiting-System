#response.py 
import os
import json
import time
import signal
import subprocess
from datetime import datetime

# Colors used to make terminal output easier to read
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
RESET = "\033[0m"

# File names and time settings
ALERT_FILE = "alerts.json"
LOG_FILE = "response_logs.txt"
CHECK_INTERVAL = 2

# Stores how many times each PID has been flagged
offense_count = {}

# Processes that should not be changed or killed
SAFE_PROCESSES = [
    "systemd",
    "kthreadd",
    "lightdm",
    "Xorg",
    "dbus-daemon",
    "NetworkManager",
    "bash",
    "zsh",
    "sh",
    "python3",
    "qterminal",
    "xfce4-terminal",
    "gnome-terminal",
    "konsole",
    "xfdesktop",
    "xfwm4",
    "xfce4-panel",
    "xfsettingsd",
    "Thunar"
]

def write_log(message, color=RESET):
    # Add current date and time to each message
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    full_message = f"[{timestamp}] {message}"

    # Show message in terminal
    print(color + full_message + RESET)

    # Save the same message in the log file
    with open(LOG_FILE, "a") as file:
        file.write(full_message + "\n")

def pid_exists(pid):
    # Check if a process with this PID still exists
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        # Process exists, but access is limited
        return True
    except Exception:
        return False

def get_protected_pids():
    # Protect the current script, its parent, and related session processes
    protected = set()

    try:
        current_pid = os.getpid()
        parent_pid = os.getppid()

        protected.add(current_pid)
        protected.add(parent_pid)

        pid = current_pid
        while pid > 1:
            try:
                # Get the parent PID of the current PID
                ppid = int(subprocess.check_output(
                    ["ps", "-o", "ppid=", "-p", str(pid)],
                    text=True
                ).strip())
                protected.add(ppid)

                # Stop if the chain ends
                if ppid == pid or ppid <= 1:
                    break

                pid = ppid
            except Exception:
                break
    except Exception:
        pass

    return protected

def reduce_priority(pid):
    # Lower the process priority using renice
    try:
        subprocess.run(["renice", "+10", "-p", str(pid)], check=True)
        write_log(f"PID {pid}: priority reduced", GREEN)
    except Exception as e:
        write_log(f"PID {pid}: failed to reduce priority -> {e}", RED)

def kill_process(pid):
    # Forcefully stop the process
    try:
        os.kill(pid, signal.SIGKILL)
        write_log(f"PID {pid}: process killed", RED)

        # Remove PID from offense tracking after killing it
        if pid in offense_count:
            del offense_count[pid]

    except Exception as e:
        write_log(f"PID {pid}: failed to kill -> {e}", RED)

def load_alerts():
    # Read alerts created by the detection module
    if not os.path.exists(ALERT_FILE):
        return []

    try:
        with open(ALERT_FILE, "r") as file:
            return json.load(file)
    except Exception as e:
        write_log(f"Could not read alerts file -> {e}", RED)
        return []

def clear_alerts():
    # Clear the alerts file after processing all alerts
    try:
        with open(ALERT_FILE, "w") as file:
            json.dump([], file)
    except Exception as e:
        write_log(f"Could not clear alerts file -> {e}", RED)

def respond_to_alert(alert):
    # Get alert details
    pid = alert.get("pid")
    violation = alert.get("violation")
    name = alert.get("name", "Unknown")

    if pid is None:
        return

    # Get PIDs that belong to the current session
    protected_pids = get_protected_pids()

    # Skip trusted process names
    if name in SAFE_PROCESSES:
        write_log(f"PID {pid} ({name}) is protected by name. Skipping action.", BLUE)
        return

    # Skip the current terminal/session processes
    if pid in protected_pids:
        write_log(f"PID {pid} ({name}) is part of current session. Skipping action.", BLUE)
        return

    # Skip the process if it already ended
    if not pid_exists(pid):
        write_log(f"PID {pid} ({name}) no longer exists. Skipping.", BLUE)
        if pid in offense_count:
            del offense_count[pid]
        return

    # Update offense count for this PID
    if pid not in offense_count:
        offense_count[pid] = 1
    else:
        offense_count[pid] += 1

    count = offense_count[pid]

    # Log the alert and current offense number
    write_log(
        f"ALERT: PID {pid} ({name}) detected for {violation} - offense #{count}",
        YELLOW
    )

    # First offense: only log
    if count == 1:
        write_log(f"PID {pid}: first offense -> logging only", BLUE)

    # Second offense: lower priority
    elif count == 2:
        write_log(f"PID {pid}: second offense -> reducing priority", BLUE)
        reduce_priority(pid)

    # Third or later offense: kill process
    else:
        write_log(f"PID {pid}: repeated offense -> killing process", BLUE)
        kill_process(pid)

def response_controller():
    # Start the response module
    write_log("Response module started", BLUE)

    while True:
        # Load alerts every few seconds
        alerts = load_alerts()

        if alerts:
            for alert in alerts:
                respond_to_alert(alert)

            # Clear alerts after handling them
            clear_alerts()

        time.sleep(CHECK_INTERVAL)

if __name__ == "__main__":
    response_controller()  