#monitor.py 
import psutil
import time
import json

# Time between each monitoring round
REFRESH_INTERVAL = 2  # seconds

def get_process_info(proc):
    try:
        pid = proc.pid
        name = proc.name()

        # Get current CPU usage
        cpu = proc.cpu_percent(interval=None)

        # Convert memory from bytes to MB
        memory = proc.memory_info().rss / (1024 * 1024)

        # Count child processes
        children = len(proc.children(recursive=True))

        # Count open files
        try:
            open_files = len(proc.open_files())
        except Exception:
            open_files = 0

        return {
            "pid": pid,
            "name": name,
            "cpu": cpu,
            "memory": memory,
            "children": children,
            "open_files": open_files
        }

    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return None

def monitor_processes():
    process_data = []

    # Loop through all running processes
    for proc in psutil.process_iter():
        info = get_process_info(proc)
        if info:
            process_data.append(info)

    return process_data

def display_processes(processes):
    print("\n[INFO] Monitoring running processes...\n")
    print(f"{'PID':<8}{'Name':<20}{'CPU %':<10}{'Memory(MB)':<15}{'Children':<10}{'Files':<10}")

    # Show process details in table form
    for p in processes:
        print(f"{p['pid']:<8}{p['name']:<20}{p['cpu']:<10.2f}{p['memory']:<15.2f}{p['children']:<10}{p['open_files']:<10}")

def export_to_json(processes, filename="process_data.json"):
    # Save process data for the detection module
    with open(filename, "w") as f:
        json.dump(processes, f, indent=4)

if __name__ == "__main__":
    print("[START] Process Monitoring Module Running...\n")

    # First CPU call is used to initialize readings
    for proc in psutil.process_iter():
        try:
            proc.cpu_percent(interval=None)
        except:
            pass

    while True:
        processes = monitor_processes()
        display_processes(processes)
        export_to_json(processes)
        time.sleep(REFRESH_INTERVAL)






