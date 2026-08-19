# Secure Process Resource Monitoring and Limiting System

### A Linux-Based Process Monitoring and Resource Control System

A Python-based cybersecurity project designed to monitor running processes on a Linux system, identify processes that consume excessive system resources, and apply predefined resource limits to help maintain system stability and security.

The system uses the `psutil` library to continuously monitor process activity and evaluate processes based on CPU usage, memory consumption, number of child processes, and number of open files.

---

## Overview

A process that consumes an excessive amount of system resources can negatively affect system performance and availability. In some cases, abnormal resource consumption may also be associated with malicious or misbehaving processes.

This project implements a lightweight process monitoring and control system for Linux. It periodically examines running processes and compares their resource usage against predefined thresholds.

The system monitors:

* CPU utilization
* Memory consumption
* Number of child processes
* Number of open files

When a process exceeds one or more configured limits, the system identifies it as a potentially problematic process and can take appropriate resource-control action.

---

## Security Objectives

The project demonstrates several operating-system security concepts:

* Continuous process monitoring
* Resource usage detection
* Process-level security policies
* Detection of excessive resource consumption
* Prevention of uncontrolled resource usage
* Linux process management
* Automated monitoring and enforcement

The goal is to provide a basic defensive mechanism that can help prevent a single process from consuming an excessive amount of system resources.

---

## Resource Limits

The monitoring system uses predefined thresholds to determine when a process is consuming an excessive amount of resources.

| Resource        |  Limit |
| --------------- | -----: |
| CPU Usage       |    50% |
| Memory Usage    | 400 MB |
| Child Processes |     20 |
| Open Files      |     50 |

These thresholds define the resource limits used by the monitoring system and can be adjusted according to the requirements of the monitored Linux system.

---

## Monitored Resources

### CPU Usage

The system monitors the CPU utilization of individual processes.

A process exceeding the configured CPU threshold is identified as consuming excessive processor resources.

### Memory Usage

The system monitors the amount of memory being used by each process.

Processes exceeding the configured memory limit are flagged for exceeding the defined resource policy.

### Child Processes

The system counts the number of child processes associated with each process.

A process creating an unusually large number of child processes may consume significant system resources and is therefore checked against the configured child-process limit.

### Open Files

The system monitors the number of files opened by each process.

Processes exceeding the configured open-file limit are identified as exceeding the resource policy.

---

## Monitoring Process

The monitoring system operates continuously rather than performing a single resource check.

The general monitoring process is:

```text
Running Linux Processes
          │
          ▼
      Process Discovery
          │
          ▼
    Resource Collection
          │
          ├──► CPU Usage
          ├──► Memory Usage
          ├──► Child Processes
          └──► Open Files
          │
          ▼
     Limit Comparison
          │
          ▼
   Resource Limit Exceeded?
       │            │
      No           Yes
       │            │
       ▼            ▼
 Continue       Take Defined
 Monitoring     Control Action
```

The monitoring cycle is repeated periodically so that changes in process activity can be detected while the system is running.

---

## Main Component

### `monitor.py`

`monitor.py` contains the main process monitoring functionality.

It is responsible for:

* Discovering running processes
* Collecting process information
* Monitoring CPU usage
* Monitoring memory usage
* Counting child processes
* Checking open files
* Comparing resource usage against predefined limits
* Identifying processes that exceed configured limits
* Applying the defined process/resource control behavior

The monitoring interval is configurable within the program.

---

## Technologies Used

* **Python 3**
* **psutil**
* **Linux**
* Linux process management and resource monitoring

The `psutil` library provides access to information about running processes and system resource utilization.

---

## Requirements

The project requires:

* A Linux operating system
* Python 3
* `psutil`

Administrative privileges may be required because the program monitors information belonging to system processes and performs process-level control operations.

---

## How to Run

### 1. Install the Required Package

On the Linux machine, install `psutil`:

```bash
pip3 install psutil
```

### 2. Navigate to the Project Directory

Open a terminal and navigate to the directory containing the project files.

### 3. Start the Monitoring System

Run:

```bash
sudo python3 monitor.py
```

The program will begin monitoring running processes and evaluating their resource usage against the configured limits.

Keep the program running while testing process activity.

---

## Testing

The monitoring system can be tested by running processes that consume system resources and observing how the monitoring system responds when configured limits are exceeded.

Testing can include observing:

* Processes with high CPU utilization
* Processes consuming large amounts of memory
* Processes creating multiple child processes
* Processes opening a large number of files

The purpose of testing is to verify that the monitoring system correctly identifies processes that exceed the configured resource thresholds.

---

## Project Structure

```text
secure-process-monitor/
│
├── monitor.py
└── README.md
```

Additional documentation, reports, or testing results can be included in the repository if available.

---

## Purpose

This project demonstrates how operating-system-level monitoring can be incorporated into a defensive security mechanism.

By continuously monitoring process behavior and enforcing predefined resource limits, the system provides a practical example of process-level resource control and basic host-based security monitoring on Linux.

---

## Contributors

This project was developed as a group project.
-  Reem Sukkari
-  Asil Khalid
-  Salma Qasse
