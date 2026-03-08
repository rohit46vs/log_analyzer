# Log Analyzer - Threat Detection

The final project in the cybersecurity learning series! A tool that reads and analyzes log files to automatically detect suspicious activity — exactly what SOC analysts do every day!

---

## Project Structure


├── log_analyzer.py        # main file
└── README_loganalyzer.md  # This file
```

---

## Requirements

- Python 3.x
- No extra libraries needed!

---

## How to Run

```bash
py log_analyzer.py
```

---

## Features

| Option | What it does |
|---|---|
| 1. Analyze a file | Analyze any log file on your computer |
| 2. Demo mode | Analyze built-in sample logs instantly |
| 3. Generate sample file | Creates a sample_logs.txt to practice with |
| 4. Learn mode | Explains how log analysis works |

---

## What It Detects

| Threat | How it detects it |
|---|---|
| Failed Logins | Regex match on failed/invalid/incorrect login messages |
| Brute Force | 3+ failed logins from the same IP address |
| Root/Sudo Access | Privilege escalation attempts |
| SQL Injection | UNION SELECT, DROP TABLE, OR 1=1 patterns |
| XSS Attempts | script tags, onerror, javascript: patterns |
| Directory Traversal | ../ and %2e%2e patterns in URLs |
| Malware/Shells | wget, curl, powershell, /bin/bash commands |
| Port Scans | nmap and portscan signatures |
| Error Spikes | Clusters of ERROR/FATAL/CRITICAL entries |

---

## Example Output

```
  Analyzing 30 log entries from: sample_logs.txt

  OVERVIEW
  Total lines                    30
  ERROR                          5     #####
  WARN                           12    ############
  INFO                           13    #############

  THREAT DETECTION
  -------------------------------------------------------

  [Failed Login] - 8 occurrence(s) found:
    >> 2024-03-06 08:03:45 WARN 192.168.1.15 - Failed login for root
    >> 2024-03-06 08:03:46 WARN 192.168.1.15 - Failed login for root
    ... and 6 more

  [SQL Injection] - 2 occurrence(s) found:
    >> 2024-03-06 08:12:33 ERROR - UNION SELECT * FROM users--

  BRUTE FORCE DETECTION
  -------------------------------------------------------
  192.168.1.15         5 failed login attempts  *** HIGH RISK ***

  SUMMARY
  =======================================================
  Threat types detected : 6
  Total threat events   : 18
  Brute force IPs       : 1
  Risk Level            : HIGH - Multiple threats detected
```

---

## How to Analyze the Honeypot Log

After running Project 6, a file called `honeypot_log.txt` is created. You can analyze it with this tool:

1. Run the log analyzer
2. Choose option 1
3. Enter path: `honeypot_log.txt`
4. See all attacks broken down automatically!

---

## What You Learn From This Project

- How to read and parse real log files in Python
- Regular expressions (regex) for pattern matching at a professional level
- How brute force detection algorithms work
- What SOC analysts look for in logs every day
- How enterprise tools like Splunk and ELK Stack work
- Log levels: INFO, WARN, ERROR, CRITICAL, FATAL
- IP frequency analysis to spot attackers

---

## Real World Tools That Do This

| Tool | Used by |
|---|---|
| Splunk | Enterprise companies worldwide |
| ELK Stack | Open source, used by startups and enterprises |
| Wazuh | Open source SIEM for smaller teams |
| Graylog | Open source log management |

This project is a simplified version of all of these!

---
