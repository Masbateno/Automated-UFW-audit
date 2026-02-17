# UFW-audit v0.1

![License](https://img.shields.io/badge/license-MIT-green)
![Release](https://img.shields.io/badge/version-v0.1-blue)

Lightweight **UFW Firewall Audit Script** for Linux.

This script performs a minimal security audit of your UFW (Uncomplicated Firewall) configuration, checks for common misconfigurations, detects potentially dangerous rules, and logs the full system topology.

---

## Features

- Checks if UFW is installed and active
- Verifies default incoming/outgoing policies
- Checks IPv6 configuration
- Detects broad "Anywhere" rules
- Detects sensitive ports exposed (SSH, FTP, Telnet, RDP, VNC, MySQL, PostgreSQL)
- Lists all listening ports
- Generates a full log file with timestamp
- Calculates a security score (0–10) with risk classification (LOW / MEDIUM / HIGH)
- Optional verbose mode for full terminal output
- Help option `-h / --help`

---

## Requirements

- Linux system (tested on Debian 12)
- UFW installed
- Bash shell

---

## Usage

Make the script executable:

```bash
chmod +x UFW-audit.sh
Run the audit (normal mode):

./UFW-audit.sh
Run the audit in verbose mode (full output in terminal):

./UFW-audit.sh -v
Show help:

./UFW-audit.sh -h
Example Output
Normal run:

=== FIREWALL CHECKLIST ===
[OK] UFW installed
[OK] Firewall active
[OK] Incoming default = DENY
[OK] Outgoing default = ALLOW
[OK] IPv6 enabled

=== SECURITY ANALYSIS ===
[WARNING] Rules allowing access from Anywhere detected
[NOT OK] Sensitive port 22 open to Anywhere
[WARNING] 2 listening ports detected

=== SUMMARY ===
OK: 5
WARNING: 2
NOT OK: 1

Security score: 6/10
Risk level: MEDIUM
Full log saved at:
./ufw_audit_20260215_143210.log
Logs
The script generates a log file in the same directory as:

ufw_audit_YYYYMMDD_HHMMSS.log
This contains the full UFW status, numbered rules, raw tables, and listening ports.

Future Improvements
Automatic fix mode for common misconfigurations

Export JSON logs for SIEM or automated tools

Compatibility checks with other Linux distributions

Extended sensitive ports detection

Optional email alert for high-risk configurations

License
This project is licensed under the MIT License. See LICENSE for details.

Author
so6
