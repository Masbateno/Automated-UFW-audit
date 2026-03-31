*[Lire en français](README_TECH_FR.md)* · *[Vue d'ensemble](../README.md)*

# ufw-audit v1.3.0

![License](https://img.shields.io/badge/license-MIT-green)
![Release](https://img.shields.io/badge/version-v1.3.0-brightgreen)
![CI](https://github.com/Masbateno/Automated-UFW-audit/actions/workflows/tests.yml/badge.svg)
![Platform](https://img.shields.io/badge/platform-Debian%20%7C%20Ubuntu%20%7C%20Mint-informational)
![Language](https://img.shields.io/badge/language-Python%203.9%2B-yellow)

Lightweight UFW firewall audit tool for Linux — designed for regular users, not system administrators.

ufw-audit analyses your UFW configuration, detects exposed network services, classifies risks per service, and provides plain-language explanations with ready-to-run remediation commands.

---

## Features

- **ASCII banner** with system information (distro, host, UFW version, user, date)
- **UFW status check** — active/inactive, default incoming policy
- **UFW rule analysis** — duplicate rules, unrestricted `allow from any`, IPv6 consistency
- **Contextual scoring** — network context detection (direct public IP vs NAT); penalties doubled on internet-exposed machines; firewall inactive caps score at 3/10
- **Detection of 22 common network services** with UFW exposure analysis and two-axis risk context (exposure + threat) for critical and high-risk services
- **Docker analysis** — iptables bypass detection and list of ports exposed by running containers
- **Virtualisation analysis** — detects active hypervisors (libvirt/KVM, VirtualBox, VMware, LXD/LXC) and Snap network packages that may create bridge interfaces and manipulate iptables directly, bypassing UFW — same risk pattern as Docker
- **Listening ports analysis** — unified single-pass analysis; ephemeral and system ports silently skipped; NetBIOS handled with contextual warning
- **UFW log analysis** — parses `/var/log/ufw.log` over a configurable period (`--log-days=N`, default 7 days); total blocked attempts, top source IPs with geolocation, top targeted ports, bruteforce detection (>10 attempts/60s), attempts on installed service ports
- **IP geolocation** — source IPs enriched with country and operator via GeoIP2 (optional, `python3-geoip2` + GeoLite2 database); private ranges identified as local network; results cached per session
- **DDNS / external exposure detection** — detects active DDNS clients (ddclient, inadyn, No-IP, DuckDNS); extracts the configured domain; crosses with unrestricted UFW ALLOW rules to identify internet-exposed ports
- **Exposure classification** per service: `open to internet` / `local network only` / `blocked by UFW` / `no rule`
- **Fix mode** — interactive section after the summary; each automatable fix requires `[y/N]` confirmation; manual-only items displayed without execution; `-y / --yes` auto-fix mode displays a prominent warning banner and prints a full command summary after applying
- **Categorised summary** — findings split into three blocks: *Action required* / *Possible improvements* / *Normal configuration*; auto-generated interpretation phrase
- **Implicit policy note** — flags when high-risk services rely on the default `deny` policy rather than explicit rules
- **Security score** (0–10) with risk level: LOW / MEDIUM / HIGH / CRITICAL
- **Services panorama** — compact table of all 22 known services after the services audit (SERVICE / STATUS / PORT(S) / UFW), non-installed services shown dimmed
- **Bilingual interface** — English by default, French with `--french`
- **No-colour mode** — `--no-color` for clean output in pipes and log files
- **Optional detailed report** — timestamped log file with ASCII art header, system info, findings, and recommendations
- **`--manage-logs`** — interactive UI to list saved reports (name, size, date) and delete them by index or all at once
- **`--install-cron`** — schedule wizard: name the job, choose schedule type (daily / specific week days / specific month days / custom cron expression), set time, set optional notification email; preview in natural language before confirmation; named cron jobs (`/etc/cron.d/ufw-audit-{name}`)
- **`--manage-cron`** — looping TUI: list installed cron jobs, edit schedule or notification email, delete; `m` command opens the email address book (add / delete saved addresses) accessible even without any cron installed

---

## Detected services

| Service                          | Default port         | Risk     | Context                                                                              |
|----------------------------------|----------------------|----------|--------------------------------------------------------------------------------------|
| SSH Server                       | 22/tcp               | Critical | Heavily targeted by automated scanners; full shell access if compromised             |
| VNC Server                       | 5900/tcp             | Critical | Often unencrypted, weak auth; equivalent to physical machine access                  |
| Samba (Windows file sharing)     | 445/tcp, 139/tcp     | Critical | LAN-only by design; ransomware vector (EternalBlue/WannaCry) if exposed              |
| FTP Server                       | 21/tcp               | Critical | Unencrypted protocol; credentials and files transmitted in plain text                |
| MySQL / MariaDB                  | 3306/tcp             | Critical | Password auth, CVE history; full database exfiltration if exposed                    |
| PostgreSQL                       | 5432/tcp             | Critical | Configurable auth; RCE possible via pg_execute_server_program                        |
| Redis                            | 6379/tcp             | Critical | No auth by default historically; documented RCE — actively exploited                 |
| Cockpit (web admin)              | 9090/tcp             | High     | Web admin interface; full system control if compromised                              |
| WireGuard VPN                    | 51820/udp            | High     | Intentional internet exposure; full internal network access if keys stolen           |
| Home Assistant                   | 8123/tcp             | High     | Controls physical devices (locks, alarms); local network access via automations      |
| Nextcloud                        | 80/tcp, 443/tcp      | High     | Personal file server; full file/contact/calendar access if compromised               |
| Mosquitto (MQTT)                 | 1883/tcp, 8883/tcp   | High     | No auth by default; anyone can control IoT devices if exposed                        |
| Apache Web Server                | 80/tcp, 443/tcp      | Medium   | Standard web exposure; risk depends on hosted content                                |
| Nginx Web Server                 | 80/tcp, 443/tcp      | Medium   | Standard web exposure; risk depends on hosted content                                |
| Jellyfin                         | 8096/tcp             | Medium   | Media library access; no critical system data                                        |
| Plex Media Server                | 32400/tcp            | Medium   | Media library access; no critical system data                                        |
| Transmission (web UI)            | 9091/tcp             | Medium   | Download control; file access limited to torrent directory                           |
| qBittorrent (web UI)             | 8080/tcp             | Medium   | Download control; file access limited to torrent directory                           |
| Gitea                            | 3000/tcp             | Medium   | Git forge; disable public registration if not needed                                 |
| Avahi (local network discovery)  | 5353/udp             | Low      | LAN-only mDNS; no data access, discovery only                                        |
| CUPS (network printing)          | 631/tcp              | Low      | Listens on localhost by default; negligible if not exposed                           |
| Syncthing                        | 8384/tcp, 22000/tcp  | Low      | Web UI on localhost by default; sync port may be internet-facing                     |

> **ℹ Note on service coverage:** Detection and classification for the following services has been validated through real-world testing: SSH, Samba, Avahi, CUPS, Redis, WireGuard, Docker, Mosquitto, Syncthing, Nginx. Other services are implemented but not yet validated by a formal test protocol. If you run one of these services and notice incorrect behaviour, please open an issue on GitHub.

---

## Requirements

- Linux system — Debian, Ubuntu, Linux Mint, or derivative
- UFW installed: `sudo apt install ufw`
- Python 3.9+
- `ss` recommended (`iproute2` package) — available by default on modern systems
- `python3-geoip2` + GeoLite2 database recommended for IP geolocation (optional): `sudo apt install python3-geoip2 geoip-database`
- `docker` CLI for Docker analysis (optional)

---

## Installation

### Prerequisites

- Linux: Debian, Ubuntu, Mint or derivative
- UFW: `sudo apt install ufw`
- pipx: `sudo apt install pipx && pipx ensurepath`

> Open a new terminal after `pipx ensurepath` to activate the PATH.

### Install

```bash
pipx install ufw-audit
```

### Enable sudo + bash completion

pipx installs the binary in `~/.local/bin/`, which is not in sudo's restricted PATH.
`--install-completion` creates the symlink `/usr/local/bin/ufw-audit` and installs the bash completion script:

```bash
sudo ~/.local/bin/ufw-audit --install-completion
source /etc/bash_completion.d/ufw-audit
```

After this step, `sudo ufw-audit` works normally and `ufw-audit --<TAB>` completes options.

---

## Uninstall

```bash
pipx uninstall ufw-audit
```

---

## Usage

```bash
# Standard audit
sudo ufw-audit

# Audit in French
sudo ufw-audit --french

# Verbose mode — technical details and port table
sudo ufw-audit -v

# Detailed mode — generate a full report file
sudo ufw-audit -d

# Fix mode — propose and apply corrections interactively
sudo ufw-audit -f

# Fix mode — apply all corrections without confirmation
sudo ufw-audit -f -y

# No-colour output (useful for pipes and redirection)
sudo ufw-audit -n > audit.txt

# Analyse logs over 14 days instead of 7
sudo ufw-audit --log-days=14

# Reconfigure custom ports
sudo ufw-audit -r

# Quiet mode — no output, use exit code to detect issues
sudo ufw-audit -q; echo $?   # 0=clean, 1=warnings, 2=alerts, 3=error

# Skip external IP lookup (air-gapped or restricted machines)
sudo ufw-audit --offline
sudo ufw-audit -o

# Show version (no sudo required)
ufw-audit -V

# Show help (no sudo required)
ufw-audit -h

# Manage saved report files interactively
sudo ufw-audit --manage-logs

# Set up an automated audit (schedule wizard)
sudo ufw-audit --install-cron

# List, edit or delete installed cron jobs
sudo ufw-audit --manage-cron

# Install bash completion and create sudo PATH symlink (run once after pipx install)
sudo ufw-audit --install-completion
```

Options can be combined:

```bash
sudo ufw-audit -v -d --fix
```

---

## Custom port configuration

When a service is detected on a non-standard port (e.g. SSH on port 2222), the script offers to save the port once. The answer is saved to `~/.config/ufw-audit/config.conf` and reused on subsequent audits. To reconfigure:

```bash
sudo ufw-audit --reconfigure
```

---

## Example output

```
╔══════════════════════════════════════════════════════════════════════════════╗
║ ██╗   ██╗ ███████╗ ██╗    ██╗      █████╗  ██╗   ██╗ ██████╗  ██╗ ████████╗  ║
║ ██║   ██║ ██╔════╝ ██║    ██║     ██╔══██╗ ██║   ██║ ██╔══██╗ ██║ ╚══██╔══╝  ║
║ ██║   ██║ █████╗   ██║ █╗ ██║ ═══ ███████║ ██║   ██║ ██║  ██║ ██║    ██║     ║
║ ██║   ██║ ██╔══╝   ██║███╗██║     ██╔══██║ ██║   ██║ ██║  ██║ ██║    ██║     ║
║ ╚██████╔╝ ██║      ╚███╔███╔╝     ██║  ██║ ╚██████╔╝ ██████╔╝ ██║    ██║     ║
║  ╚═════╝  ╚═╝       ╚══╝╚══╝      ╚═╝  ╚═╝  ╚═════╝  ╚═════╝  ╚═╝    ╚═╝     ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  UFW-AUDIT v1.3.0  │  UFW firewall audit                                     ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  System        : Ubuntu 24.04 LTS                                            ║
║  Host          : my-machine                                                  ║
║  UFW           : v0.36.2                                                     ║
║  User          : alice                                                       ║
║  Date          : 27/03/2026 10:00                                            ║
╚══════════════════════════════════════════════════════════════════════════════╝

┌──────────────────────────────────────────────────────────────────────────────┐
│  FIREWALL STATUS                                                             │
└──────────────────────────────────────────────────────────────────────────────┘

✔ [OK] UFW is installed
✔ [OK] UFW firewall is active
✔ [OK] Default policy: incoming connections blocked (recommended)

┌──────────────────────────────────────────────────────────────────────────────┐
│  UFW RULES ANALYSIS                                                          │
└──────────────────────────────────────────────────────────────────────────────┘

✔ [OK] No duplicate UFW rules detected
✔ [OK] No 'allow from any' rule without port restriction detected
✔ [OK] IPv6 configuration consistent with UFW rules

┌──────────────────────────────────────────────────────────────────────────────┐
│  NETWORK SERVICES ANALYSIS                                                   │
└──────────────────────────────────────────────────────────────────────────────┘

  ▶ SSH Server
    ┄ Risk context — CRITICAL
    Exposure : Heavily targeted by automated scanners and brute-force attacks
    Potential threat   : Full shell access to the machine, privilege escalation

✖ [ALERT] Port 22/tcp — open to internet — no source restriction in UFW

  ▶ Nginx Web Server
✔ [OK] Service active and set to start automatically at boot
⚠ [WARNING] Port 80/tcp — open to internet — no source restriction in UFW

  ▶ Redis
    ┄ Risk context — CRITICAL
    Exposure : No authentication by default historically, very frequently misconfigured
    Potential threat   : Read/write access to all data, remote code execution (RCE)

✔ [OK] Service active and set to start automatically at boot
ℹ [INFO] Port 6379/tcp — covered by default deny policy (no explicit UFW rule needed)

┌──────────────────────────────────────────────────────────────────────────────┐
│  SERVICES PANORAMA                                                           │
└──────────────────────────────────────────────────────────────────────────────┘

  SERVICE                           STATUS         PORT(S)               UFW
  ────────────────────────────────  ─────────────  ────────────────────  ───
  SSH Server                        ACTIVE         22/tcp                ✖
  Nginx Web Server                  ACTIVE         80/tcp, 443/tcp       ⚠
  Redis                             ACTIVE         6379/tcp              ✖
  ...

┌──────────────────────────────────────────────────────────────────────────────┐
│  LISTENING PORTS ANALYSIS                                                    │
└──────────────────────────────────────────────────────────────────────────────┘

ℹ [INFO] Internal system port — no risk: 53/udp (DNS)
ℹ [INFO] Port 25/tcp — bound to localhost only — no external exposure
✔ [OK] All ports listening on 0.0.0.0 are covered by a UFW rule

┌──────────────────────────────────────────────────────────────────────────────┐
│  UFW LOG ANALYSIS                                                            │
└──────────────────────────────────────────────────────────────────────────────┘

  Period analysed : 7 day(s) — 7 day(s) of logs available

✔ [OK] Normal activity — 47 blocked attempt(s) over 7 day(s), no threat detected
ℹ [INFO] Top source IPs : 203.0.113.42 (US, Virginia) — 18 attempt(s)
ℹ [INFO] Top targeted ports : 22/tcp — 31 attempt(s)

╔══════════════════════════════════════════════════════════════════════════════╗
║  Security score : 6/10                                                       ║
║  Risk level : ✖ MEDIUM                                                       ║
║  Network context : 🌐 Exposed to internet                                    ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  ✖ Action required                                                           ║
║    ✖  Port 22/tcp — open to internet — no source restricti…                  ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  ⚠ Possible improvements                                                     ║
║    ⚠  Port 80/tcp — open to internet — no source restricti…                  ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  Score breakdown                                                             ║
║    -2  SSH Server 22/tcp exposed to internet                                 ║
║    -1  Nginx Web Server 80/tcp exposed to internet                           ║
║    -1  SSH Server 22/tcp exposed to internet                                 ║
╚══════════════════════════════════════════════════════════════════════════════╝

  Corrections are needed. Address items marked 'Action required' first.
```

---

## Report files

With `-d`, a timestamped report is created in a configurable directory (prompted on first use, saved to `config.conf`):

```
ufw_audit_20260323_100000.log
```

The report opens with a 62-char ASCII art header and contains: system information, all timestamped findings, complete listening port list, detailed log analysis (top IPs with geolocation, top ports, bruteforce, hits on installed service ports), risk context for critical/high services, score summary.

---

## Options reference

| Option                  | Description                                                        |
|-------------------------|--------------------------------------------------------------------|
| *(no option)*           | Standard audit                                                     |
| `-v`, `--verbose`       | Show technical details (port table, per-port exposure)             |
| `-d`, `--detailed`      | Generate a full report file                                        |
| `-q`, `--quiet`         | Suppress all output — use exit code to detect issues               |
| `-f`, `--fix`           | Propose and apply corrections interactively                        |
| `-y`, `--yes`           | Apply all corrections without confirmation (use with `-f`)         |
| `-r`, `--reconfigure`   | Reconfigure all custom ports                                       |
| `-n`, `--no-color`      | Disable ANSI colour output                                         |
| `--json`                | Export summary as JSON                                             |
| `--json-full`           | Export full audit details as JSON                                  |
| `--log-days=N`          | Analyse logs over N days (default: 7)                              |
| `-o`, `--offline`       | Skip external IP lookup (no HTTP calls)                            |
| `--manage-logs`         | Interactive UI to list and delete saved report files               |
| `--install-cron`        | Set up an automated nightly audit (cron)                           |
| `--install-completion`  | Install bash completion and create sudo PATH symlink               |
| `--french`              | Switch interface to French                                         |
| `-V`, `--version`       | Show version and exit (no sudo required)                           |
| `-h`, `--help`          | Show help and exit (no sudo required)                              |

---

## Files

| File                                     | Description                                                          |
|------------------------------------------|----------------------------------------------------------------------|
| `~/.local/bin/ufw-audit`                 | pipx entry point                                                     |
| `/usr/local/bin/ufw-audit`               | Symlink for sudo access (created by `--install-completion`)          |
| `/etc/bash_completion.d/ufw-audit`       | Bash completion (created by `--install-completion`)                  |
| `/usr/local/bin/ufw-audit-nightly`       | Nightly wrapper script (created by `--install-cron`)                 |
| `/etc/cron.d/ufw-audit-{name}`           | Named system cron entry (created by `--install-cron`)                |
| `~/.config/ufw-audit/config.conf`        | User configuration (custom ports, log directory; permissions 600)    |
| `ufw_audit_YYYYMMDD_HHMMSS.log`          | Detailed report (created with `-d`, in the configured directory)     |

---

## Exit codes

When using `--quiet`, the exit code tells you the audit result:

| Code | Meaning |
|------|---------|
| `0`  | Clean audit — no alerts, no warnings |
| `1`  | Warnings detected |
| `2`  | Alerts detected — action required |
| `3`  | Technical error |

Example cron job — daily audit at 6am, email on issues:

```bash
0 6 * * * sudo ufw-audit --quiet -d || echo "ufw-audit exit $? on $(hostname)" | mail -s "UFW Alert" admin@example.com
```

---

## Important note

ufw-audit is an audit and diagnostic tool, not a security shield. It analyses your configuration and flags problems — but it does not apply corrections automatically without your consent, and it cannot detect everything. Some software like Docker can bypass UFW by manipulating iptables directly: ufw-audit detects this specific case and flags it, but other similar vectors exist that fall outside the current scope of the project. In short: ufw-audit helps you see more clearly — it does not replace good general security hygiene.

---

## Roadmap

**v0.9** — Complete Python rewrite, 421 unit tests, transparent installer with manifest, bash completion, bilingual EN/FR, 22 services with two-axis risk context

**v0.10** — Optional GeoIP2 geolocation, whois removal, short CLI flags, bash completion for install.sh, score scope disclaimer

**v0.11** — CLI consolidation & field testing (Mint/Debian/Kali), non-interactive mode (`--quiet`, exit codes 0-3), `check_virtualization()`, port deduplication, scoring fixes

**v0.11.1** — Security hardening patch: 20 vulnerabilities fixed (shell injection, ANSI injection, path traversal, symlink attacks, ReDoS, JSON bomb, file permission hardening)

**v0.11.2** — Output & UX pass: banner redesigned (full "UFW-AUDIT" block art, 80-char width, version étage), log verdict line, report file section consistency fixes, locale grammar fixes

**v0.11.3** — Log location prompt, services panorama, `--manage-logs`, `--install-cron` / `--remove-cron`, ASCII art header in report files, auto-fix banner and command summary, `AUTOMATION.md`

**v0.11.4** — Bug fix patch: open-any wildcard detection (trailing spaces, `/tcp`/`/udp` variants), semantic duplicate detection (`PORT/proto` vs `PORT`), comment stripping, critical/high services exposure → alert, DDNS bare port rule support, `TESTING.md`

**v0.12** — Markdown email reporting: zero-dependency HTML conversion, MIME multipart emails (plaintext + HTML), nightly script HTML rendering, UTF-8 box stripping

**v0.13** — Multi-cron scheduler: named cron jobs, 4-step schedule wizard (daily / week days / month days / custom expression), `--manage-cron` TUI, `--remove-cron` with explicit selection, `cron.py` isolated module

**v0.14** — Refactoring: `__main__.py` reduced from ~1820 to ~481 lines; new dedicated modules: `display.py`, `fixes.py`, `manage_logs.py`, `panorama.py`, `sysinfo.py`; `check_rules()` moved to `checks/firewall.py`; pure orchestrator with no business logic

**v0.14.1** *(stable)* — Post-release corrections: false positive ALERT for loopback-bound services (Redis/6379), DDNS false positives (system ports, dangling rules, bare proto rules), `--remove-cron` not removed on release, VERSION banner showing `v0.13.0b`

**v0.15** — Security hardening (input validation, file permissions, shell surfaces, error handling); DRY refactoring (`checks/_run.py`, `_paths.py`, `_truncate`); install script fixes (missing `__init__.py`, Python version check, glob-based locale/doc copy, new modules); IPv6 wildcard detection bug fix (`open_any_pattern` now matches `Anywhere (v6)` lines); loopback port message fix (`ports.uncovered_local` locale key); full live regression test suite validated

**v0.15.1** — Install script robustness: trap + rollback on partial failure, `do_copy_dir` dead code removed; bug fix: open-any without `[N]` index no longer produces invalid fix command; fix UI output cleanup (`capture_output`); locale `_meta.version` corrected; installation design documented in README_TECH

**v0.16** — Two panorama false-positive fixes: `Exposure.NOT_LISTENING` (registry port not actively listening → panorama ✔, no message) and `Exposure.LOOPBACK_NO_RULE` (loopback port with no UFW rule → panorama ✔, INFO message); full live regression suite (C6 × 9 services, C8 OPEN_LOCAL, E1 loopback)

**v0.17** — Unit test suite fully green: 505/505; 15 pre-existing failures fixed across 6 test files; two code fixes (`_extract_duckdns_domain` query-param parsing, `cron_to_human` DOW range guard)

**v0.18** — 26 new unit tests for `fixes.py` (`run_fixes()`): item classification, UFW delete sort order, subprocess paths, interactive mode, auto mode (`--yes`), auto summary; suite reaches 531/531

**v0.19** — GitHub Actions CI: pytest on every push/PR, Python 3.8 / 3.10 / 3.12 matrix

**v0.20** — 17 degraded-mode tests (`tests/test_degraded.py`): ss absent, empty UFW rules, missing log file, combined multi-module degradation; suite reaches 548/548

**v0.21** — Pre-v1.0 quality pass: 78 new tests + 3 bug fixes; `virtualization.py` fully covered; CGNAT/IPv6 false-positive fixed; commented config lines no longer mis-detected; CLI mode exclusion enforced; `--manage-cron` email address book (add/delete/clear); suite reaches 619/619

**v0.22** — Internal quality pass: 5 modules refactored (`__main__`, `firewall`, `services`, `scoring`, `output`); box-border alignment fixed across all UI frames; `meta: dict` removed from `CheckResult` → typed `open_ports: List[str]`

**v0.22.1** — Hotfix: UFW detected as inactive on non-English locales; `LANGUAGE` env var now cleared alongside `LC_ALL=C`

**v1.0** — Stable release; `pipx install ufw-audit` as primary install method; `--install-completion` creates bash completion and sudo PATH symlink; Python 3.9 minimum; CI matrix updated (3.9 / 3.10 / 3.12); `not_listening` locale key added; install.sh deprecated

**v1.2.0** — Code quality pass: 12 defensive fixes across 8 modules; private IPv4 `172.x` regex corrected; `Deduction.context` validated; cap visible in score breakdown; 639/639

**v1.2.1** — Packaging cleanup: `install.sh` removed; `pyproject.toml` fixes (LICENSE, classifier, Issues URL)

**v1.3.0** *(current)* — i18n completeness: all deduction reasons translated via `t()`; `--offline`/`-o` flag; IPv6 public address detection; 3-provider IP fallback chain; 652/652

**Post v1.0**
- Web UI (`--gui`) — graphical interface for non-technical users, pedagogical approach, simplified scope
- Launchpad PPA / `.deb` package if adoption warrants it

---

## License

MIT License — © 2026 Cédric Clauzel. See `LICENSE` for details.

---

## Author

Cédric Clauzel