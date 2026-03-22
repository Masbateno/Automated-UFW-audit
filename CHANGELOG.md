# UFW-audit — Changelog

All notable changes to this project are documented here.

---

## [v0.11.2] — 2026-03-22

### Output & UX improvements

- **Banner redesigned** — "UFW-AUDIT" in full block ASCII art (figlet Doom style) spanning the full 80-char banner width; dash rendered as `═══` on the vertical midpoint; mascot removed; new étage row (`╠═╣ / UFW-AUDIT vX.X  │  subtitle / ╠═╣`) inserted between the art and system info
- **Log verdict** — replaced raw block count with a coloured verdict line: `[OK] Normal activity` or `[WARNING] Suspicious activity`
- **Top IPs / ports** — promoted from `print_dim` to `print_info` (`ℹ [INFO]`) for consistent visual weight
- **Port dump (ss)** — conditioned to verbose mode (`-v`); non-verbose shows a `Use -v to display the full port table` hint instead
- **Port exposure messages** — made fully self-explanatory: `open to internet — no source restriction in UFW`, `restricted to local network by UFW rule`, `explicitly blocked by a UFW rule`, `covered by default deny policy (no explicit UFW rule needed)`
- **Installation docs** — added `chmod +x install.sh` step to README and README_FR

### Report file fixes

- Removed duplicate log section header (written twice: from main flow and from `_display_log_results`)
- `LISTENING PORTS` section title now uses the active locale instead of hardcoded English
- Virtualisation findings now have their own `=== ANALYSE DE VIRTUALISATION ===` section header (were appended inside the Docker section)
- Removed duplicate `PORTS EN ÉCOUTE (VUE GÉNÉRALE)` header (the ss dump header was redundant with the section header two lines above)
- Added blank line separator between the port count line and the ss dump in the report

### Locale fixes

- French: `"jours de logs disponibles"` → `"jour(s) de logs disponibles"` (grammar for count=1)
- English: `"days of logs available"` → `"day(s) of logs available"` (consistency)

---

## [v0.11.1] — 2026-03-22

### Security hardening — 20 fixes across 3 passes

Patch release addressing security vulnerabilities found during internal code review. No functional changes — all v0.11 features remain identical.

#### Critical / High

- **Shell injection** — `subprocess.run(cmd, shell=True)` in fix mode replaced by `shlex.split()` + list form; virtualization interface name quoted with `shlex.quote()`
- **Daemon.json overwrite** — Docker fix command replaced by a safe Python one-liner that merges existing keys instead of blindly overwriting the file with `tee`
- **ANSI injection** — new `output.sanitize()` strips ANSI escape sequences and non-printable characters from all external data (container names, hostnames, domains) before terminal display
- **Path traversal / symlink attacks** — `_is_safe_config_path()` added to `ddns.py` and `services.py`; all config file reads guarded by `path.is_absolute() and not path.is_symlink()`
- **GeoIP2 symlink attack** — `_geo_via_geoip2()` and `geoip2_status()` skip symlinked database files
- **`SUDO_USER` injection** — validated against `^[a-zA-Z0-9_.-]{1,256}$` before `pwd.getpwnam()`

#### Medium

- **ReDoS** — `\S+` in `_extract_field()` bounded to `\S{1,256}`
- **JSON bomb / DoS** — `registry.py` and `i18n.py` cap JSON file reads at 1 MB and 512 KB respectively before `json.loads()`
- **Memory DoS** — `/var/log/ufw.log` read capped at 100 MB; `/etc/os-release` line capped at 512 bytes
- **`UFW_AUDIT_SHARE` injection** — validated: must be absolute, non-symlink, existing directory before use in `registry.py` and `i18n.py`
- **HTTP response validation** — ipify.org response limited to 64 bytes and validated against IPv4 regex
- **Domain injection** — extracted DDNS domain validated against domain regex; sanitized with `output.sanitize(max_len=253)` before display
- **Port / protocol injection** — `services.py` validates port number (1–65535) and protocol (`tcp`/`udp`) from registry before use
- **TOCTOU** — `docker.py` daemon.json existence check replaced with atomic `try/except FileNotFoundError`

#### Low

- **File permissions** — report files created with `0o600` via `os.open()`; user config directory created with `0o700`; config file written with `0o600`
- **Subprocess returncode** — fix mode checks `proc.returncode` and reports success/failure explicitly
- **Broad exception clauses** — `except Exception` replaced by specific exception types throughout
- **FD leak** — quiet mode `/dev/null` file descriptor registered with `atexit` for clean closure
- **Hostname / OS name injection** — sanitized with `output.sanitize(max_len=64)` before terminal display
- **Unused import** — `import io` removed from quiet mode path

---

## [v0.11] — 2026-03-22

### CLI consolidation & field testing

- Tested on 3 distributions: Linux Mint 22.3, Debian 13 (trixie), Kali Linux Rolling
- Python versions covered: 3.12, 3.13
- All bugs found during field testing fixed (see below)

### Bug fixes

- **`_command_exists()` returncode** — `subprocess.run` does not raise on missing command; returncode was not checked, causing removed packages (`rc` dpkg state) to be detected as installed. Fixed in `firewall.py` and `docker.py`.
- **Wildcard address `*`** — some `ss` versions use `*` instead of `0.0.0.0` for "all interfaces"; added to `_ALL_INTERFACES` regex and `_split_addr_port()` parser in `ports.py`.
- **qlipper port 6666/udp** — KDE clipboard sync tool; added to `_SYSTEM_PORTS` to suppress false positive.
- **Verbose mode double display** — port exposure lines were printed twice with `-v`; removed redundant block in `__main__.py`.
- **Score breakdown `-0`** — when firewall is inactive, cap was displayed as `-0` instead of a clear note; replaced with `⚠ Score capped at 3 (firewall inactive)`.
- **Port deduplication** — NetBIOS ports 137/138 and other multi-address ports were reported once per bound address instead of once per port; added `reported_warn_ports` and `reported_alert_ports` sets in `ports.py`.
- **UPnP/SSDP port 1900/udp** — local multicast discovery; added to `_SYSTEM_PORTS`.
- **DHCPv6 ports 546/547/udp** — added to `_SYSTEM_PORTS`.
- **IPv6 warning duplicate** — appeared in both `FIREWALL STATUS` and `UFW RULES ANALYSIS` sections; removed from `firewall.py`, kept only in `_check_rules()`.

### Non-interactive mode (`--quiet`)

- New `-q` / `--quiet` flag — suppresses all terminal output via stdout redirect to `/dev/null`
- Meaningful exit codes for scripting and cron automation:
  - `0` — clean audit, no alerts or warnings
  - `1` — warnings detected
  - `2` — alerts detected, action required
  - `3` — technical error
- `--quiet` is incompatible with `--fix` (validated at parse time)
- Exit codes documented in `--help` and README

### `check_virtualization()`

- New `ufw_audit/checks/virtualization.py` module — same pattern as `check_docker()`
- Detects: libvirt/KVM (`virsh`, `virbr*`), VirtualBox (`vboxmanage`, `vboxnet*`), VMware (`vmware`, `vmnet*`), LXD/LXC (`lxd`/`lxc`, `lxdbr*`)
- Also detects Snap packages with active network connections
- Warning displayed without score penalty — informational, not a misconfiguration
- Validated on Linux Mint 22.3 with active libvirt/KVM + `virbr0`

### Bash completion

- `install.sh` completion added — `./install.sh --<TAB>` completes `--dry-run`, `--uninstall`, `--help`

---

## [v0.10] — 2026-03-22

### IP geolocation — whois removed, GeoIP2 optional

- **`whois` completely removed** — unreliable across registries, slow on large log files, blocking on 100+ IPs
- **GeoIP2 optional integration** — uses `python3-geoip2` + MaxMind GeoLite2 database if available; silent fallback to bare IP if not installed
- **In-memory cache `_GEO_CACHE`** — each IP resolved only once per session regardless of how many times it appears in logs
- **`geoip2_status()`** — detects library availability and database presence independently; three states: `available`, `unavailable`, `no_database`
- **One-time info message** in log analysis section:
  - GeoIP2 absent: `GeoIP2 not available — install it with: sudo apt install python3-geoip2 geoip-database`
  - GeoIP2 installed but no database: `GeoIP2 installed but no GeoLite2 database found — install it with: sudo apt install geoip-database`
  - GeoIP2 available: no message displayed

### CLI improvements

- **Short flags** — all frequently used options now have a short form:
  - `-f` / `--fix`
  - `-y` / `--yes`
  - `-r` / `--reconfigure`
  - `-n` / `--no-color`
  - `-V` / `--version` (already existed, now documented)
- **`-h` / `--help` and `-V` / `--version` without sudo** — root check moved after argument parsing; informational options never require elevated privileges
- **Help rewritten** — clean tabular format with short+long flags, usage examples, and documentation link

### Bash completion

- **`install.sh` completion added** — `./install.sh --<TAB>` now completes `--dry-run`, `--uninstall`, `--help`
- Completion file updated in `/etc/bash_completion.d/ufw-audit`

### Score scope disclaimer

- **Two-line note displayed after every audit summary** — reminds the user that the score covers firewall exposure only, not system updates, application security, or other attack vectors
- Bilingual EN/FR via locale keys `summary.scope_line1` and `summary.scope_line2`

### Version format

- Version strings changed from `0.9.0` style to `0.9` / `0.10` — simpler, consistent with project conventions

---

## [v0.9.0] — 2026-03-20

Complete rewrite in Python — all functionality preserved and extended, architecture overhauled.

### Complete Python rewrite

- **Language** — rewritten from Bash to Python 3.8+ (stdlib only, zero PyPI dependencies)
- **Architecture** — each check module split into two strict layers:
  - `XxxSnapshot.from_system()` — system data collection via subprocess
  - `check_xxx(snapshot, t)` — pure logic, fully unit-testable without system calls
- **421 unit tests** across 13 test files — zero failures; all tests run without sudo and without UFW installed
- **Package structure** — `ufw_audit/` with `checks/` subpackage, `locales/`, `data/`
- **Entry point** — `/usr/local/bin/ufw-audit` installed by `install.sh`

### Installer

- **`install.sh`** — transparent installer with explicit output for every action
- Detects Python 3.8+, copies files to standard Linux locations (`/usr/local/`)
- Writes an exhaustive install manifest to `/usr/local/share/ufw-audit/install.manifest`
- **`--uninstall`** — reads the manifest, removes exactly what was installed, removes directories only if empty, offers user configuration removal separately
- **`--dry-run`** — shows all actions without making any changes

### New modules

| Module | Role |
|---|---|
| `cli.py` | `AuditConfig` dataclass + `parse_args()` |
| `config.py` | `UserConfig` — `~/.config/ufw-audit/config.conf` (replaces `~/.ufw_audit.conf`) |
| `i18n.py` | `t("key.sub_key")` with dot notation, `UFW_AUDIT_SHARE` env var for installed layout |
| `output.py` | All terminal display functions — banner, sections, findings, summary box |
| `registry.py` | `ServiceRegistry.load()` from `services.json` — declarative service definitions |
| `report.py` | `AuditReport` + `NullReport` — immediate flush on every write, no buffering |
| `scoring.py` | `ScoreEngine`, `CheckResult`, `Finding`, `Deduction`, `RiskLevel` |
| `checks/firewall.py` | `FirewallStatus` + `check_firewall()` |
| `checks/services.py` | `ServiceSnapshot` + `check_services()` + `Exposure` enum |
| `checks/ports.py` | `PortsSnapshot` + `check_ports()` + `PortCategory` enum |
| `checks/logs.py` | `LogsSnapshot` + `check_logs()` + `get_ip_geo()` + bruteforce detection |
| `checks/ddns.py` | `DdnsSnapshot` + `check_ddns()` + domain extraction per client type |
| `checks/docker.py` | `DockerSnapshot` + `check_docker()` + `ExposedPort` |

### Declarative service registry (`services.json`)

- 22 services defined declaratively — no hardcoded service logic in Python
- Each service carries: id, label, packages, systemd services, default ports, risk level, config_key, detection hints (binary, snap, config files)
- Adding a new service requires editing `services.json` only — no Python changes

### Internationalisation

- 183 translation keys in `en.json` and `fr.json` — full parity verified
- New `service_risk` section — 12 critical/high services with three keys each: `level`, `exposure`, `threat`
- `UFW_AUDIT_SHARE` environment variable — locales and `services.json` read from the installed share directory in production, from the source tree in development

### Bug fixes (post first run)

| # | Problem | Fix |
|---|---|---|
| 1 | Banner misaligned — badge width hardcoded | `_build_logo()` — dynamic badge width from content |
| 2 | No blank line before section boxes | `print()` added at the start of `print_section()` |
| 3 | Summary box `⚠  :` — colon on empty value | Conditional separator in `print_summary_box()` |
| 4 | WireGuard shown as "unknown state" | Template service `wg-quick@` with no instance → `INACTIVE_DISABLED` |
| 5 | DNS port reported twice | `reported_system_ports` set — deduplicates by `(port, proto)` |
| 6 | Listening ports list absent from terminal | `ss_output` now printed to terminal in ports overview section |
| 7 | Config path shows `/root/` under sudo | `_get_user_home()` via `SUDO_USER` + `pwd.getpwnam()` |
| 8 | `ModuleNotFoundError: ufw_audit` | Entry point uses parent of `LIB_DIR` in `sys.path`, not `LIB_DIR` itself |

### Documentation

- **`README.md`** — complete user documentation for v0.9.0 (English): features, service table, requirements, installation, usage, options reference, file locations
- **`README_DEV.md`** — developer documentation (English): architecture, project structure, running tests, adding a service, adding a language, code conventions, execution flow, scoring system, internationalisation

---

## [v0.8.0] — 2026-03-20

### IP geolocation in UFW log analysis

- **`get_ip_geo()`** — new function resolving country and operator for any IP address via `whois`
- Private/loopback ranges (`10.x`, `192.168.x`, `172.16-31.x`, `127.x`) returned as "réseau local" / "local network" without network query
- Results cached in `GEO_CACHE[]` — each IP looked up only once per run
- Geolocation displayed in terminal on top source IP and bruteforce hits
- Geolocation displayed in detailed report (`-d`) on full top-10 IP table and bruteforce table
- If `whois` is not installed: single informational note displayed, audit continues normally without geo data

---

## [v0.7] — 2026-03-20

Major release — risk classification overhaul, UFW log analysis, DDNS/external exposure detection, new services, and multiple bug fixes.

### Risk classification overhaul

- **New risk levels** — 7 services reclassified based on two-axis framework (exposure surface + potential threat):
  - SSH Server, VNC Server, MySQL/MariaDB, PostgreSQL, Redis → `critical` (was `high`)
  - Cockpit, Home Assistant → `high` (was `medium`)
- **`get_risk_context()`** — new function returning exposure and threat strings per service (FR + EN); covers all `high` and `critical` services
- **`log_risk_context()`** — displays risk context block in terminal and log for active `high`/`critical` services (skipped for `inactive_disabled`)
- **`finalize_log()`** — new `[RISK CONTEXT]` section in detailed report listing all detected `high`/`critical` services with full two-axis context; inactive/disabled services excluded

### UFW log analysis — `audit_ufw_logs()`

- New dedicated section parsing `/var/log/ufw.log`
- Supports both syslog (`Mar 19 10:23:14`) and systemd ISO (`2026-03-19T18:20:08`) formats
- Fast single-pass `awk` filtering by date — no `date` subprocess per line
- Configurable period via `--log-days=N` (default: 7)
- Terminal summary: total blocked attempts, top source IP, top targeted port, bruteforce detection, attempts on installed service ports
- Detailed report: full top-10 tables for IPs and ports
- Bruteforce detection: >10 attempts from same IP on same port within 60 seconds

### DDNS / external exposure detection — `audit_ddns()`

- New section detecting active DDNS clients: ddclient, inadyn, No-IP DUC, DuckDNS script
- Extracts configured domain from client config file
- Crosses active DDNS with unrestricted UFW `ALLOW` rules to identify internet-exposed ports
- Identifies high/critical services among exposed ports
- Score: −1 global if DDNS active + open ports (not per port)
- Conseil Fail2ban displayed when exposure is detected
- Detailed report section included

### New services (4)

- **Nextcloud** — `high`; snap + apt detection; two-axis risk context
- **Gitea / Forgejo** — `medium`; binary + systemd + apt detection; port auto-detected from `app.ini`
- **Mosquitto (MQTT)** — `high`; `fixed` ports 1883/8883; two-axis risk context
- **Syncthing** — `medium`; port auto-detected from `config.xml`

### Detection improvements

- **`is_package_installed()`** — extended beyond dpkg: snap packages (`snap list`) and binary installations (gitea, forgejo)
- **`get_service_state()`** — snap service state detection via `snap services`
- **`AUDITED_PORTS[]`** — ports processed by `audit_services()` now excluded from `check_listening_ports_analysis()` — eliminates duplicate port reporting

### --fix improvements

- **Sort ufw delete commands in descending rule number order** — prevents renumbering failures when deleting multiple rules sequentially
- **`eval "$CMD" < /dev/null`** — prevents blocking on interactive prompts

### Scoring

- **`IMPLICIT_POLICY_SVCS[]`** — tracks `high`/`critical` services with no explicit UFW rule; displayed as a contextual note under the summary phrase (no score penalty)
- **Mosquitto** correctly added to implicit policy note when active without explicit rule

### Bug fixes

- UFW version `N/A` in report header — `grep -oE` now applied to full `ufw version` output, not just `head -1`
- `grep -c` replaced by `wc -l` in log analysis — prevents `0\n0` arithmetic errors on some grep versions
- `mawk` compatibility — `awk` date filtering rewritten using `substr()` instead of `match()` with capture groups
- WireGuard `inactive_disabled` no longer shown in risk context (terminal or report)

### README

- Service table updated with `Basis` column explaining risk classification
- Note added distinguishing validated services from implemented-but-untested services
- Beta tester call to action with GitHub issue link

---

## [v0.6.1] — 2026-03-19

Patch release — bug fix for interactive port prompt.

### Bug fix

- **`resolve_ports()` — `ask` config_key now saves port after first prompt** — services with `config_key=ask` (Nginx, Apache, VNC, qBittorrent, Home Assistant) were asking for the port on every run instead of saving the answer. The fix converts `ask` into a stable key derived from the service label (e.g. `nginx_web_server_port`) and saves it to `~/.ufw_audit.conf` like any named key. Subsequent runs read the saved value without prompting. `--reconfigure` correctly clears these dynamic keys.

---

## [v0.6] — 2026-03-19

Major release — Docker analysis, new services, JSON export, --fix mode, contextual scoring improvements, and false positive fixes.

### New: --fix mode

- **`run_fixes()`** — interactive fix section displayed after the summary when `--fix` is passed
- Each `action` item with an automatable command gets a `[y/N]` prompt
- Items without a safe automated fix (e.g. firewall disabled) are shown as `[manual]` with no execution
- `--fix --yes` applies all fixes without confirmation
- `eval "$CMD" < /dev/null` prevents blocking on interactive prompts (e.g. `ufw delete`)
- `sudo ufw --force delete` used for rule deletion to suppress UFW confirmation

### New: Docker analysis

- **`audit_docker()`** — dedicated section after network services:
  - Detects if Docker is installed and active
  - Checks `daemon.json` for `"iptables": false` — OK if present, ALERT if absent (UFW bypass risk)
  - Lists running container ports via `docker ps` and checks for explicit UFW DENY coverage
  - Container ports without DENY shown as `improvement` (no extra score — already counted by port section)
  - Removes duplicate `log_section` call that generated spurious blue frame inside Docker section

### New: JSON export

- **`export_json()`** — two modes:
  - `--json` : summary (score, risk, context, categorised items, score breakdown)
  - `--json-full` : adds listening ports and UFW rules
- Output always on stdout; file `.json` written alongside `.log` when `-d` is active
- Pretty-printed via `python3 -m json.tool` when available

### New services (5)

- **WireGuard VPN** — `wg-quick@` template service detection; `fixed` port 51820/udp; contextual message (VPN exposure is intentional)
- **Redis** — `fixed` port 6379/tcp; warns if bound outside localhost; INFO when correctly on 127.0.0.1
- **Jellyfin** — `fixed` port 8096/tcp
- **Plex Media Server** — `fixed` port 32400/tcp
- **Home Assistant** — `ask` port 8123/tcp; two-factor authentication reminder when internet-facing

### New: --no-color

- **`setup_colors()`** — replaces static ANSI variable definitions; called after argument parsing
- All colour variables set to empty strings when `--no-color` is passed
- Detected in first-pass argument loop so colours are never emitted even in early error messages

### Scoring improvements

- **Firewall inactive → score capped at 3** — `FW_INACTIVE` flag set in `check_firewall_status()`, cap applied in `show_summary()` after all `score_deduct()` calls complete; annotated in score breakdown with `⚠` marker
- **Open incoming policy → −3** (was −2) — `--no-score` + manual `score_deduct 3` to override default ALERT penalty
- **IPv6 without rules** — WARN and −1 only when UFW rules exist; silent OK on fresh installs with no rules configured

### Summary improvements

- **Implicit policy note** — shown after the interpretation phrase when score is clean but `high`/`critical` services rely on default `deny` policy rather than explicit rules; lists affected services; suppressed when actions are pending
- **Score cap annotation** — `⚠ score capped at 3 — firewall disabled` displayed in score breakdown as a distinct entry (yellow `⚠`, no `-X` prefix)

### False positive fixes

- **`AUDITED_PORTS[]`** — ports processed by `audit_services()` are registered and skipped in `check_listening_ports_analysis()`, eliminating duplicate port reporting (e.g. Redis 6379, Samba 445/139)
- **`get_service_state()`** — handles systemd template services (`wg-quick@*`); falls back to `wg` binary check for WireGuard when no unit is loaded
- Redis, Jellyfin, Plex changed from `auto`/`ask` to `fixed` — eliminates interactive port prompts for services with standard ports

### Security hardening

- **`chmod 600`** applied to `~/.ufw_audit.conf` on creation (`config_load`) and on every write (`config_set`)

### New CLI flags

- `--fix` — propose fixes after audit
- `--yes` — apply all fixes without confirmation (requires `--fix`)
- `--no-color` — disable ANSI colour output
- `--json` — export summary as JSON
- `--json-full` — export full audit as JSON


---

## [v0.5] — 2026-03-13

Major release — audit engine overhaul, contextual scoring system, and redesigned summary.

### Audit engine — new checks

- **`check_ufw_duplicates()`** — detects duplicate UFW rules (same port, action, and source)
- **`check_ufw_allow_any()`** — detects `allow from any` rules without port restriction (critical risk)
- **`check_ipv6_consistency()`** — verifies consistency between the system's IPv6 state and corresponding UFW rules
- **`check_listening_ports_analysis()`** — unified listening port analysis (replaces two separate sections):
  - ports bound to `0.0.0.0` with no UFW rule → ALERT
  - NetBIOS 137/138 (Samba) bound to `0.0.0.0` with no rule → WARNING with contextual message (low risk behind NAT)
  - ports bound to a specific local IP → INFO
  - ephemeral ports (>32767) → silently skipped
  - known system ports (DNS 53, DHCP 67/68, mDNS 5353, CUPS 631) → informational only, no score impact

### Contextual scoring

- **`detect_network_context()`** — detects whether the machine is directly internet-exposed (public IP on a local interface) or behind NAT
- **`score_deduct()`** — replaces direct score manipulation in `log()`:
  - public context: penalties doubled (WARN −2, ALERT −4), capped at −4
  - local context: WARN −1, ALERT −2
  - duplicate rules: −1 regardless of context
- **`log()`** — two new optional parameters:
  - `--no-score`: disables score deduction for correctly configured services (e.g. Samba restricted to a specific IP)
  - `--nature=action|improvement|structural`: categorises each WARN/ALERT for the summary

### Redesigned summary

- **3 distinct blocks** in the summary:
  - `Action required` — items needing immediate attention
  - `Possible improvements` — optional hardening steps
  - `Normal configuration` — expected warnings for this type of system (local Samba, NetBIOS, etc.)
- **Interpretation phrase** generated automatically based on item composition:
  - no issues → *"Your configuration is healthy."*
  - structural only → *"Warnings reflect normal configuration for this type of system."*
  - mixed → *"Most of your configuration is normal. Address items marked Action required."*
  - action only → *"Corrections are needed."*
- **Network context** displayed in summary (🏠 local network / ⚡ public IP)
- **Score breakdown**: each deduction listed with its truncated reason and public IP context annotation if applicable

### False positive fixes

- `analyze_port_exposure()` — rewrote `ufw status numbered` parsing (extracts the `From` column via `awk $NF` instead of the `from [0-9]` regex that failed against the actual format)
- A specific IP (e.g. `192.168.1.10:137`) is no longer treated as exposed on `0.0.0.0`
- Port deduplication: a single port can no longer generate multiple log entries for the same exposure
- Ephemeral and system ports no longer produce spurious WARN/ALERT entries

### Internationalisation

- 25 new `t()` keys added (FR + EN):
  - sections: `sec_ports_analysis`, `sec_rules`
  - categorised summary: `sum_cat_action`, `sum_cat_improvement`, `sum_cat_structural`
  - interpretation: `sum_interp_clean`, `sum_interp_structural`, `sum_interp_mixed`, `sum_interp_action`
  - network context: `ctx_label`, `ctx_public`, `ctx_local`
  - ports: `uncov_alert`, `uncov_info`, `uncov_none`, `uncov_fix`, `uncov_sysport`, `uncov_ephemeral`
  - NetBIOS: `ports_netbios_warn`, `ports_netbios_fix`
  - scoring: `score_breakdown`, `score_pub_penalty`
  - rules: `dup_found`, `any_found`, `ipv6_*`

### Technical

- `build_listen_map()` — pre-aggregates all `ss` output in a single pass; worst-case wins (`exposed` overrides `local`, never the reverse)
- `log()` refactored to parse all positional arguments from position 4 onwards (multi-flag support)
- `AUDIT_ITEMS[]` — global array recording each WARN/ALERT as `level|nature|message`
- `SCORE_BREAKDOWN[]` — global array of score deductions for display in the `-d` report
- New global variables: `PUBLIC_IP`, `HAS_PUBLIC_IP`, `NETWORK_CONTEXT`, `AUDIT_ITEMS`, `SCORE_BREAKDOWN`

---

## [v0.4] — 2026-03-04

Major feature release — service-aware audit engine, internationalisation, and visual overhaul.

### New features

- **Internationalisation system** — `t()` function centralises all user-visible strings;
  `--french` flag switches the entire interface to French at runtime
- **ASCII banner** — coloured block-art header with system info box (distro, host, UFW
  version, user, date)
- **Service registry** — 13 known network services tracked: SSH, VNC, Samba, FTP,
  Apache, Nginx, MySQL/MariaDB, PostgreSQL, Transmission, qBittorrent, Avahi, CUPS,
  Cockpit
- **Per-service audit engine** — `audit_services()` detects installed packages,
  checks systemd state, resolves ports, and classifies UFW exposure as
  `open_world` / `open_local` / `deny` / `no_rule`
- **Contextual explanations and recommendations** — `get_risk_explanation()` and
  `get_recommendation()` return tailored, bilingual guidance per service and per
  exposure situation
- **Port resolution pipeline** — `resolve_ports()` tries in order: saved config →
  auto-detection from config files → interactive prompt; custom ports are
  persisted to `~/.ufw_audit.conf`
- **Persistent port configuration** — `config_load/get/set/delete_key()` manage a
  per-user config file; `--reconfigure` flag forces re-asking all custom ports
- **Distribution detection** — `detect_distro()` warns if the system is not
  Debian/Ubuntu-based
- **Rich terminal formatting** — `log_section()`, `log_service_header()`,
  `log_detail()`, `log_recommendation()`, and `banner_row()` (ANSI-aware padding)

### Changes and improvements

- `log()` refactored: now emits an icon (`✔ ⚠ ✖ ℹ`) alongside the prefix; prefix
  is localised in French mode (`[ATTENTION]`, `[ALERTE]`, `[ERREUR]`)
- ANSI colour variables switched to `$'...'` syntax — fixes literal `\e[32m` being
  printed instead of actual colour codes
- `check_firewall_status()` replaces `check_firewall()` — now reads the default
  incoming policy and reports it explicitly
- `init_logfile()` absorbs `init_log_header()` — log header now includes distro,
  kernel, UFW version, user, port config path, and active language
- `get_recommendation()` replaces `generate_recommendation()` — recommendations are
  now per-service and per-situation rather than keyword-matched
- Real user home resolved via `$SUDO_USER` so `~/.ufw_audit.conf` is written to the
  invoking user's home, not root's
- Help updated with `--french` and `--reconfigure` options
- All code comments translated to English

---

## [v0.3] — 2026-02-22

- Fully stable release with root-check refinement:
  - Help (`-h`) and version (`-V`) can now be displayed without sudo
  - Root privileges required only when performing actual audit
- Added `-V/--version` option to display script version
- Enhanced logging system:
  - Recommendations automatically added for WARN and ALERT entries in detailed mode
  - Log header now includes "Audit initiated by" field
  - Final log section with summary and recommended actions
- Dependency check improved:
  - Distinguishes mandatory (`ufw`) and optional (`ss` / `netstat`) dependencies
  - Provides clear install instructions for missing dependencies
- Listening port analysis now:
  - Uses `ss` or `netstat` safely depending on availability
  - Verbose and detailed logs separated
  - Counts listening ports and highlights public exposure
- `AUDIT_REQUESTED` flag introduced to track when an audit is actually being performed
- `is_detailed()` helper function added to simplify detailed-log checks
- `finalize_log()` function added to neatly append audit summary and recommendations
- Improved modularity and readability without changing any scoring or existing feature
- Maintains full backward compatibility with v0.2 behavior

---

## [v0.2.1] — 2026-02-20

- Internal security hardening and defensive coding improvements
- Added locale normalization (LC_ALL=C.UTF-8) for consistent command parsing
- Improved root privilege handling (help accessible without sudo)
- Reworked argument parser with strict unknown option detection
- Secured logging system to prevent writes when logfile is undefined
- Added safe fallback for listening port detection (ss → netstat)
- Replaced unsafe eval usage in logfile path resolution
- Improved UFW status handling to avoid false positives when command output is empty
- Prevented unexpected exits by replacing hard exit in firewall check with controlled return
- Strengthened conditional checks for empty variables and missing files
- Improved overall execution resilience without altering scoring logic
- Maintained full backward compatibility with v0.2 behavior
- No feature removals

---

## [v0.2] — 2026-02-19

- Major internal hardening and stability improvements
- Added safe interruption handling (Ctrl+C trap)
- Introduced dependency verification system before execution
- Improved error resilience with set -o pipefail and controlled exit behavior
- Secured logging mechanism to prevent undefined logfile writes
- Added fallback mechanism for network socket detection (ss → netstat)
- Improved internal command safety and variable handling
- Enhanced execution robustness without altering scoring logic
- Maintained full backward compatibility with v0.1.1 behavior
- Added minimal vs. detailed log selection (-d for detailed, minimal by default)
- Verbose terminal output (-v) now separated from log detail level
- Option -h (help) accessible without root privileges
- No functional changes or feature removals

---

## [v0.1.1] — 2026-02-17

- Added root privilege check at startup
- Script renamed to `ufw_audit.sh` for consistency
- Improved logging: each message is saved to the log
- Optimized analysis of sensitive ports and UFW rules
- Added system information in the log (hostname, UFW version, kernel)
- Clearer and standardized messages for alerts, warnings, and notes
- Minor fixes for compatibility and readability

---

## [v0.1] — 2026-02-15

- First stable release of the script
- Basic UFW audit
- Counting of OK, WARNING, and NOT OK statuses
- Full log of rules and listening ports
- Options: `-v/--verbose` and `-h/--help`
- Detection of "Anywhere" rules and sensitive ports
- Security summary with score and risk level