# Changelog

All notable changes to this project are documented here.

## [v0.1] - 2026-02-15
- First stable release of the script
- Basic UFW audit
- Counting of OK, WARNING, and NOT OK statuses
- Full log of rules and listening ports
- Options: `-v/--verbose` and `-h/--help`
- Detection of “Anywhere” rules and sensitive ports
- Security summary with score and risk level

## [v0.1.1] - 2026-02-17
- Added root privilege check at startup
- Script renamed to `ufw_audit.sh` for consistency
- Improved logging: each message is saved to the log
- Optimized analysis of sensitive ports and UFW rules
- Added system information in the log (hostname, UFW version, kernel)
- Clearer and standardized messages for alerts, warnings, and notes
- Minor fixes for compatibility and readability

## [v0.2] - 2026-02-19

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

## [v0.2.1] - 2026-02-??

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

## [v0.3] - 2026-02-22
- Fully stable release with root-check refinement:
  - Help (`-h`) and version (`-V`) can now be displayed without sudo
  - Root privileges required only when performing actual audit
- Added `-V/--version` option to display script version
- Enhanced logging system:
  - Recommendations automatically added for WARN and ALERT entries in detailed mode
  - Log header now includes “Audit initiated by” field
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

## [v0.4.0] - 2026-03-04

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