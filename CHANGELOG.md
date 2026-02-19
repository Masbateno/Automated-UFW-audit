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