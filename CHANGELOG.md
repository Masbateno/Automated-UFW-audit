*[Lire en français](CHANGELOG_FR.md)* · *[Full changelog](DOCUMENTS/CHANGELOG_FULL.md)*

# ufw-audit — Changelog

| Version | Date | Summary |
|---------|------|---------|
| [v1.25.0](#v1250) | 2026-04-26 | CIS compliance mapping inline (`[CIS:X.Y.Z]` per finding, full ref in `--verbose`); best-practice prefix; `cis_refs.json` restructured; `get_cis_code()`; `explain_cis` removed from locales; 5 new services (SMTP, NFS, Jenkins, OpenVPN, Squid); `_ipt_has_conntrack` ACCEPT fix; FORWARD DROP/REJECT → OK; 4200/4200 tests (+60) |
| [v1.24.1](#v1241) | 2026-04-25 | Hotfix: Debian kernel parsing (`_KVER_RE` `[-+]`, ABI fallback, `linux-image-$(uname -r)` apt path); v1.24.0 changelog correction (INPUT ACCEPT → ALERT −3 pts); 4140/4140 tests (+6) |
| [v1.24.0](#v1240) | 2026-04-25 | CHECK 46 (iptables/nftables audit when UFW inactive); audit profile shown in banner; 5 new critical services (Telnet, RDP, MongoDB, Elasticsearch, Memcached); CRITICAL/HIGH installed-but-inactive → ⚠ + risk context; kernel apt update check; 4134/4134 tests (+92) |
| [v1.23.0](#v1230) | 2026-04-24 | `--format=FORMAT` unified output; `--check=list`; `--manage-logs` preview + summary mode; `[CRITIQUE • LAN]` scope qualifier; `--install-cron`/`--manage-cron` curses TUI; `_tty.py` raw-mode reader; `compare.py` `None`/`[]` fix; `tests/helpers.py` + 62-file migration; 4042/4042 tests (+35) |
| [v1.22.3](#v1223) | 2026-04-20 | Bugfixes: interface-scoped ports excluded from exposure (67/udp%virbr0); ephemeral UDP filter in exposure; `ufw status verbose` displayed in rules section (-v mode); 4007/4007 tests (+2) |
| [v1.22.2](#v1222) | 2026-04-20 | Bugfixes: snakeoil cert filter now covers nginx/apache/postfix paths; DDNS reflected in internet exposure view; high-numbered listen ports shown in exposure table; double `ℹ` prefix removed from SSH notes; 4004/4004 tests (+3) |
| [v1.22.1](#v1221) | 2026-04-20 | `recurrence.py` float policy unified (`update_recurrence` now normalizes like `load_recurrence`); `import os` removed; test suite hardening (+5 tests); 4001/4001 tests |
| [v1.22.0](#v1220) | 2026-04-20 | Signal correlation engine (5 compound-risk rules); recurring finding tracker; port exposure analysis; comparative report finding-key diff; IPv6 link-local false-positive fix; snakeoil cert filter; `--explain` 87→112 keys; kernel duplicate-kernel message fix; `backup` domain moved to `disk`; quality pass (compare, display, runner, domain_scores); 3996/3996 tests (+218) |
| [v1.21.0](#v1210) | 2026-04-19 | CHECK 43 (TLS/SSL cert expiry); CHECK 44 (systemd timers); CHECK 45 (firmware & microcode); `--html` standalone HTML export; `--check`/`--skip` run-only/exclude checks; `--output-dir`; SSH context note bug fix; quality pass (firmware + systemd_timers); 3778/3778 tests (+284) |
| [v1.20.0](#v1200) | 2026-04-18 | CHECK 40 (UFW logging level); CHECK 41 (system umask); CHECK 42 (auth.log login analysis); score history (`--history` + sparkline); ignore list (`--ignore`/`--show-ignored`/`ignore.yml`); process-aware system port classification; auth_log `days=0` fix; 3494/3494 tests (+235) |
| [v1.19.0](#v1190) | 2026-04-17 | SSH `PermitRootLogin` OK cases (no/prohibit-password/forced-commands-only); SUID scan performance (targeted roots); IoT dominance display fix; domain score labels i18n; hardening: 6 new sysctl checks (tcp_syncookies, accept_source_route, accept_redirects_v6, send_redirects, protected_hardlinks, protected_symlinks); SGID whitelist expansion; 3259/3259 tests (+530) |
| [v1.18.0](#v1180) | 2026-04-16 | CHECK 34 (AppArmor/SELinux MAC policy); CHECK 35 (backup solution audit); kernel listing (always shown); profile override fix (nature cleared on INFO downgrade); summary box cleanup (structural section removed); profile pass (desktop 6 overrides, container 12 skip_sections); `--explain` 76→86 keys; bash-completion Debian fix; `--manage-logs` UX (move prompt + multi-dir view); 2729/2729 tests |
| [v1.17.0](#v1170) | 2026-04-15 | CHECK 31 (auditd); CHECK 32 (Secure Boot); CHECK 33 (file integrity AIDE/Tripwire); `--explain` profile variants (17 keys); `workstation` → `desktop` profile; Trusted Publishing; `cmd_type` fix/check; IPv6 avahi fix; journald fallback; sysctl persistence; UX improvements; 2507/2507 tests |
| [v1.16.0](#v1160) | 2026-04-12 | CHECK 19 (desktop app detection); CHECK 28 (NTP sync); CHECK 29 (Fail2ban standalone); CHECK 30 (rootkit/integrity scan); `--target N` → exit code 4; CLI validation for empty values; 5 thematic group headers; fail2ban moved out of hardening; 2292/2292 tests |
| [v1.15.1](#v1151) | 2026-04-12 | Hotfix: bash-completion — `--explain` no longer gets trailing `=`; `compopt -o nospace` for value options |
| [v1.15.0](#v1150) | 2026-04-12 | CHECK 26 (IoT/local source dominance in UFW logs); CHECK 27 (SMTP local exposure); `--fix` dry-run by default, `--apply` to execute; `--target N` score cible; `--explain` TUI: clamped nav, in-curses detail screen, ESC/q fix; `--explain` 73→77 keys; quality pass `smtp.py`; 2139/2139 tests |
| [v1.14.0](#v1140) | 2026-04-10 | Samba Security Audit (CHECK 24, 6 findings); ClamAV Antivirus Audit (CHECK 25, DB freshness + scan age); `--diff` info_count fix; `--explain` 63→73 keys (17 groups); quality pass; 2045/2045 tests |
| [v1.13.0](#v1130) | 2026-04-10 | Disk health audit (CHECK 22, SMART + partitions, new `disk` domain); Memory & Swap (CHECK 23, SSD wear, swappiness); NVMe support; partition progress bar; `--explain` 33→63 keys (15 groups); quality pass; 1890/1890 tests |
| [v1.12.0](#v1120) | 2026-04-10 | CLI pass + 4 Debian VM fixes (risk context all services, GeoIP mkdir, unattended workstation, expired dates); 1703/1703 tests |
| [v1.11.0](#v1110) | 2026-04-07 | `--explain` A2 (+13 keys, 20→33); user account audit (CHECK 17); password policy audit (CHECK 18); quality pass; 1675/1675 tests |
| [v1.10.0](#v1100) | 2026-04-07 | `--explain` hint in summary box; kernel module audit (CHECK 14); cron job audit (CHECK 15); service state audit (CHECK 16); quality pass (source + 9 test files); 1541/1541 tests |
| [v1.9.0](#v190) | 2026-04-06 | System updates audit (CHECK 13); `--explain KEY` with CIS refs; webhooks; domain scores; `--diff`; 1332/1332 tests |
| [v1.8.0](#v180) | 2026-04-06 | SSH security audit (CHECK 11); sensitive files & sudoers (CHECK 12); i18n fix; INFO verbose detail; 1104/1104 tests |
| [v1.7.0](#v170) | 2026-04-04 | Audit profiles; `Deduction.key`; multi-email cron; multi-delete cron; `--reset-baseline`; ephemeral-port filter; 966/966 tests |
| [v1.6.0](#v160) | 2026-04-04 | Hardening check; IPv6 consistency check; comparative report; plugin API; 926/926 tests |
| [v1.5.0](#v150) | 2026-04-04 | Firewall Stack Analysis; Network Context; enriched banner; code quality pass (12 modules hardened); 766/766 tests |
| [v1.4.2](#v142) | 2026-04-04 | Hotfix: NetBIOS 137/138 still warned when UFW rule exists |
| [v1.4.1](#v141) | 2026-04-04 | Hotfix: `--install-completion` missing from bash completion suggestions |
| [v1.4.0](#v140) | 2026-04-04 | UFW default deny awareness; `__main__.py` split into 4 modules; hardening pass (11 fixes); 676/676 tests |
| [v1.3.0](#v130) | 2026-03-31 | i18n completeness (all deduction reasons translated); `--offline` mode; IPv6 network detection; 3-provider IP fallback chain |
| [v1.2.1](#v121) | 2026-03-31 | Packaging cleanup: `install.sh` removed; `pyproject.toml` fixes (LICENSE, classifier, URLs) |
| [v1.2.0](#v120) | 2026-03-30 | Code quality pass: 12 defensive fixes across 8 modules — no behaviour changes |
| [v1.1.1](#v111) | 2026-03-30 | Hotfix: Avahi (mDNS) shows ✖ in panorama despite being covered by default deny policy |
| [v1.1.0](#v110) | 2026-03-30 | Summary box redesigned (word-wrap + fix commands + disclaimer); vsftpd/Transmission port detection fixed; internal code quality pass |
| [v1.0.4](#v104) | 2026-03-29 | Hotfix: ephemeral ports still shown in LISTENING PORTS OVERVIEW (display layer) |
| [v1.0.3](#v103) | 2026-03-29 | Hotfix: hundreds of ephemeral UDP port messages flooding output (Samba/busy desktop) |
| [v1.0.1](#v101) | 2026-03-29 | Hotfix: SSH on non-standard port not detected; TCP high ports wrongly classified as ephemeral |
| [v1.0](#v10) | 2026-03-29 | PyPI packaging, `--install-completion`, Python 3.9+, install.sh deprecated |
| [v0.22.1](#v0221) | 2026-03-29 | Hotfix: firewall detected inactive on French-locale systems |
| [v0.22](#v022) | 2026-03-29 | 5 modules refactored, box-border alignment fixed, `CheckResult` cleanup |
| [v0.21](#v021) | 2026-03-28 | 619/619 tests — CGNAT/IPv6 false-positive fixes, `--manage-cron` email book |
| [v0.20](#v020) | 2026-03-28 | 548/548 — 17 degraded-mode tests (`ss`/rules/log absent) |
| [v0.19](#v019) | 2026-03-28 | GitHub Actions CI — Python 3.8/3.10/3.12 matrix |
| [v0.18](#v018) | 2026-03-28 | 531/531 — 26 new tests for `fixes.py` |
| [v0.17](#v017) | 2026-03-28 | 505/505 — 15 pre-existing failures fixed; two code bug fixes |
| [v0.16](#v016) | 2026-03-28 | Panorama false-positives: `NOT_LISTENING` + `LOOPBACK_NO_RULE` fixed |
| [v0.15.1](#v0151) | 2026-03-27 | Install script: transactional rollback; fix UI cleaner |
| [v0.15](#v015) | 2026-03-27 | Security audit (8 fixes), DRY refactor, IPv6 wildcard detection fixed |
| [v0.14.1](#v0141) | 2026-03-26 | False positives: loopback Redis, DDNS system ports, VERSION banner |
| [v0.14](#v014) | 2026-03-25 | `__main__.py` 1820→481 lines — 5 new modules extracted |
| [v0.13](#v013) | 2026-03-24 | Multi-cron scheduler, `--manage-cron` TUI, 40+ cron tests |
| [v0.12](#v012) | 2026-03-24 | HTML email reports, zero-dependency markdown→HTML |
| [v0.11.4](#v0114) | 2026-03-23 | Open-any regex fixed, critical services→Action required, `TESTING.md` |
| [v0.11.3](#v0113) | 2026-03-23 | `--install-cron`, `--manage-logs`, services panorama, auto-fix banner |
| [v0.11.2](#v0112) | 2026-03-22 | Banner redesigned (Doom ASCII art), port messages rewritten |
| [v0.11.1](#v0111) | 2026-03-22 | Security patch: 20 vulnerabilities fixed |
| [v0.11](#v011) | 2026-03-22 | Field-tested (Mint/Debian/Kali), `--quiet`, virtualisation detection |
| [v0.10](#v010) | — | GeoIP2 geolocation, short CLI flags, score scope disclaimer |
| [v0.9](#v09) | — | Complete Python rewrite, 421 tests, 22 services, bilingual EN/FR |

---

## v1.25.0

**2026-04-26**

### Features

- **CIS compliance mapping inline** — each finding with a formal CIS code now shows `[CIS:X.Y.Z]` (dimmed) in the summary box; best-practice entries (no formal section number) are left unlabelled
- **`--verbose` CIS ref text** — full CIS reference string displayed dimmed after each WARN/ALERT finding line (e.g. `CIS Ubuntu 22.04 L1 — 5.2.7 — Ensure SSH MaxAuthTries is set to 4 or less`)
- **Best-practice entries renamed** — 34 entries without a CIS section number (virtualisation bypass, SSH public-key, etc.) now use the prefix `"Best practice — ..."` instead of the misleading `"CIS ..."` prefix; `get_cis_ref()` returns the appropriate string for each category
- **`cis_refs.json` restructured** (`data/cis_refs.json`) — each entry is now `{"ref": "...", "code": "CIS:X.Y.Z"|null}` instead of a flat string; 133 entries total: 99 CIS Ubuntu 22.04 (`code: "CIS:X.Y.Z"`), 4 CIS Docker (`code: "CIS Docker:X.Y"`), 34 best-practice (`code: null`)
- **`get_cis_code()`** (`cis_refs.py`) — new function returning the short machine-readable code (e.g. `"CIS:5.2.7"`, `"CIS Docker:5.4"`) or `None` for best-practice entries
- **`explain.py` CIS refs decoupled from locale** — `run_explain()` and the curses TUI now call `get_cis_ref(key)` directly instead of `t("explain_cis.{key}")`; the `explain_cis` section (170 strings) has been removed from `en.json` and `fr.json`
- **5 new services** (`data/services.json`) — SMTP/Postfix/Exim (25/tcp, high), NFS Server (2049/tcp+udp, high), Jenkins (8080/tcp, high), OpenVPN (1194/udp, medium), Squid Proxy (3128/tcp, medium); registry now covers **32 services**
- **`_ipt_has_conntrack` ACCEPT fix** (`checks/iptables_nftables.py`) — regex extended to require `-j ACCEPT` on the same line; previously `--ctstate ESTABLISHED,RELATED -j DROP` was incorrectly treated as a valid conntrack rule
- **FORWARD DROP/REJECT → `result.ok()`** (`checks/iptables_nftables.py`) — when FORWARD policy is DROP or REJECT, emits ✔ [OK]; symmetric with INPUT; locale key `forward_ok` added

### Tests

| File | Change |
|------|--------|
| `tests/test_cis_refs.py` | new — 39 tests: `TestGetCisRef` (12), `TestGetCisCode` (11), `TestLoadCache` (4), `TestJsonSchema` (10), `TestNoStaleExplainCis` (2) |
| `tests/test_domain_scores.py` | `TestCISReferences` updated — `test_explain_cis_all_keys_resolve` accepts best-practice refs; `test_explain_cis_locale_independent` renamed |
| `tests/test_iptables_nftables.py` | `TestIptableParsers` (+2: conntrack DROP action false); `TestForwardPolicy` (+4: forward ok DROP/REJECT, ok level, no deduction) |
| `tests/test_services.py` | `TestNewServicesRegistry` (+15: smtp/nfs/jenkins/openvpn/squid — exists, risk, ports) |

✅ 4200/4200 unit tests (+60 from v1.24.1)

---

## v1.24.1

**2026-04-25**

### Fixes

- **Debian kernel version parsing** (`checks/kernel_modules.py`) — `_KVER_RE` extended from `[-]` to `[-+]` to parse Debian-style versions (`6.12.74+deb13+1-amd64`); `_kernel_sort_key` rewritten to handle absent numeric ABI group (Debian separates with `+`, not `-ABI`); `_query_apt_kernel_update` adds `apt-cache policy linux-image-$(uname -r)` as secondary primary path for Debian (no `linux-image-generic` meta-package); apt upgrade command generalised to `sudo apt upgrade`
- **v1.24.0 changelog correction** — INPUT ACCEPT → ALERT −3 pts (not WARN −1 pt); FORWARD ACCEPT remains WARN −1 pt; `iptables -S` (not `-L`) documented; "active backend" → "available firewall layer"

### Tests

| File | Change |
|------|--------|
| `tests/test_kernel_modules.py` | `TestKernelSortKey` (+2), `TestParseInstalledKernels` (+2), `TestKernelAptUpdate` (+2) — Debian sort key, `+` separator parsing, apt up-to-date on Debian |

✅ 4140/4140 unit tests (+6 from v1.24.0)

---

## v1.24.0

**2026-04-25**

### Features

- **CHECK 46 — iptables/nftables audit** (`checks/iptables_nftables.py`) — when UFW is inactive, audits the underlying firewall layer; detects available firewall layer (nft list ruleset or iptables -S rules); checks INPUT/FORWARD default policies (iptables -S / nft list ruleset); checks for ESTABLISHED/RELATED conntrack rule; INPUT ACCEPT → ALERT −3 pts; FORWARD ACCEPT → WARN −1 pt; conntrack absent → WARN −1 pt; gated on `not fw_status.active`
- **Audit profile in banner** — active profile (`server` / `desktop` / `container`) shown as ℹ [INFO] immediately after the banner header
- **5 new critical services** (`data/services.json`) — Telnet Server (23/tcp), RDP/xRDP (3389/tcp), MongoDB (27017/tcp), Elasticsearch (9200/tcp), Memcached (11211/tcp+udp); registry now covers **28 services**
- **Installed-but-inactive critical/high services** — packages installed but port not listening now emit `⚠ [ATTENTION]` (was `ℹ [INFO]`) and display the risk context block; `services.state.installed_inactive_critical` locale key; `runner.py` and `display.py` updated

### Fixes & improvements

- **UFW inactive context** — services section shows explicit context when UFW is off; NetBIOS ports downgraded to INFO; IPv6 check downgraded; "all ports covered" suppressed
- **`iptables_nftables.py` quality** — `nft add chain` → `nft chain`; conntrack regex requires `\baccept\b`; FORWARD `unknown` state → INFO
- **Kernel apt update check** (`checks/kernel_modules.py`) — `_query_apt_kernel_update()` checks apt for newer kernel; primary: `apt-cache policy linux-image-generic`; fallback: `apt list --upgradable`; ✔ [OK] when confirmed current; `apt_checked` flag

### Tests

| File | Change |
|------|--------|
| `tests/test_iptables_nftables.py` | new — 51 tests: INPUT/FORWARD policies, conntrack, nftables backend, unknown FORWARD, cmd assertions |
| `tests/test_kernel_modules.py` | `TestKernelAptUpdate` — +9 tests: update available, up-to-date OK, apt not checked |
| `tests/test_services.py` | `TestInactiveDisabled` (+5) + `TestPortExposureFindings` (+4) — critical/high inactive → warn |

✅ 4134/4134 unit tests (+92 from v1.23.0)

---

## v1.23.0

**2026-04-24**

### Features

- **`--format=FORMAT`** (`cli.py`) — canonical unified output flag accepting `json`, `json-full`, `csv`, `markdown`, `html`; legacy flags (`--json`, `-j`, `-J`, `--output csv/markdown`, `--html`) kept as silent aliases — zero breaking change
- **`--check=list`** (`cli.py`, `__main__.py`) — prints all 31 filterable section names without sudo; notes prefix matching (`kernel` matches `kernel_hardening` + `kernel_modules`) and always-on core checks; `--check=LIST` help line updated to mention discoverability
- **`--manage-logs` log preview** (`manage_logs.py`) — Enter on a log file opens a full scrollable viewer; `s` toggles between full log and summary mode (score block + ALERT/WARN findings only); `g`/`G` jump to top/bottom; `↑↓ / PgUp/PgDn` scroll; Esc returns to list
- **Risk context scope qualifier** (`display.py`) — `[CRITIQUE • LAN]`, `[MOYEN • LAN]`, `[FAIBLE • LAN]` appended to all service risk labels when `network_context == "local"`; public/DDNS contexts unchanged
- **`--install-cron` curses TUI** (`cron.py`) — `run_install_cron()` now wraps `curses.wrapper()` and falls back to the plain wizard when curses is unavailable; new `_run_install_cron_curses()` with inline readline (`_curses_readline`), Esc-to-cancel on every prompt, live schedule preview
- **`--manage-cron` curses TUI** (`cron.py`) — `run_manage_cron()` similarly dispatches to `_run_manage_cron_curses()` or `_run_manage_cron_plain()`; consistent UX with `--install-cron`
- **`ufw_audit/_tty.py`** — new raw-mode line reader (`read_line()`): Esc returns `None` (cancel), Enter returns `""` (confirm), printable chars buffered with echo; select-based escape-sequence drain distinguishes standalone Esc from arrow keys; graceful `input()` fallback in non-TTY environments (tests, pipes)

### Fixes

- **`compare.py` baseline `None` vs `[]` semantics** — `finding_keys` field now `list[str] | None`; `None` means pre-v1.22 baseline (key absent in JSON, skip diff to avoid false-positive flood); `[]` means legitimately empty clean audit (diff normally); `load_baseline()` returns `None` for absent key; `compute_delta()` guards on `is not None` instead of truthiness

### Polish

- **TUI help bar harmonization** — `--explain` picker `navigate` → `move`; `--explain` detail `↑↓/PgUp/PgDn` → `↑↓ / PgUp/PgDn`, `Esc: back to list` → `Esc: back`; preview log `PgUp PgDn` → `PgUp/PgDn`
- **Bash completion** — `--format=` with 5 value completions; `--check=` suggests `list` + all section names; `--html` added to `long_opts`
- **`history.py` atomic write** — `write_text()` replaced by `os.open()` + `os.fdopen()` + `os.replace()` ensuring 0o600 permissions and crash-safe rotation
- **`report_markdown.py`** — `_inline_format()`: link extraction now runs before `html.escape()` to prevent URL mangling (`&` → `&amp;`); `<li>` items wrapped in `<ol>` blocks in the audit-log-to-HTML converter; unused `import email` removed
- **Checks hardening** — `_C_LOCALE_ENV` passed to subprocess calls in `auth_log.py` and `logs.py`; `except Exception` narrowed to `(OSError, subprocess.SubprocessError, subprocess.TimeoutExpired)` in both; `timeout=10` added to `ssl_certs.py` cert-date subprocess; `removeprefix()` replaces `lstrip()` for regex anchors in `sysinfo.py`
- **`markdown_output.py`** — uses `engine.breakdown` instead of `getattr(engine, "_deductions", [])` for public API access to deductions

### Test suite hardening

- **`tests/helpers.py`** — new shared utilities module: `_t` (translation stub), `levels()`, `_has_finding()`, `_get_finding()`, `_finding_level()`, `_deduction_keys()`, `_deduction_points()`; 62 test files migrated to import from it, eliminating ~200 lines of duplicated boilerplate

### Tests

- `tests/test_cli.py` — `TestFormatFlag` (+22 tests): all 5 formats, space-separated form, invalid value, cross-flag conflicts, legacy alias backward-compat
- `tests/test_cli.py` — `TestCheckSkipFlags` (+4 tests): `--check=list`, `--check LIST`, case-insensitive, default false
- `tests/test_manage_logs.py` — `TestExtractSummaryView` (+7 tests): summary block extraction, ALERT/WARN inclusion, continuation lines, empty log fallback
- `tests/test_display_explain_hint.py` / `tests/test_runner.py` — scope qualifier (+2 tests): `is_local=True` appends `• LAN`; `build_risk_context_entries` with `network_context="local"`
- ✅ 4042/4042 unit tests (+35 from v1.22.3)

---

## v1.22.3

**2026-04-20**

### Bugfixes

- **`checks/ports.py`**: `_split_addr_port` now captures and returns the interface scope (`%iface`); `ListeningPort` gains `iface: str = ""` field; `is_all_interfaces` returns `False` when `iface` is set — fixes `0.0.0.0%virbr0:67` (dnsmasq/KVM) appearing as all-interfaces
- **`exposure.py`**: high-numbered UDP ports (`> 32767`) excluded from the exposed-ports set — mirrors the `EPHEMERAL` filter in `check_ports()`; prevents avahi/mDNS ephemeral sockets from polluting the exposure table

### Feature

- **`runner.py`**: `ufw status verbose` output displayed after the UFW rules findings in verbose mode (`-v`)

### Tests

- `tests/test_ports.py` — `TestSplitAddrPort`: updated for 3-tuple signature + `test_ipv4_virbr0_iface`; `TestListeningPort`: `test_is_all_interfaces_false_when_iface_scoped` (7 tests total in class)
- `tests/test_exposure.py` — `test_high_numbered_udp_port_excluded` added; `test_high_numbered_listen_port_is_shown` → `test_high_numbered_tcp_port_is_shown` (55 tests total)
- ✅ 4007/4007 unit tests (+2 from v1.22.2)

---

## v1.22.2

**2026-04-20**

### Bugfixes

- **`ssl_certs.py`**: snakeoil cert filter now applied globally after all paths are collected — previously only filtered `/etc/ssl/private`; nginx/apache/postfix references to snakeoil certs were not excluded
- **`exposure.py`**: `compute_exposure` now reflects DDNS activity (`ddns.warn` key) in the internet-facing row — shows `⚠ warn` instead of `✔ ok` when DDNS is active
- **`exposure.py`**: removed `port < 32768` ephemeral-port heuristic — LISTEN-state ports are always server ports regardless of port number
- **`runner.py`**: SSH non-standard port note and local-exposure note now printed as separate `print_info` calls — previously concatenated on one line causing garbled output
- **`locales/en.json`, `locales/fr.json`**: removed `ℹ ` prefix from `local_exposure_note` (double prefix with `print_info`); added `internet_facing_ddns` key

### Tests

- `tests/test_exposure.py` — `test_ephemeral_port_excluded` → `test_high_numbered_listen_port_is_shown` + `test_port_32768_is_shown`; +3 DDNS tests in `TestInternetFacing` (54 tests total)
- ✅ 4004/4004 unit tests (+3 from v1.22.1)

---

## v1.22.1

**2026-04-20**

### Source fix

- **`recurrence.py`**: unified float-tolerance policy — `update_recurrence` now normalizes floats to `int` (consistent with `load_recurrence`); removed unused `import os`

### Tests

- `tests/test_correlation.py` — +1 `test_message_uses_translation_key` (51 tests total)
- `tests/test_exposure.py` — `test_fw_policy_none_does_not_crash`: strengthened to `assert color == "alert"` (51 tests total)
- `tests/test_recurrence.py` — +1 `test_float_value_in_prev_is_normalized` (29 tests total)
- ✅ 4001/4001 unit tests (+5 from v1.22.0)

---

## v1.22.0

**2026-04-20**

### Signal correlation engine (`correlation.py`)

- `CorrelationRule`: `all_of` / `any_of` frozensets of finding keys; fires when `all_of ⊆ active` AND (`any_of` empty OR `any_of ∩ active ≠ ∅`)
- `run_correlations(engine, t)` → list of `CorrelatedFinding` (key, level, message, triggered_by)
- 5 built-in rules:
  - `corr.root_no_protection` — SSH PermitRootLogin + no Fail2ban → ALERT
  - `corr.password_auth_under_attack` — password auth enabled + brute-force detected → ALERT
  - `corr.ssh_root_password` — root login + password auth → ALERT
  - `corr.privilege_escalation` — NOPASSWD sudoers + unexpected SUID → WARN
  - `corr.stale_unmonitored` — security updates pending + no Fail2ban → WARN
  - `corr.fully_blind` — UFW logging off + no Fail2ban + no auditd → WARN
- 49 tests in `tests/test_correlation.py`

### Recurring finding tracker (`recurrence.py`)

- `load_recurrence()` / `save_recurrence()` — JSONL counters at `~/.config/ufw-audit/recurrence.json`
- `update_recurrence(prev, active_keys)` — increments per key; keys not present are dropped (resolved)
- Corrupted / negative values normalized to 0 before increment; empty-string keys and negative values filtered on load
- Atomic write with `tmp.unlink(missing_ok=True)` cleanup on failure
- 27 tests in `tests/test_recurrence.py`

### Port exposure analysis (`exposure.py`)

- Groups exposed listening services by interface scope and risk level
- `fw_policy` allowlist fix: uses `not in ("deny", "reject")` — unknown/None policy treated as permissive
- Direct `lp.port` attribute for ephemeral-port filter (was reparsing `port_proto` string)
- 43 tests in `tests/test_exposure.py`

### Comparative report — finding-key diff (`compare.py`)

- `AuditBaseline.finding_keys` — new field: sorted list of active ALERT/WARN keys saved with each baseline
- `AuditDelta.new_finding_keys` / `resolved_finding_keys` — keys that appeared or resolved since last audit
- Migration guard: when `prev.finding_keys` is empty (baseline pre-v1.22), key diff is skipped — prevents false-positive flood on first upgrade run
- `display_delta()` shows each new key (WARN) and each resolved key (OK)

### Bug fixes

- **Port exposure color (`exposure.py`)**: open ports colored `alert` when `fw_policy` is not `deny`/`reject` (was `"allow"` only — `"unknown"` and `None` incorrectly produced `warn`)

- **IPv6 false positive (`checks/ipv6.py`)**: `has_global_ipv6` field + `_read_global_ipv6()` parser; when UFW IPv6 is disabled and listeners exist but only link-local/ULA addresses are assigned, the WARN −2 pts is downgraded to INFO — the machine cannot be reached via IPv6 from the internet
- **Kernel obsolete message (`checks/kernel_modules.py`)**: when running kernel equals most-recent installed, the redundant "(running: X, latest: X)" parenthetical is suppressed — uses new `kernels_obsolete_same` locale key
- **Snakeoil cert (`checks/ssl_certs.py`)**: Debian/Ubuntu `ssl-cert-snakeoil.pem` filtered from `/etc/ssl/private` scan — system test certificate no longer triggers TLS audit
- **Implicit services warning (`display.py`)**: `implicit_svcs` message suppressed when `fw_policy` is `deny` or `reject` — default-deny policies already block undeclared services
- **SSH non-standard port note (`runner.py`)**: note "Non-standard port — reduced exposure to automated scanners" shown in service section when SSH runs on a non-22 port

### Quality pass

- **`domain_scores.py`**: `backup` domain moved from `hardening` to `disk` — backup solutions belong with disk health scoring
- **`explain.py`**: 87→112 keys (+25 across 7 new groups: Authentication Logs, Umask, Firewall Logging, TLS / SSL Certificates, Systemd Timers, Firmware, Docker)
- **`__main__.py`**: `fw_policy` passed through to `print_audit_summary`

### Tests

- `tests/test_correlation.py` — 49 tests (new)
- `tests/test_exposure.py` — 50 tests (new)
- `tests/test_recurrence.py` — 27 tests (new)
- `tests/test_ipv6.py` — +26 tests (`TestReadGlobalIPv6`: global unicast, link-local, ULA, loopback, monkey-patch `_run`)
- `tests/test_explain.py` — updated key count assertion (87→112)
- ✅ 3996/3996 unit tests (+218 from v1.21.0)

---

## v1.21.0

**2026-04-19**

### CHECK 43 — TLS/SSL certificate expiry (`checks/ssl_certs.py`)

- `SslCertsSnapshot`: scans certificate files from five sources — Let's Encrypt (`/etc/letsencrypt/live/*/fullchain.pem`), `/etc/ssl/private/*.{pem,crt,cert}`, nginx `ssl_certificate` directives, apache2 `SSLCertificateFile` directives, postfix `smtpd_tls_cert_file`
- `check_ssl_certs()`: expired cert → ALERT −2 pts; expires < 7 days → ALERT −2 pts; expires < 30 days → WARN −1 pt; valid cert → OK
- Total deduction capped at −4 pts regardless of how many certs are affected
- `_MAX_CERTS=30`, `_MAX_CONF_FILES=100`, `_MAX_CERT_SIZE=50 000 B` — guards against CA bundles and large deployments
- Quoted paths in nginx/apache config correctly stripped (`ssl_certificate "/path/to/cert.pem"`)
- Broken symlinks skipped gracefully
- 59 tests in `tests/test_ssl_certs.py`

### CHECK 44 — Systemd timers audit (`checks/systemd_timers.py`)

- `SystemdTimersSnapshot`: discovers all timer units via `systemctl list-timers --all --no-pager`; reads associated service unit files
- Pipe-to-shell detection: two-part regex — `_DOWNLOADER_RE` (`\b(curl|wget)\b`) + `_PIPE_TO_SHELL_RE` (`|\s*(/[a-z/]*/)?(?:ba)?sh\b`); both must be present → WARN −2 pts (flat)
- World-writable `.sh` scripts referenced in `ExecStart=` → WARN −1 pt (flat); `chmod o-w` fix command
- User-created timers in `/etc/systemd/system/` running without a `User=` directive → INFO only
- `_MAX_TIMERS=100`, `_MAX_EXEC_LENGTH=200` hard caps
- `svc_path.resolve()` used for symlink-safe user-created detection
- `lstrip("-@")` strips systemd ignore-fail (`-`) and argv0-override (`@`) prefixes from `ExecStart`
- Last `.service` on ambiguous timer lines (multiple services on one line) used
- 58 tests in `tests/test_systemd_timers.py`

### CHECK 45 — Firmware & microcode audit (`checks/firmware.py`)

- `FirmwareSnapshot`: two independent sub-checks
  - **fwupd**: `fwupdmgr get-updates` (cached result, no forced network call); pending updates → WARN −1 pt; fwupd absent → INFO; command error reported independently from updates
  - **CPU microcode**: `dpkg -l intel-microcode|amd64-microcode`; exact column match (handles arch-qualified output like `intel-microcode:amd64`); missing → WARN −1 pt; non-Intel/AMD → INFO
- `_detect_cpu_vendor()`: three clean states — `"intel"` | `"amd"` | `"unknown"`
- `_FWUPD_TIMEOUT=30` s, `_MAX_ERROR_LEN=200`, `_FWUPD_ERROR_RE` for structured error parsing
- Error and updates results reported independently (both can coexist)
- 54 tests in `tests/test_firmware.py`

### `--html` — Standalone HTML export (`html_output.py`)

- `build_html_output(engine, sys_info)` produces a self-contained HTML file (no JS, no external resources)
- Embedded CSS: `code{}` monospace, `.score-circle` colored badge, `.badge` level labels (ALERT/WARN/INFO/OK)
- Score deductions table; findings grouped by severity; footer with GitHub link
- `_h()` HTML-escapes all user data (`html.escape(quote=True)`) — XSS-safe
- `level_label` safely handles `None` engine level (`"UNKNOWN"` fallback)
- Dual-attribute deduction access: `getattr(engine, "deductions", getattr(engine, "_deductions", []))`
- 56 tests in `tests/test_html_output.py`

### `--check LIST` / `--skip LIST` — Check-level CLI filters

- `--check=ssh,firewall,ports` — run only the named checks; `--skip=clamav,rootkit` — exclude named checks
- Mutually exclusive (using both raises `CLIError`)
- `_section_enabled(section, config, profile)` helper in `runner.py` replaced 31 individual guards
- `validate_check_filters(config)` warns if an unknown check name is passed
- Profile `skip_sections` respected: `--check` can force a section even if the profile normally skips it
- Tests: 17 new tests across `test_cli.py` and `test_runner.py`

### `--output-dir PATH`

- `get_or_prompt_log_dir()` now prioritises `config.output_dir` when set — no interactive prompt, no write to user config
- `--output-dir` does not persist; it overrides the saved directory for the current run only
- 5 new tests in `test_cli.py`

### Bug fixes

- **SSH context note**: `runner.py` — the "SSH not publicly accessible" context note in the services section was never shown. Root cause: `_svc_id` was derived from the service label ("SSH Server" → `"ssh_server"`) and compared against `"openssh"`. Fixed by using `snap.service.id == "ssh"` (the canonical registry identifier).
- **auditd**: `no_rules` finding downgraded from WARN to INFO on `desktop` profile (server keeps WARN −1 pt)

### Quality pass

- **`firmware.py`**: `_detect_cpu_vendor()` simplified to 3 clean states; `_dpkg_installed()` uses exact column match for arch-qualified packages; fwupd error and updates results fully decoupled
- **`systemd_timers.py`**: pipe-to-shell detection split into two focused regexes (eliminates false negatives for `/bin/bash`, `bash -c`); `svc_path.resolve()` for symlink safety; `lstrip("-@")` for systemd prefixes; last service on ambiguous lines

### Tests

- `tests/test_ssl_certs.py` — 59 tests
- `tests/test_systemd_timers.py` — 58 tests
- `tests/test_firmware.py` — 54 tests
- `tests/test_html_output.py` — 56 tests
- Existing files: +57 tests (`test_cli.py` / `test_runner.py` — `--check`/`--skip`/`--output-dir`/`--html`; `test_auditd.py` — desktop INFO; quality pass assertions)
- ✅ 3778/3778 unit tests (+284 from v1.20.0)

---

## v1.20.0

**2026-04-18**

### CHECK 40 — UFW logging level (`checks/firewall.py`)

- `check_ufw_logging()`: reads current UFW logging level via `ufw status verbose` / `ufw logging`
- `off` → ALERT, −2 pts — logging fully disabled, no visibility into blocked traffic
- `low` / `medium` → OK — standard coverage
- `high` / `full` → INFO — verbose logging enabled (high disk I/O, no deduction)
- New locale keys: `firewall.logging_off`, `firewall.logging_ok`, `firewall.logging_verbose`

### CHECK 41 — System umask (`checks/umask.py`)

- `UmaskSnapshot`: reads umask from `/etc/login.defs`, `/etc/pam.d/common-session`, `/etc/profile`, shell RC files, and current process
- `check_umask()`: detects permissive umask values (0022 is OK; 0002/0000 → WARN, −1 pt)
- `_fix_cmd()`: proposes `/etc/profile.d/umask.conf` with correct `umask 0027` or `0022`
- All-sources conflict detection: warns when sources disagree
- 54 tests in `tests/test_umask.py`

### CHECK 42 — SSH auth.log login analysis (`checks/auth_log.py`)

- `AuthLogSnapshot`: parses `/var/log/auth.log` for SSH login events
- `check_auth_log()`: brute-force detection (>10 failed attempts from same IP in 60 s → ALERT); last successful logins shown; top failed-login sources listed
- `days=0` fix: when auth.log is empty (just rotated), uses `auth_log.no_logins_no_range` key instead of "0 day(s)"
- New locale keys: `auth_log.no_logins_no_range`
- 62 tests in `tests/test_auth_log.py`

### Score history (`history.py`)

- `HistoryEntry` dataclass + `load_history()` / `save_history()` — JSONL at `~/.config/ufw-audit/history.jsonl`
- `--history` flag: displays last N audit scores as a sparkline (▁▂▃▅▇█) with date and score
- Automatic rotation: keeps last 90 entries

### Ignore list (`ignore.py`)

- `--ignore KEY` — adds a finding key to `~/.config/ufw-audit/ignore.yml`; that finding is silenced in all future audits
- `--show-ignored` — lists all currently ignored keys
- `ScoreEngine.ignore_keys` frozenset: ignored findings are collected in `engine.ignored_findings` but not scored or displayed
- Hint shown on ignored findings: `Run ufw-audit --ignore <key> to silence this finding permanently`
- 44 tests in `tests/test_ignore.py`

### Bug fixes

- **ports**: `1900/udp` (UPnP/SSDP) owned by Spotify was classified as `SYSTEM_INTERNAL`; added `_SYSTEM_DAEMONS` frozenset — only recognised OS daemons (avahi-daemon, systemd-*, dnsmasq, …) qualify; user-space owners fall through to normal checks
- **ports**: process name now included in `uncovered_default_deny` INFO message (`57621/tcp (my-app)` instead of `57621/tcp`)
- **auth_log**: `_estimate_days()` returns 0 on an empty/just-rotated log; `check_auth_log()` now uses `auth_log.no_logins_no_range` instead of the `days=0` interpolation

### Tests

- `tests/test_auth_log.py` — 62 tests
- `tests/test_history.py` — 36 tests
- `tests/test_ignore.py` — 44 tests
- `tests/test_umask.py` — 54 tests
- `tests/test_ufw_logging.py` — 32 tests
- Existing files: +7 tests (ports process-aware, auth_log days=0)
- ✅ 3494/3494 unit tests (+235 from v1.19.0)

---

## v1.19.0

**2026-04-17**

### SSH audit improvements (`checks/ssh.py`)

- `_check_sshd_config` now emits OK findings for `PermitRootLogin no` (full disable) and `PermitRootLogin prohibit-password` / `forced-commands-only` (key-only / restricted)
- Previously only the `yes` (ALERT −3 pt) path was covered; the OK and INFO paths now complete the check
- New locale keys: `ssh.permit_root_login_disabled`, `ssh.permit_root_login_restricted`
- 7 new tests in `tests/test_ssh.py`

### SUID/SGID scan performance (`checks/suid_audit.py`)

- Replaced `find /` full-filesystem scan with a targeted `_SCAN_ROOTS` list (`/bin`, `/sbin`, `/usr/bin`, `/usr/sbin`, `/usr/lib`, `/usr/local/...`, `/opt`, …)
- Scan time reduced from >10 s to <1 s on a typical desktop
- SGID whitelist extended: `camel-lock-helper-1.2`, `support-tool-launcher`

### Display fix: IoT local dominance (`display.py`)

- `display_log_results` previously iterated only WARN findings; the `logs.local_dominance` INFO finding was silently dropped
- Fixed by explicitly iterating INFO findings for the `local_dominance` key after top-ports output

### Domain score labels i18n (`domain_scores.py`)

- `render_domain_scores` now passes all domain labels through `t()` — labels are translated when `--french` is active
- New `_label()` helper with English fallback when the translation key is absent
- Added `domain_scores.samba` and `domain_scores.disk` to `en.json` / `fr.json`

### Hardening: 6 new sysctl checks (`checks/hardening.py`)

- **`tcp_syncookies`** (`net.ipv4.tcp_syncookies`): OK if ≥ 1 (on or always-on); WARN −1 pt if 0
- **`accept_source_route`** (`net.ipv4.conf.all.accept_source_route`): OK if 0; WARN −1 pt if 1
- **`accept_redirects_v6`** (`net.ipv6.conf.all.accept_redirects`): OK if 0; WARN −1 pt if 1
- **`send_redirects`** (`net.ipv4.conf.all.send_redirects`): OK if 0; WARN −1 pt if 1
- **`protected_hardlinks`** (`fs.protected_hardlinks`): OK if 1; WARN −1 pt if 0
- **`protected_symlinks`** (`fs.protected_symlinks`): OK if 1; WARN −1 pt if 0
- All reads via `/proc/sys/` — no subprocess
- Fix commands write to `/etc/sysctl.d/99-hardening.conf`
- 21 new tests in `tests/test_hardening.py`

### Tests

- ✅ 3259/3259 unit tests (+530 from v1.18.0)

---

## v1.18.0

**2026-04-16**

### CHECK 34 — AppArmor / SELinux MAC policy (`checks/mac_policy.py`)

- `MacPolicySnapshot`: `apparmor_installed`, `apparmor_active`, `apparmor_enforcing`, `apparmor_complain`, `selinux_installed`, `selinux_mode`
- `from_system()`: `aa-status --json` (AppArmor); `sestatus` / `getenforce` (SELinux); graceful if unavailable
- `check_mac_policy()`: SELinux enforcing → OK (short-circuit); AppArmor enforcing > 0 → OK; AppArmor active but no enforce profiles → WARN −1 pt (server) / INFO (desktop); AppArmor inactive → WARN −1 pt; SELinux permissive only → WARN −1 pt; no MAC → WARN −1 pt
- 40 tests in `tests/test_mac_policy.py`

### CHECK 35 — Backup solution audit (`checks/backup.py`)

- `BackupSnapshot`: `active_tools`, `installed_tools` — two confidence levels: active (binary + config artefact / systemd service) vs. installed (binary only)
- Detected tools: borgmatic, borg, restic, timeshift, duplicati, bacula, rclone, tarsnap, deja-dup
- Active evidence: borgmatic config files; borg keys directory; timeshift JSON; `systemctl is-active`; rclone/tarsnap config files
- `check_backup()`: at least one active tool → OK; installed-only → INFO (no deduction, any profile); no tool at all → WARN −1 pt (server) / INFO (desktop)
- Container profile: `backup` added to `skip_sections` (backup is an orchestrator / host concern in ephemeral containers)
- 39 tests in `tests/test_backup.py`

### Kernel module check extension (`checks/kernel_modules.py`)

- `KernelModulesSnapshot` gains `dpkg_available`, `running_kernel`, `installed_kernels`
- `from_system()`: `dpkg -l 'linux-image-*'` to enumerate installed kernels
- `_check_installed_kernels()`: profile-aware retention — server keeps 3 (running + 2 fallbacks), desktop keeps 2 (running + 1 fallback)
- Always emits `kernels_listed` INFO with annotated list (`6.x.y (*) = running`) even when no cleanup is needed; covers single kernel, custom (non-dpkg) kernel, and within-retention cases
- Reboot pending (running ≠ most-recent installed) → `kernel_modules.kernels_reboot_pending` INFO
- Obsolete kernels → `kernel_modules.kernels_obsolete` INFO + `apt purge linux-image-X` per version, `cmd_type="check"`; running kernel never included
- Kernel version sorting: parses `MAJOR.MINOR.PATCH-ABI` tuples for numeric ordering

### Profile pass

**`data/profiles/desktop.conf`** — 6 new overrides:
- `ssh.password_auth`, `ssh.x11_forwarding`, `ssh.allow_tcp_forwarding` → `info` (common on personal workstations)
- `rootkit.no_scan`, `rootkit.scan_old` → `info`
- `password_policy.no_quality_module` → `info`

**`data/profiles/container.conf`** — 13 `skip_sections` (previously 1):
- Added: `kernel_modules`, `secure_boot`, `auditd`, `rootkit`, `file_integrity`, `disk`, `memory`, `fail2ban`, `clamav`, `ntp`, `mac_policy`, `backup`

### `--explain` — CHECKs 31 / 32 / 33 (10 new keys, 76 → 86 total)

- `auditd.not_installed`, `auditd.service_inactive`, `auditd.no_rules`, `auditd.missing_sensitive_rules` (profile-variant: server / desktop)
- `secure_boot.setup_mode`, `secure_boot.disabled` (profile-variant: server explains it as expected; desktop explains the risk)
- `file_integrity.not_installed`, `file_integrity.no_db`, `file_integrity.no_check`, `file_integrity.check_old`
- CIS Ubuntu 22.04 references added for all 10 keys
- FR locale updated with full translations

### Bash-completion fix

- `long_opts` collapsed to a single line — avoids multiline string parsing issues on Debian's older bash
- `--explain` listed without trailing `=` (was inadvertently added in some builds)
- `compopt -o nospace 2>/dev/null || true` — silent fallback when `compopt` is unavailable

### `--manage-logs` UX improvements

- **Move prompt on location change**: after entering a new path via `c`, if reports exist and the destination differs, proposes moving all visible reports `[y/N]`; confirms count of files moved
- **Multi-directory view**: current + all previous log directories displayed together; previous locations shown under `─── Previous location: /path ───` with continuous index; every report is reachable and actionable regardless of which path is currently configured
- Old directory registered in `log_dirs_extra` when user declines move; auto-removed when empty
- New locale keys: `current_label`, `previous_label`, `move_logs_prompt`, `move_logs_done`
- 29 tests in `tests/test_manage_logs.py`

### Tests

- **2729/2729** (+222 vs v1.17.0)

---

## v1.17.0

**2026-04-15**

### CHECK 31 — Linux Audit Framework (`checks/auditd.py`)

- `AuditdSnapshot`: `installed`, `service_active`, `rules_loaded`, `watched_files` (list of sensitive paths actually covered)
- `from_system()`: `shutil.which("auditctl")`; `systemctl is-active auditd`; `auditctl -l` to count loaded rules and extract watched paths; sensitive targets: `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`
- `check_auditd()`: not installed → INFO; service inactive → WARN −1 pt; no rules → WARN −1 pt; sensitive files not watched → WARN −1 pt (server profile) / INFO (desktop)
- 41 tests in `tests/test_auditd.py`

### CHECK 32 — Secure Boot (`checks/secure_boot.py`)

- `SecureBootSnapshot`: `state` ("enabled" / "disabled" / "no_uefi" / "unknown"), `method` ("mokutil" / "efivars" / "bootctl")
- Detection order: `mokutil --sb-state` → `/sys/firmware/efi/efivars/SecureBoot-*` → `bootctl status`
- `check_secure_boot()`: enabled → OK; disabled on desktop → WARN −1 pt; disabled on server (VMs/cloud) → INFO; BIOS/unknown → INFO
- 21 tests in `tests/test_secure_boot.py`

### CHECK 33 — File integrity monitoring (`checks/file_integrity.py`)

- `FileIntegritySnapshot`: `tool` ("aide" / "tripwire" / ""), `db_exists`, `last_check_date` (ISO date or None)
- `from_system()`: detects AIDE first (preference over Tripwire); db presence via path list; last check from log mtime
- `check_file_integrity()`: not installed → INFO; no database → WARN −1 pt; no recent check → WARN −1 pt; check > 30 days → WARN −1 pt; OK if check recent
- 33 tests in `tests/test_file_integrity.py`

### `--explain` profile variants

- 17 keys now show 3 dedicated sections (`[ server ]` / `[ desktop ]` / `[ container ]`) with profile-adapted WHY and HOW text
- Keys with no meaningful profile difference display a uniform note in yellow: `ⓘ  This finding applies equally to all profiles.`
- ESC delay in the interactive TUI reduced from ~1 s to 25 ms (`ESCDELAY=25` env var)
- +81 tests in `test_explain.py`

### Refactor — `workstation` → `desktop` profile

- `data/profiles/desktop.conf` created with the same overrides as the former `workstation.conf`
- `container.conf`: `extends = desktop`
- `profiles.py`: `workstation` alias in `load_profile()` for backward compatibility
- `cli.py` and bash-completion updated; `--help` references updated
- All tests migrated to `desktop`; alias tests added

### Bug fixes

- **IPv6 false alarm (avahi/cups/loopback)** — `ss -tulnp` process names; `_INTERNAL_PROCESSES` frozenset filters avahi-daemon, systemd-resolve, dnsmasq, containerd, dockerd from IPv6 rule suggestions
- **Logs journald fallback** — Debian 13 without rsyslog: `LogsSnapshot` gains `log_source` field; `from_system()` falls back to `journalctl -k --output=short-iso` when `/var/log/ufw.log` absent
- **Hardening sysctl persistence** — `rp_filter`, `redirects_enabled`, `log_martians_disabled` commands now write to `/etc/sysctl.d/99-hardening.conf`
- **disk.py** — `disk.smartctl_missing` finding now includes `sudo apt install smartmontools` cmd

### UX

- **`cmd_type`** — `Finding` dataclass gains `cmd_type: str = "fix"` / `"check"`; summary box uses a different prefix (`ℹ Check:` vs `→ Fix:`)
- **manage_logs.py** — menu stays open after each delete action (`while True` loop)
- **runner.py** — services sorted by severity (critical → high → medium → low → inactive)
- **panorama.py** — rows sorted alphabetically by label
- **display.py** — active audit profile displayed in the summary box
- **output.py** — group header title centred in the `━` separator line; risk context entries colour-coded by tier
- **Trusted Publishing** — `.github/workflows/publish.yml` publishes to PyPI via OIDC (no API token)

### Tests

- **2507/2507** (+215 vs v1.16.0)

---

## v1.16.0

**2026-04-12**

### New checks

- **CHECK 19** — Desktop application detection: 30+ known GUI apps running as processes → INFO, no deduction; section not shown if no app is running
- **CHECK 28** — NTP time synchronisation: systemd-timesyncd/chronyd/ntpd active and synchronised → WARN −1 pt if inactive or not yet synced
- **CHECK 29** — Fail2ban intrusion prevention (standalone): service status, active jails, SSH jail detection → WARN −1 pt if inactive or no jails; moved out of hardening check
- **CHECK 30** — Rootkit & integrity scan: rkhunter/chkrootkit DB freshness and last scan date → WARN −1 pt each

### Improvements

- **`--target N` exit code 4** — `EXIT_TARGET_MISSED = 4` when score < target; takes priority over codes 1/2
- **CLI validation** — `--explain=`, `--profile=`, `--lang=`, `--webhook=`, `--target=` with empty value now raise a clear error
- **5 thematic group headers** — output reorganised into FIREWALL & NETWORK / EXPOSURE & SERVICES / ACCESS CONTROL / SYSTEM HARDENING / DETECTION & HEALTH; full-width `━` cyan separator; fail2ban moved to GROUP 5

### Tests

- **2292/2292** (+153 vs v1.15.1)

---

## v1.15.1

**2026-04-12**

### Hotfix — bash-completion

- `--explain` was listed as `--explain=` in `long_opts` → trailing `=` removed; now completes correctly without `=`
- `compopt -o nospace` added: suppresses trailing space when the single completion result ends with `=` (e.g. `--target=`, `--log-days=`, `--profile=`)

---

## v1.15.0

**2026-04-12**

### CHECK 26 — IoT/local source dominance (`checks/logs.py`)

- `_dominant_local_source()`: detects when a single private IP accounts for ≥ 70% of all blocked traffic over ≥ 50 log entries
- Finding key `logs.local_dominance` — WARN, −1 pt (context `local`) — typical of IoT devices doing LAN sweeps
- Constants `_LOCAL_DOMINANCE_THRESHOLD = 0.70` and `_LOCAL_DOMINANCE_MIN_COUNT = 50`

### CHECK 27 — SMTP local exposure (`checks/smtp.py`)

- `SmtpSnapshot.from_system()`: detects installed MTA (Postfix, Exim, Sendmail) via `ps -eo comm`; checks port-25 bind address via `ss -tlnp` / `netstat -tlnp` fallback
- `check_smtp()`: not installed → OK; installed not listening → INFO; listening on localhost only → INFO; listening on all interfaces → WARN −1 pt
- `_LOCAL_BIND_RE` regex covers `127.*`, `::1`, `localhost`
- 5 locale keys in both `en.json` and `fr.json`

### C1 — `--fix` dry-run by default; `--apply` to execute

- `--fix` alone now shows a preview of all available fixes without executing anything (dry-run mode)
- `--fix --apply` triggers the interactive apply flow (previous behaviour)
- `--fix --apply --yes` auto-confirms all fixes (audit trail printed)
- `fixes.py`: dry-run branch shows `→ cmd` preview for each fix, then returns; apply branch unchanged
- `cli.py`: new `apply: bool` field; `--apply` requires `--fix`; `--yes` requires `--fix --apply`; `--quiet` / `--json` incompatibility now limited to `--fix --apply` (dry-run is compatible)
- `fixes.dry_run_hint` locale key added to `en.json` + `fr.json`
- `--apply` added to bash-completion

### C2 — `--target N` score cible

- `--target=N` (1–10): adds a **Target** line to the audit summary box
  - Score ≥ target: `✔ target reached` (green)
  - Score < target: `▲ +N pt(s) needed` (yellow)
- Locale keys `scoring.target_label`, `scoring.target_reached`, `scoring.target_gap` in `en.json` + `fr.json`
- `--target=` added to bash-completion and `--help` (AUDIT section)

### UX — `--explain` TUI fixes

- ↑ on the first item no longer wraps to the last; ↓ on the last item no longer wraps to the first (clamped navigation)
- Selecting a key now opens an in-curses detail screen instead of exiting to the terminal — press ESC to return to the picker
- ESC no longer quits the picker (only `q` / `Q` quit)
- `q` no longer closes the detail screen (only ESC returns to the picker)
- Group headers reappear correctly when scrolling back up
- `--explain` 73→77 keys (+4): `user_accounts` group added (`uid_zero`, `empty_password`, `expired_account`, `no_shadow`)

### UX — wizard cancellation (`q` at any step)

- **`--install-cron`**: quit hint shown at start; `q` accepted at every prompt → "Wizard cancelled."
- **`--manage-cron` edit email**: `q` in `prompt_emails()` → "Cancelled." with no modification; NOTIFY_EMAILS regex fixed; `q. Cancel — back to menu` now visible in the email picker list (`email_prompt.cancel` locale key)
- **`--manage-cron` edit schedule**: `q` accepted at every step → "Cancelled."
- **`--manage-logs` change location**: `prompt_path()` gains `allow_cancel=True`; `q` → "Cancelled."
- `--manage-cron` now shows one line per email address in the listing

### Tests

- `test_explain_flag_without_value_raises` → `test_explain_flag_without_value_launches_interactive` (behaviour change)
- `test_yes` / `test_json_and_fix_raises` / `test_quiet_and_fix_raises` updated for new `--apply` semantics
- `TestApplyFlag`: 12 new tests for `--apply` parsing and validation
- `TestTargetFlag`: 10 new tests for `--target` parsing and validation
- `TestDryRun`: 8 new tests for dry-run mode in `fixes.py`
- `TestDominantLocalSource`: 13 new tests (CHECK 26)
- `test_smtp.py`: 31 new tests (CHECK 27)
- **2130/2130 tests** (+84 vs v1.14.0)

### Quality pass — `checks/smtp.py`

- `_LOCAL_BIND_RE`: removed `\*$` — `*` in `ss` output means all interfaces (was incorrectly treated as local-only, causing false negatives)
- `_check_port_25()`: collects all bind addresses for port 25; strips brackets from IPv6 (`[::1]` → `::1`); returns the most exposed address when multiple binds coexist (e.g. `127.0.0.1:25` + `0.0.0.0:25` → returns `0.0.0.0`, avoiding false negatives)
- `check_smtp()`: fix command now Postfix-specific (`sudo postconf -e 'inet_interfaces = loopback-only'`) with a restart note; empty `cmd` for Exim/other MTAs (fix is MTA-specific, shown as manual action)
- `smtp.exposed_restart_postfix` locale key added to `en.json` + `fr.json`
- `test_smtp.py`: `test_wildcard_star` → `test_wildcard_star_is_exposed` (+2 `_LOCAL_BIND_RE` tests, `TestSmtpCmd` 4 tests, `TestSmtpWildcardExposed` 3 tests)
- **2139/2139 tests** (+9)

---

## v1.14.0

**2026-04-10**

- Samba Security Audit (CHECK 24): SMB1 ALERT −2, null passwords ALERT −3, guest writable share WARN −1, guest read-only INFO, server signing disabled WARN −1, map to guest WARN −1; `SambaSnapshot`; 12 locale keys
- ClamAV Antivirus Audit (CHECK 25): installation detection (clamav-daemon, freshclam, clamd socket fallback), DB freshness (≥14 d ALERT, ≥7 d WARN), last scan age (≥30 d ALERT, ≥14 d WARN); `ClamavSnapshot`; 10 locale keys; DB age via `st_mtime`; scan date parsed as local time (naive datetime)
- `--diff` fix: `info_count` now tracked and included in baseline delta
- `--explain`: 63→73 keys (17 groups) — added Samba (6 keys) and Disk (5 keys)
- Quality pass: DB age `st_mtime` + `.days`; `(?i)` regex; freshclam detection; clamd socket fallback constant
- **2045/2045 tests** (+155 vs v1.13.0)

---

## v1.13.0

**2026-04-10**

### CHECK 22 — Disk Health (`checks/disk.py`)

- `DiskSnapshot` + `check_disk()` — pure snapshot/logic separation
- SMART health via `smartctl -H`: PASSED → OK; FAILED → ALERT, −3 pts; virtual/unsupported → INFO
- Critical SMART attributes via `smartctl -A`: reallocated sectors (ID 5), pending sectors (ID 197), uncorrectable errors (ID 198) — each non-zero → WARN, −1 pt
- Partition usage via `df -P`: ≥ 90% → WARN, −1 pt; ≥ 80% → INFO; pseudo-filesystems (tmpfs, squashfs, overlay, etc.) skipped
- `smartctl` not installed → INFO with install hint; `lsblk` used for disk detection
- New **`disk`** domain added to `domain_scores.py` (6th domain, between Hardening and Firewall & Services)
- 22 locale keys added to `en.json` + `fr.json`

### CHECK 23 — Memory & Swap (`checks/memory.py`)

- `MemorySnapshot` + `check_memory()` — reads `/proc/meminfo` + `/proc/sys/vm/swappiness` + `/sys/block/*/queue/rotational`
- No swap configured → INFO, no deduction
- Swap on SSD with `swappiness > 30` → WARN, −1 pt; profile-aware recommended value (server: 1, workstation: 10)
- Swap in use while RAM > 50% free → WARN (unjustified swap), no deduction
- Default `swappiness=60` → INFO suggestion to lower; optimal → OK
- Swap statistics always shown when swap is present
- Memory/swap findings route to the **`hardening`** domain
- 9 locale keys added to `en.json` + `fr.json`; `sections.memory` + `sections.disk` added

### NVMe support & robustness (`checks/disk.py`)

- `_parse_nvme_attrs()` — maps NVMe health counters: Media and Data Integrity Errors → `uncorrectable_errors`, Error Information Log Entries → `pending_sectors`
- SMART health parsing now matches the specific "SMART overall-health" line only (avoids false positives from other lines containing "passed"/"failed")
- Dead `device != "overlay"` condition removed (already covered by `_SKIP_TYPES_RE`)
- `du` command: `du -x -h --max-depth=1` (was `du -sh *`)

### Memory & Swap robustness (`checks/memory.py`)

- Unjustified swap now requires 3 conditions: swap ≥ 32 MB AND RAM > 50% free AND `swappiness > recommended` (prevents false positives from kswapd LRU aging)
- `swapon --show=NAME --noheadings --raw` — explicit column, independent of column-order changes
- All `/proc` reads use `errors="ignore"` for byte-level robustness

### Partition table display (`display.py`)

- `display_disk_partitions()` — DISK HEALTH section shows a per-partition table with device, size, and colored progress bar (green < 70%, yellow < 90%, red ≥ 90%)
- Size formatted as `< 1 GB` for sub-1 GB volumes

### SMART deeper analysis tips

- `disk.smart_tips` INFO finding appended when `smartctl` is present: lists `smartctl -a` per disk + guided commands for running short/long tests, monitoring progress (`watch`), aborting (`-X`), and consulting history (`-l selftest`)

### `--explain` expanded (33 → 63 keys, 15 groups)

- `EXPLAIN_KEYS` expanded from 33 to 63 keys; 30 new keys across SSH authorized keys, SSH client config, firewall rules, IPv6, password policy, disk, and memory
- `--explain list` now displays keys organized into 15 labeled groups with headers
- `tests/test_explain.py` updated: `test_has_sixty_three_keys` asserts `len(EXPLAIN_KEYS) == 63`

### Tests

- `tests/test_disk.py`: 60 tests across 9 test classes (+3 NVMe tests)
- `tests/test_memory.py`: 37 tests across 8 test classes (+6 robustness tests)
- **Total: 1890/1890** (+187 vs v1.12.0)

---

## v1.12.0

**2026-04-10**

### `--help` redesign

- 6 named sections: AUDIT / OUTPUT / FIXES / INTEGRATIONS / CONFIGURATION / MAINTENANCE / STANDALONE
- Each section leads with a short description of its purpose
- STANDALONE section groups no-sudo commands (`--explain`, `--install-completion`, `--version`, `--help`)
- Usage line shows `ufw-audit --explain KEY` as second form (no sudo)
- EXIT CODES section renamed and clarified for scripting use

### New short options

| Short | Long | Purpose |
|-------|------|---------|
| `-J`  | `--json-full` | JSON full export (pairs with `-j`) |
| `-C`  | `--manage-cron` | Manage cron jobs (pairs with `-c`) |
| `-e`  | `--explain KEY` | Explain a finding key |
| `-D`  | `--diff` | Diff mode |
| `-w`  | `--webhook URL` | Webhook URL |
| `-p`  | `--profile NAME` | Audit profile |

### Autocompletion fix

7 options were missing from bash completion: `--lang=`, `--profile=`, `--reset-baseline`, `--explain=`, `--diff`, `--webhook=`, `--webhook-format=`

Added smart completions: `--profile=` → server/workstation/container; `--lang=` → en/fr; `--webhook-format=` → auto/generic/slack

All 6 new short options added to completion.

### Debian VM fixes

**Fix #1 — Risk context for all installed services**
- `service_risk` entries added in `en.json` + `fr.json` for 11 medium/low services: Apache, Nginx, Transmission, qBittorrent, Avahi, CUPS, Jellyfin, Plex, Gitea, Syncthing, Ollama
- `runner.py` + `display.py`: risk context block now shown for all active services (not just high/critical)

**Fix #2 — GeoIP wget**
- `sudo mkdir -p /usr/share/GeoIP &&` prefix added to the wget command in `en.json`, `fr.json` and the `display.py` fallback — directory absent by default on Debian

**Fix #3 — `unattended-upgrades` profile-aware**
- `check_updates()` accepts `profile_name` parameter
- On `workstation` profile: compound risk (unattended missing + security pending) demoted to INFO, no extra −1 pt deduction

**Fix #4 — Expired accounts with dates**
- `expired_accounts` changed from `List[str]` to `Dict[str, str]` (username → ISO expiry date)
- System accounts (UID < 1000) excluded from the expired check — their expiry is managed by the package manager
- Finding message now shows date per account: `alice (2023-06-15), bob (2022-01-01)`

### Tests

- 8 new tests in `test_cli.py` covering all 6 new short options
- 16 new tests: `TestWorkstationProfile` (5) in `test_updates.py`; date assertions + dict fixtures in `test_user_accounts.py`
- **Total: 1703/1703**

---

## v1.11.0

**2026-04-07**

### `--explain` Phase A2 (20 → 33 keys)

- `EXPLAIN_KEYS` expanded from 20 to 33 keys; grouped by category in source
- New SSH keys: `max_auth_tries`, `allow_tcp_forwarding`, `x11_forwarding`, `permit_user_env`, `ignore_rhosts_disabled`, `host_based_auth`, `strict_modes_disabled`, `client_strict_host_no`, `weak_ciphers`, `weak_macs`, `weak_kex`
- New Hardening key: `fail2ban_missing`
- New Kernel modules keys: `risky_fs`, `risky_net`
- New Cron key: `pipe_to_shell` (duplicate of `world_writable` already present)
- New Services state key: `enabled_inactive`
- Locale (`en.json`, `fr.json`): title / why / how / CIS ref added for all 13 new keys
- Test: `test_has_thirty_three_keys`, 13 new membership assertions

### User account audit (CHECK 17)

- New module `checks/user_accounts.py` — `UserAccountsSnapshot` + `check_user_accounts()`
- UID 0 accounts other than root → ALERT, −3 pts (flat); `shlex`-safe `passwd -l` command
- Empty password on login-capable account → ALERT, −2 pts (flat); reads `/etc/shadow` (root required)
- Accounts with a past expiry date → INFO, no deduction
- `/etc/shadow` unreadable (non-root) → INFO, no deduction; UID 0 detection still runs (world-readable `/etc/passwd`)
- Accounts using `nologin`/`/bin/false` excluded from empty-password check
- `dict.fromkeys` deduplication on all account lists; snapshot never mutated
- Domain: `user_accounts` → `file_perms`
- New test file: `test_user_accounts.py` — 51 tests

### Password policy audit (CHECK 18)

- New module `checks/password_policy.py` — `PasswordPolicySnapshot` + `check_password_policy()`
- No PAM quality module (`pam_pwquality` / `pam_cracklib` absent from `common-password`) → WARN, −1 pt
- Explicit `minlen < 8` in `pwquality.conf` or inline PAM option (when module IS configured) → WARN, −1 pt
- `PASS_MAX_DAYS ≥ 365` → INFO only; no deduction (NIST SP 800-63B no longer mandates periodic expiration)
- `elif` structure: `no_quality_module` and `weak_minlen` are mutually exclusive
- `pwquality.conf` minlen takes precedence over inline PAM `minlen=` option
- Domain: `password_policy` → `hardening`
- New test file: `test_password_policy.py` — 51 tests

### Quality pass

- `test_user_accounts.py`: `test_no_shadow_info_absent_when_readable`, 3 snapshot immutability tests, `test_no_t_does_not_crash`
- `test_password_policy.py`: `test_minlen_7_flagged`, `test_login_defs_unreadable_no_crash`, `test_pass_min_days_ignored`, `test_no_t_does_not_crash`, `test_pam_cracklib_ok_finding`

---

## v1.10.0

**2026-04-07**

### `--explain` hint in summary box (Phase A1)

- Every actionable finding now shows `? ufw-audit --explain <key>` when the key is in `EXPLAIN_KEYS`
- Uses `normalize_key()` — `file_perms.shadow.world_writable` → `file_perms.world_writable`
- New test file: `test_display_explain_hint.py` — 25 tests

### Kernel module audit (CHECK 14)

- New module `checks/kernel_modules.py` — `KernelModulesSnapshot` + `check_kernel_modules()`
- Risky FS modules: cramfs, freevxfs, jffs2, hfs, hfsplus, squashfs, udf, usb_storage → WARN, −1 pt (flat)
- Risky net modules: dccp, sctp, rds, tipc → WARN, −1 pt (flat)
- Max −2 pts; cmd: `sudo modprobe -r <modules>` (shell-safe via `shlex.quote`)
- `lsmod` unavailable → INFO, no deduction
- New test file: `test_kernel_modules.py` — 48 tests

### Cron job audit (CHECK 15)

- New module `checks/cron_audit.py` — `CronAuditSnapshot` + `check_cron_audit()`
- `curl/wget … | sh/bash/zsh/…` in any system cron file → WARN, −2 pts (flat); regex covers `/bin/sh`, `zsh`, `/usr/bin/bash -s`
- World-writable `.sh` script referenced in cron → WARN, −1 pt; cmd: `sudo chmod o-w <scripts>` (shell-safe)
- `/etc/cron.d` parsed as crontab format (script paths extracted); `cron.daily/hourly/weekly/monthly` stat'd directly
- Unexpected user crontabs in `/var/spool/cron/crontabs/` → INFO, no deduction
- Max −3 pts
- New test file: `test_cron_audit.py` — 47 tests

### Service state audit (CHECK 16)

- New module `checks/services_state.py` — `ServicesStateSnapshot` + `check_services_state()`
- Two-step `systemctl` query: `list-unit-files` (enabled state) + `list-units --all` (active state) — only flags enabled+inactive
- Monitors: ufw, fail2ban, apparmor, auditd, clamav-daemon, clamav-freshclam, ssh, sshd, crowdsec, ossec
- Enabled-at-boot but inactive/failed → WARN per service, −1 pt (capped at −3)
- `systemctl` unavailable → INFO, no deduction
- New test file: `test_services_state.py` — 35 tests

### Quality pass

- `firewall.py`: added `key=` to all findings in `_check_duplicates`, `_check_open_any`, `_check_ipv6_coverage`
- `test_check_rules.py` (19→29): key-based assertions, `TestOpenAny`/`TestDuplicates`/`TestIPv6Coverage`/`TestCombined` classes
- `test_cli.py` (25→63): all flags/defaults/combos covered; `TestWebhook` and `TestExplain` classes
- `test_compare.py` (47→54): `SimpleNamespace` for data objects, module-level `_make_delta`, `skipif` Windows
- `test_cron.py` (52→62): parametrized `TestOrdinal`, French weekdays, `_parse_dom("")`
- `test_ddns.py` (37→42): quoted hostname, empty value, fallback regex, malformed rule
- `test_degraded.py` (17→20): real `LogEntry`, firewall-inactive + empty-ports/rules combos

### Domain scores

- `kernel_modules`, `cron_audit`, `services_state` now map to the `hardening` domain

---

## v1.9.0

**2026-04-06**

### System updates audit (CHECK 13)

- New module `checks/updates.py` — `UpdatesSnapshot` + `check_updates()`
- Detects security packages pending update via `apt-get -s upgrade` + `-security` suite matching
- Detects regular packages pending update (informational)
- Detects `unattended-upgrades` installation and configuration (apt-conf + systemd timer)
- Scoring: security pending → −2 pts (flat regardless of package count); `unattended-upgrades` absent + security pending → −1 pt additional (compound risk)
- Deduplication of package names (`dict.fromkeys` order-preserving); `None`-safe list handling

### `--explain KEY`

- New module `explain.py` — `normalize_key()` + `run_explain()`
- Prints structured explanation per finding: title, WHY IT IS A RISK, HOW TO FIX, CIS Ubuntu 22.04 reference
- 20 explainable keys across all domains (SSH ×11, file_perms ×4, updates ×2, hardening ×2, firewall ×1)
- `--explain list` — lists all 20 keys with translated titles
- Key normalisation strips `file_perms.*` middle segments (regex handles deep nesting)
- CIS references stored in `explain_cis` locale section (EN + FR)
- No root required — early exit before privilege check

### Webhooks (`--webhook`)

- New module `webhook.py` — `build_generic_payload()`, `build_slack_payload()`, `send_webhook()`
- Generic payload: Grafana / custom HTTP receivers; includes `domain_scores`
- Slack payload: auto-detected by URL (`hooks.slack.com`), colour-coded (red/orange/green)
- `--webhook-format=auto|generic|slack` — override format detection
- Non-fatal: failures print to stderr, audit exit code unaffected
- `--offline` suppresses webhook call; stdlib only (`urllib.request`)
- Config persistence: `get/set_webhook_url()`, `get/set_webhook_format()` in `UserConfig`

### Domain scores

- New module `domain_scores.py` — `compute_domain_scores()` + `render_domain_scores()`
- Five domains: SSH, Files & Access, Updates, Hardening, Firewall & Services
- Each domain scored independently: `max(0, min(10, 10 − domain_deductions))`
- Displayed in terminal after audit summary (█/░ bar chart)
- Included in `--json`, `--json-full`, and generic webhook payload
- Hardened against `None` keys, missing attributes, negative points

### `--diff` mode

- Runs audit silently (`quiet=True`), displays only the comparative delta (what changed since last audit)
- Combines with `--verbose`

### Tests

- `test_updates.py` — 34 tests: apt unavailable, security/regular pending, unattended-upgrades, combined scenarios, edge cases (None lists, duplicates, invariants)
- `test_explain.py` — ~94 tests: normalize_key (deep nesting, over-strip guard), EXPLAIN_KEYS list, run_explain (unknown key, list mode, all 20 keys ×3 parametrized), CLI parsing
- `test_domain_scores.py` — ~48 tests: key-to-domain (None/malformed inputs), deduction attribution, score floor/ceiling, rendering, CIS all-20-keys, JSON/webhook structure
- `test_webhook.py` — ~54 tests: URL detection, format selection, generic/Slack payloads, HTTP mocking, UserConfig persistence, CLI parsing, combined flags
- 1332/1332 (+228)

---

## v1.8.0

**2026-04-06**

### SSH security audit (CHECK 11)

- New module `checks/ssh.py` — full `sshd_config` analysis (15 directives + weak crypto), private key audit, `authorized_keys`, `~/.ssh/config`, `known_hosts`
- Targets `SUDO_USER`'s home directory; distro-aware install hints (apt/dnf/pacman/zypper/apk)
- 93 new tests in `tests/test_ssh.py`

### Sensitive files & sudoers (CHECK 12)

- New module `checks/file_perms.py` — world-writable/too-permissive sensitive files, SSH host key permissions, `NOPASSWD:ALL` sudoers detection
- 45 new tests in `tests/test_file_perms.py`

### i18n / display

- `output.recommendation_label` key added (EN/FR) — fixes hardcoded French in all-locale output
- INFO findings now show `detail` text in verbose mode (`-v`)

### Tests

- 1104/1104 (+138)

---

## v1.7.0

**2026-04-04**

### Audit profiles

- Named profiles (`server`, `workstation`, `container`) shipped as `.conf` files under `ufw_audit/data/profiles/`
- `--profile=NAME` CLI flag — selects an audit profile; persisted across runs in `~/.config/ufw-audit/config.conf`
- Profile file format (INI): `[profile]` name/extends/description; `[overrides]` key=level; `[skip_sections]` section names
- `extends` inheritance with depth guard (`_MAX_EXTENDS_DEPTH = 8`) — prevents circular chains
- Override levels: `info | warn | alert | skip`
- User-defined profiles: drop a `.conf` file in `~/.config/ufw-audit/profiles/` — takes priority over built-ins
- `apply_profile()` is post-check — existing and future check functions require no changes to benefit from profiles

### Deduction keys (`Deduction.key`)

- `Deduction.key: str = ""` added to `Deduction` dataclass — stable i18n key linking each deduction to its finding
- `add_deduction(key=)` parameter added to `CheckResult`
- All scored deductions in `hardening.py` and `ipv6.py` now carry matching `key=` arguments
- `_remove_deductions_for_key()` in `profiles.py` simplified to `d.key != key` — deterministic, no heuristic on translated strings
- `_find_profile_file()` cached with `@lru_cache(maxsize=32)` — deep `extends` chains pay disk cost only once
- Override keys in profile files are normalized (`strip().lower()`) — tolerates mixed case

### `--install-cron` — multiple notification emails

- `prompt_emails()` replaces `prompt_email()` — asks "Add another email? [y/N]" after each selection
- Previously-selected addresses shown with ✔ marker to avoid duplicates
- All selected addresses stored comma-separated in the cron file and script
- Bash script loops over recipients: `IFS="," read -ra _ADDRS` — each address gets its own email

### `--manage-cron` — bulk delete

- `d:1,3` — delete cron jobs 1 and 3 (comma list)
- `d:1-3` — delete cron jobs 1 through 3 (range)
- `d:all` — delete all installed cron jobs (dedicated confirmation message)
- Single-item delete (`d:N`) unchanged; confirmation message adapts to selection size

### Comparative report — ephemeral port filter

- `build_baseline()` now excludes ephemeral ports (≥ 32768) — eliminates false-positive "new port" noise from Avahi, libvirt, VPN, and other transient UDP sockets
- `--reset-baseline` — deletes `~/.config/ufw-audit/last_baseline.json` and exits cleanly (useful after switching profiles or major system changes)

### Migration note

If upgrading from v1.6.0, run `sudo ufw-audit --reset-baseline` once to discard the old baseline (which may contain ephemeral ports). The next audit will create a clean baseline automatically.

---

## v1.6.0

**2026-04-04** — 928/928 tests

### New sections

- **HARDENING** (`checks/hardening.py`) — unattended-upgrades, rp_filter, ICMP redirect acceptance, fail2ban, AppArmor, log_martians, ICMP broadcast
- **IPv6 CONSISTENCY** (`checks/ipv6.py`) — cross-checks kernel IPv6 enable/disable against UFW IPv6 setting and active IPv6 listeners

### Comparative report

- `compare.py` — `AuditBaseline` + `AuditDelta` dataclasses; `build_baseline()`, `save_baseline()`, `load_baseline()`, `compute_delta()`, `display_delta()`
- Baseline saved at `~/.config/ufw-audit/last_baseline.json` after every audit
- Shows score delta, alert/warn delta, new/closed ports, new/stopped services

### Plugin API

- `plugin_checks.py` — third-party check functions discovered via `ufw_audit.checks` entry-point group
- Plugin isolation: import errors skip the plugin with a warning rather than crashing the audit
- ANSI sanitization for plugin check names (`_sanitize_check_name()`)

### JSON output

- `hardening_snapshot` and `ipv6_snapshot` objects added to `--json-full` output

---

## v1.5.0

**2026-04-04** — 766/766 tests

### New sections

- **FIREWALL STACK ANALYSIS** (`checks/firewall_stack.py`) — detects raw iptables ACCEPT rules that bypass UFW in the INPUT chain; ACCEPT rules in FORWARD chain (suppressed if Docker/WireGuard/libvirt are detected); nftables tables running in parallel to UFW (iptables-nft compatibility tables are excluded); ip_forward enabled without a routing daemon (Docker, WireGuard, or libvirt/KVM)
- **NETWORK CONTEXT** (`checks/network_context.py`) — interface table (name, type, UP/DOWN, IPv4 address); established TCP connection count + top remote IPs; WARN if established connection to an external host on a sensitive port (MySQL, PostgreSQL, Redis, MongoDB, CouchDB)

### Banner enriched

- Kernel version, iptables version + backend (`nf_tables` / `legacy`), nftables version shown at startup
- `"not installed"` displayed when iptables or nftables is absent

### JSON output (`--json-full`)

- `"firewall_stack"` object: `input_bypasses`, `forward_bypasses`, `nftables_active`, `ip_forward`, routing daemon flags
- `"network_context"` object: `interfaces` list, `connections_count`, `top_remote_ips`

### Tests

- `tests/test_firewall_stack.py` — 38 tests (new file)
- `tests/test_network_context.py` — 51 tests (new file)
- `tests/test_report.py` — fixture updated for `iptables_version` / `nftables_version`

### Code quality pass (12 modules — no behaviour change for clean audits)

- **`report_markdown.py`** — XSS fix: `_safe_url()` rejects non-`http(s)` URLs; timestamp coherence via `created_at`; table column normalization; `.md` file extension
- **`registry.py`** — port range validation (1–65535); Python keyword guard on `config_key`; `__iter__` return type
- **`cli.py`** — `--lang=CODE` generalizes `--french`; `--quiet`+`--json` conflict; `--json`+`--fix` conflict; `--log-days` capped at 3650; unused `field` import removed
- **`config.py`** — atomic writes (`.tmp` + `replace()`) for `UserConfig` and `EmailStore`; email validation (strict regex); `set()` rejects invalid keys
- **`cron.py`** — email regex tightened; cron script path supports spaces; `_validate_custom_cron()` checks minute (0–59) and hour (0–23) ranges
- **`fixes.py`** — manual findings now displayed after auto-fixes; UFW delete regex anchored (`^(?:sudo\s+)?ufw`); shell operator guard; `done_summary` locale key
- **`i18n.py`** — per-key EN fallback when FR key missing; JSON root type validated; key depth guard (max 10); `_load_locale()` extracted; logging reflects actual loaded language
- **`manage_logs.py`** — `"all"` delete requires `[y/N]` confirmation
- **`panorama.py`** — `PanoramaRow TypedDict`; `state`/`exposures` defensive guards; `risk` normalized lowercase
- **`completion.py`** — `src.exists()` guard before copy; distinct messages per failure reason
- **`_paths.py`** — `.strip()` on env var; `resolve(strict=True)`
- **`pyproject.toml`** — README explicit `content-type = "text/markdown"`; Python 3.11 classifier

---

## v1.4.2

**2026-04-04**

- Fix: NetBIOS ports 137/138 still reported as uncovered even when an explicit UFW rule exists — UFW coverage check was evaluated after the NetBIOS branch instead of before

---

## v1.4.1

**2026-04-04**

- Fix: `--install-completion` was missing from the bash completion suggestions

---

## v1.4.0

**2026-04-04**

- Feature: `services.d` plugin system — drop JSON files in `~/.config/ufw-audit/services.d/` to define custom service definitions loaded alongside built-ins
- Feature: UFW default deny awareness — `check_ports()` accepts `default_incoming_policy`; uncovered public ports downgraded to INFO when UFW policy is `deny` or `reject`
- Refactor: `__main__.py` split into 4 modules — `completion.py` (`--install-completion`), `runner.py` (8 checks pipeline), `json_output.py` (JSON serialization); `__main__.py` is now a pure orchestrator (~160 lines)
- Refactor: `run_checks()` returns typed `ChecksResult` NamedTuple instead of bare `tuple`
- Fix: `__main__.py` — `CLIError` now returns `EXIT_ERROR (3)` instead of `1` (was conflicting with `EXIT_WARNINGS`); `try/finally` ensures `sys.stdout` and `_devnull` are always restored on exception
- Fix: `firewall.py` — `found_duplicate` boolean replaces fragile `startswith[:20]` heuristic in duplicate rule detection
- Fix: `logs.py` — year-boundary fix for syslog timestamps (log from Dec parsed in Jan no longer set to future date); removed `is_symlink()` exclusion for GeoIP2 `.mmdb` (valid symlinks on Debian/Ubuntu via `update-alternatives`)
- Fix: `_run.py` — `_is_safe_config_path()` centralized (was duplicated in `ddns.py` and `services.py`)
- Fix: `cron.py` — `read_text(encoding="utf-8")`; range cap `min(end, start+999)` prevents memory abuse; NOTIFY_EMAIL regex accepts both single- and double-quoted values
- Fix: `json_output.py` — UTC timestamp (`timezone.utc`); typed parameters (`SystemInfo`, `list[ServiceSnapshot]`); `schema_version: "1"` field added
- Fix: `completion.py` — guard for missing `/etc/bash_completion.d/`; refuses to overwrite existing real binary at symlink target
- 676/676 unit tests (+24 from v1.3.0)

---

## v1.3.0

**2026-03-31**

- Feature: all `Deduction.reason` strings now pass through `t()` — score breakdown fully translated in EN and FR (zero hardcoded strings)
- Feature: `--offline` / `-o` flag — skips all external HTTP calls (no public IP lookup); useful for air-gapped or firewalled machines
- Feature: `get_public_ip()` now tries 3 providers in order (`api.ipify.org` → `ifconfig.me/ip` → `icanhazip.com`) before returning `""`
- Feature: `detect_network_context()` now detects public IPv6 addresses (`inet6` on interfaces, excluding `::1`, `fe80::`, ULA `fc`/`fd`)
- 652/652 unit tests (11 new in `tests/test_sysinfo.py`)

---

## v1.2.1

**2026-03-31**

- Remove: `install.sh` definitively removed — deprecated since v1.0, `pipx install ufw-audit` is the canonical method
- Fix: `pyproject.toml` — `license-files = ["LICENSE"]` (was `[]`); added `Python :: 3 :: Only` classifier; replaced duplicate `Repository` URL with `Issues`

---

## v1.2.0

**2026-03-30**

- Fix: `i18n.current_lang()` now returns the actually loaded locale, not the requested one (relevant when falling back from an unsupported language)
- Fix: `manage_logs.py` — all three deletion paths (`single`, `multi`, `all`) guard `unlink()` with `try/except OSError`
- Fix: `i18n.init()` now raises `ValueError` with a clear message on malformed JSON locale files (was a bare `JSONDecodeError`)
- Fix: `_paths.resolve_share_dir()` guards `Path.resolve()` with `try/except OSError`
- Fix: `registry.py` — `config_key` validated against `VALID_CONFIG_KEYS` or `isidentifier()`; port format validated (`number/tcp|udp`); `config_key="fixed"` requires at least one port
- Fix: `report_markdown.py` — table detection uses `line.strip().startswith("|")` (handles indented tables); ASCII box lines in `_audit_log_to_html` matched by full-line regex instead of per-character scan
- Fix: `report_markdown.py` — `send_html_email()` checks for `sendmail` (not `mail`) since `sendmail` is what's actually called
- Fix: `output.py` — panorama label and port strings truncated to column width to prevent layout overflow
- Fix: `scoring.py` — `Deduction.context` validated against `{"local", "public", "structural"}`; cap now injects a synthetic `Deduction` into the breakdown during `finalize()` so the cap reason appears in the score breakdown
- Fix: `sysinfo.py` — private IPv4 regex centralised (`_PRIVATE_IPV4_RE`) and applied consistently; `172.x` detection corrected to RFC 1918 range only (`172.16–31`); `kernel` and `user` strings sanitized
- 639/639 unit tests

---

## v1.1.1

**2026-03-30**

- Hotfix: services with `Exposure.NO_RULE` (e.g. Avahi/mDNS 5353/udp) incorrectly showed ✖ in the panorama UFW column — a port with no explicit rule is covered by UFW's default deny policy and should show ✔

---

## v1.1.0

**2026-03-30**

- Feature: summary box messages now word-wrapped — long findings never truncated
- Feature: fix commands (`→ cmd`) displayed inline under each finding in the summary box
- Feature: red disclaimer shown under the "Possible improvements" block
- Bug fix: vsftpd `listen_port=X` directive not detected by port auto-detection
- Bug fix: Transmission `rpc-port` in `settings.json` not detected (JSON config)
- Internal: `_run()` timeout parameter; domain validation regex hardened; `ipaddress` used for Docker public-IP detection; log file read from end; dead code removed; typing improved
- 639/639 unit tests (+5)

---

## v1.0.4

**2026-03-29**

- Bug fix: ephemeral UDP ports were still flooding the LISTENING PORTS OVERVIEW section — `display_ports_overview()` was printing the raw `ss` output unfiltered. The display layer now applies the same ephemeral filter as the analysis layer.

---

## v1.0.3

**2026-03-29**

- Bug fix: ephemeral UDP ports were each generating an INFO message — on active desktops (Samba, browser, etc.) this produced hundreds of lines of noise. Ephemeral ports are now silently discarded.

---

## v1.0.1

**2026-03-29**

- Bug fix: SSH on a non-standard port (e.g. `Port 49732` in sshd_config) was always reported as listening on 22 — auto-detection now reads `/etc/ssh/sshd_config` correctly
- Bug fix: TCP ports above 32767 were wrongly classified as ephemeral — only UDP high ports are ephemeral; TCP LISTEN sockets are always server sockets
- 634/634 unit tests (15 new)

---

## v1.0

**2026-03-29**

- PyPI packaging — `pipx install ufw-audit` is now the recommended install method
- `--install-completion` — installs bash completion + `/usr/local/bin/` symlink for sudo PATH
- Bug fix: `services.exposure.not_listening` key displayed raw in audit output
- `install.sh` deprecated; Python 3.9 minimum; CI matrix updated (3.9/3.10/3.12)

---

## v0.22.1

**2026-03-29**

- Hotfix: UFW detected as inactive on non-English locale systems
- Root cause: `LANGUAGE` env var overrides `LC_ALL=C` in gettext — now cleared in all subprocess calls

---

## v0.22

**2026-03-29**

- 5 modules refactored (`__main__`, `firewall`, `services`, `scoring`, `output`) — no new features
- Box-border alignment fixed across all UI frames (wide Unicode + wrong overhead constant)
- `meta: dict` removed from `CheckResult` → typed `open_ports: List[str]`
- `FirewallStatus` caches subprocess output — no duplicate `ufw status` calls

---

## v0.21

**2026-03-28** — 619/619 tests

- 78 new tests + 3 bug fixes — pre-v1.0 quality pass
- False positive fix: CGNAT (`100.64/10`) and IPv6 private ranges were classified `OPEN_WORLD`
- False positive fix: commented config lines matched by port-detection regex
- `--manage-cron` gains a full email address book (add/delete/clear)
- `--fix` / `--manage-logs` / `--install-cron` / `--manage-cron` are now mutually exclusive

---

## v0.20

**2026-03-28** — 548/548 tests

- 17 new degraded-mode tests: `ss` absent, empty UFW rules, missing log file, combined degradation
- No crash, no false deductions when system tools are unavailable

---

## v0.19

**2026-03-28**

- GitHub Actions CI: pytest on every push/PR
- Python 3.8 / 3.10 / 3.12 matrix on ubuntu-latest

---

## v0.18

**2026-03-28** — 531/531 tests

- 26 new tests for `fixes.py` — `run_fixes()` fully covered
- Item classification, subprocess success/failure/timeout, interactive and auto (`--yes`) modes

---

## v0.17

**2026-03-28** — 505/505 tests

- 15 pre-existing test failures fixed across 6 files — no functional change to the audit
- Bug fix: DuckDNS domain extraction (`?domains=` query param)
- Bug fix: `cron_to_human` DOW range guard (`1-5` no longer routed to weekday path)

---

## v0.16

**2026-03-28**

- `Exposure.NOT_LISTENING` — registry port with no active listener → panorama ✔, no message (was ✖)
- `Exposure.LOOPBACK_NO_RULE` — loopback port without UFW rule → panorama ✔, INFO message (was ✖)
- Full regression suite completed (C6 × 9 services, C8, E1) — zero `pending` entries

---

## v0.15.1

**2026-03-27**

- Install script: trap + rollback on partial failure — partial installs are impossible
- Bug fix: open-any rule without `[N]` index no longer generates invalid fix command
- Fix UI: UFW subprocess output no longer leaks to terminal

---

## v0.15

**2026-03-27**

- Full security audit — 8 issues fixed (cron permissions, path traversal, HTML injection, log bounds)
- DRY: shared `checks/_run.py` + `_paths.py`, duplicate code removed from 7 files
- Bug fix: IPv6 wildcard rules (`Anywhere (v6)`) now fully detected and fixed by `--fix`
- 6 install script correctness fixes

---

## v0.14.1

**2026-03-26**

- False positive fix: loopback-bound services (Redis on `127.0.0.1`) no longer trigger ALERT
- DDNS false positives eliminated: system ports and dangling rules filtered out
- `--remove-cron` actually removed; VERSION banner corrected

---

## v0.14

**2026-03-25**

- `__main__.py` reduced from ~1820 to ~481 lines
- 5 new modules extracted: `display.py`, `fixes.py`, `manage_logs.py`, `panorama.py`, `sysinfo.py`
- `check_rules()` moved to `checks/firewall.py`

---

## v0.13

**2026-03-24**

- Multi-cron scheduler: multiple named audit jobs (`/etc/cron.d/ufw-audit-{name}`)
- 4-step schedule wizard (daily / weekdays / month days / custom expression)
- `--manage-cron` TUI: list, edit, delete jobs
- `cron.py` isolated module + 40+ unit tests

---

## v0.12

**2026-03-24**

- Email reports now include HTML (MIME multipart) alongside plaintext
- Zero-dependency markdown→HTML converter (pure Python stdlib)
- Cron nightly script generates and sends HTML emails automatically

---

## v0.11.4

**2026-03-23**

- Open-any regex fixed: trailing spaces, `/tcp`/`/udp` variants, semantic duplicates all detected
- Critical/high services exposed to internet → *Action required* (was *Possible improvements*)
- `TESTING.md` added — first formal manual regression test plan

---

## v0.11.3

**2026-03-23**

- `--install-cron`: schedule automated audits with optional email notification
- `--manage-logs`: interactive UI to browse and delete saved reports
- Services panorama: compact table of all 22 services after each audit
- Auto-fix (`-y`) now shows warning banner + full command summary

---

## v0.11.2

**2026-03-22**

- Banner fully redesigned: "UFW-AUDIT" in Doom block ASCII art, 80-char width
- Port exposure messages rewritten to be fully self-explanatory
- Port table moved to verbose mode (`-v`) only

---

## v0.11.1

**2026-03-22**

- Security patch: 20 vulnerabilities fixed across 3 rounds
- Shell injection, ANSI injection, path traversal, symlink attacks, ReDoS, JSON bomb
- File permissions hardened: report files `0o600`, config directory `0o700`

---

## v0.11

**2026-03-22**

- Field-tested on Mint 22.3, Debian 13, Kali Rolling — all bugs fixed
- `--quiet` mode with exit codes 0–3 for scripting and cron
- Virtualisation detection: libvirt/KVM, VirtualBox, VMware, LXD, Snap network packages

---

## v0.10

- Optional GeoIP2 geolocation (country + operator), whois removed
- Short CLI flags (`-v`, `-d`, `-f`, `-q`, `-n`)
- Score scope disclaimer added to output

---

## v0.9

- Complete rewrite in Python (from bash)
- 421 unit tests
- Transparent installer with manifest and rollback
- 22 services with two-axis risk context (exposure + threat)
- Bilingual EN/FR interface
- Bash completion
