*[Lire en français](CHANGELOG_FULL_FR.md)* · *[TL;DR](../CHANGELOG.md)*

# UFW-audit — Changelog

All notable changes to this project are documented here.

---

## [v1.25.0] — 2026-04-26

### Features

- **CIS compliance mapping inline** (`ufw_audit/display.py`, `ufw_audit/cis_refs.py`) — each finding with a formal CIS code in the audit summary box now displays its machine-readable code `[CIS:X.Y.Z]` (dimmed, below the finding line); the code is retrieved via `get_cis_code(item.key)` and injected by `_add_finding_lines()` before the `--explain` hint; entries without a formal CIS section number (best-practice rules) are left unlabelled so the box remains uncluttered for the 34 rules that do not map to a specific CIS benchmark section

- **`--verbose` CIS ref text** (`ufw_audit/display.py`) — in verbose mode, each WARN/ALERT finding already emitted the full CIS reference string (dimmed) via `print_dim(cis)`; best-practice entries (e.g. `Best practice — Ensure bridge interfaces do not bypass UFW FORWARD rules`) are now correctly included — previously they carried a misleading `"CIS..."` prefix in `cis_refs.json` and were displayed as if they were formal CIS controls

- **Best-practice entries renamed** (`ufw_audit/data/cis_refs.json`) — 34 entries that describe hardening recommendations without a formal CIS benchmark section number now use the prefix `"Best practice — ..."` instead of `"CIS Ubuntu 22.04 — ..."` or `"CIS: ..."`, preventing confusion with entries that have an actual benchmark section; affected categories include virtualisation bridge bypass, SSH public-key auth, process accounting, login.defs, PAM password history, Samba hardening, disk SMART, and others; `get_cis_ref()` returns the appropriate string for each category

- **`cis_refs.json` restructured** (`ufw_audit/data/cis_refs.json`) — the flat `"key": "CIS ref string"` format is replaced by `"key": {"ref": "...", "code": "CIS:X.Y.Z"|null}`; 133 entries total: 99 CIS Ubuntu 22.04 (with `code: "CIS:X.Y.Z"`), 4 CIS Docker (with `code: "CIS Docker:X.Y"`), 34 best-practice (with `code: null` — no formal benchmark section number); the `_load()` cache and `get_cis_ref()` function in `cis_refs.py` are updated accordingly

- **`get_cis_code()`** (`ufw_audit/cis_refs.py`) — new public function returning the short machine-readable code (e.g. `"CIS:5.2.7"`, `"CIS:3.5.1.1"`, `"CIS Docker:5.4"`) or `None` for best-practice entries; backed by the same `_load()` cache as `get_cis_ref()`; used by `display.py` for summary box injection

- **`explain.py` CIS refs decoupled from locale** (`ufw_audit/explain.py`) — `run_explain()` (terminal path) and the curses TUI path both now call `get_cis_ref(norm)` directly instead of `t(f"explain_cis.{norm}")`; the `explain_cis` section (170 key-value pairs) has been removed from `ufw_audit/locales/en.json` and `fr.json`; locale files shrink by ~170 strings each; CIS refs remain language-independent (always in English, sourced from the benchmark)

- **5 new services** (`ufw_audit/data/services.json`) — SMTP/Postfix/Exim (25/tcp, risk=high, packages: postfix/exim4), NFS Server (2049/tcp+udp, risk=high, package: nfs-kernel-server), Jenkins (8080/tcp, risk=high, package: jenkins), OpenVPN (1194/udp, risk=medium, package: openvpn), Squid Proxy (3128/tcp, risk=medium, packages: squid/squid3); registry grows from 27 to **32 services**

- **`_ipt_has_conntrack` ACCEPT fix** (`ufw_audit/checks/iptables_nftables.py`) — regex updated from `r"(--state|--ctstate)\s+[A-Z,]*ESTABLISHED"` to `r"(--state|--ctstate)\s+[A-Z,]*ESTABLISHED[^\n]*-j\s+ACCEPT"`; the prior regex returned True for any rule mentioning ESTABLISHED, including `-j DROP` or `-j REJECT` rules; the same fix had already been applied to the nftables path (v1.24.0) where `ct state established drop` was correctly rejected — the iptables path was the remaining gap documented in the v1.24.0 CHANGELOG_FULL as "to be added in v1.25.0"

- **FORWARD DROP/REJECT → `result.ok()`** (`ufw_audit/checks/iptables_nftables.py`) — a new `elif snapshot.forward_policy in ("DROP", "REJECT")` branch emits `result.ok(message=_t("iptables_nft.forward_ok", policy=...), key="iptables_nft.forward_ok")`; previously this state was silent (no finding emitted), inconsistent with the INPUT path which always emits either an alert, ok, or info; locale key `forward_ok` added as `"Default FORWARD policy: {policy} (recommended)"` in both `en.json` and `fr.json`

### Tests

| File | Class | Change |
|------|-------|--------|
| `tests/test_cis_refs.py` | `TestGetCisRef` | new — 12 tests: known key, iptables/nft key, kernel_modules key, new iptables/kernel keys, best-practice prefix, no-CIS prefix for best-practice, unknown/partial/empty key, services_state, mac_policy |
| `tests/test_cis_refs.py` | `TestGetCisCode` | new — 11 tests: formal entry, code format pattern, Docker entry, best-practice returns None, samba/disk best-practice, unknown key, auditd code, iptables_nft forward code, code format rejects bare colon, code format rejects alpha section |
| `tests/test_cis_refs.py` | `TestLoadCache` | new — 4 tests: returns dict, entries have ref+code, cache identity, empty dict on missing file (monkeypatch) |
| `tests/test_cis_refs.py` | `TestJsonSchema` | new — 10 tests: key pattern, non-empty refs, code string/null, formal refs start with CIS, best-practice refs no CIS-section prefix, code pattern, minimum count, no duplicates, best-practice count range, section number appears in ref |
| `tests/test_cis_refs.py` | `TestNoStaleExplainCis` | new — 2 tests: `explain_cis` absent from `en.json` and `fr.json` |
| `tests/test_domain_scores.py` | `TestCISReferences` | updated — `test_explain_cis_all_keys_resolve`: assertion softened to accept best-practice refs (`startswith("Best practice")`); `test_explain_cis_locale_independent` renamed from `test_explain_cis_fr_locale` |
| `tests/test_iptables_nftables.py` | `TestIptableParsers` | +2 tests — `test_has_conntrack_drop_action_is_false` (`--ctstate ESTABLISHED -j DROP` → False), `test_has_conntrack_state_form_without_accept_is_false` (`--state ESTABLISHED -j REJECT` → False) |
| `tests/test_iptables_nftables.py` | `TestForwardPolicy` | +4 tests — `test_ok_when_forward_drop`, `test_ok_when_forward_reject`, `test_forward_ok_is_ok_level`, `test_forward_drop_no_deduction` |
| `tests/test_services.py` | `TestNewServicesRegistry` | new — 15 tests: smtp (exists/risk/port), nfs (exists/risk/ports), jenkins (exists/risk/port), openvpn (exists/risk/port), squid (exists/risk/port) |

✅ 4200/4200 unit tests (+60 from v1.24.1)

---

## [v1.24.1] — 2026-04-25

### Fixes

- **Debian kernel version parsing** (`ufw_audit/checks/kernel_modules.py`) — `_KVER_RE` regex extended from `^(\d+)\.(\d+)\.(\d+)-(\d+)` to `^(\d+)\.(\d+)\.(\d+)[-+]` to handle Debian-style kernel versions where the separator is `+` rather than `-` (e.g. `6.12.74+deb13+1-amd64`); `_kernel_sort_key` rewritten — after matching the `[-+]` separator, the rest of the string is scanned for an optional leading integer (the ABI number); Debian versions have no integer immediately after `+`, so `abi` falls back to `0` and sorting still works correctly across Ubuntu and Debian kernels; `_query_apt_kernel_update` adds a secondary primary path: `apt-cache policy linux-image-$(uname -r)` for systems where the `linux-image-generic` meta-package is absent (Debian uses the full versioned package name directly); apt upgrade command generalised from `sudo apt upgrade linux-image-generic` to `sudo apt upgrade` (works on both Ubuntu and Debian); combined effect on Debian 13: on systems where all three issues are present, `installed_kernels` becomes empty → early return → apt check finding never reached → no ✔ [OK] displayed even when kernel was current
- **v1.24.0 changelog correction** — CHANGELOG.md, CHANGELOG_FR.md, CHANGELOG_FULL.md, CHANGELOG_FULL_FR.md corrected: INPUT ACCEPT emits `result.alert(points=3)` — ALERT −3 pts, not WARN −1 pt; FORWARD ACCEPT remains WARN −1 pt; `iptables -S` (not `iptables -L INPUT --line-numbers`) documented; "detects active backend" revised to "detects available firewall layer"

### Tests

| File | Class | Change |
|------|-------|--------|
| `tests/test_kernel_modules.py` | `TestKernelSortKey` | +2 tests — `test_debian_style_version_parseable` (`6.12.74+deb13+1-amd64` → `(6, 12, 74, 0)`), `test_debian_sorts_correctly_against_ubuntu` (Debian > older Ubuntu) |
| `tests/test_kernel_modules.py` | `TestParseInstalledKernels` | +2 tests — `test_parses_debian_style_kernel`, `test_parses_mixed_ubuntu_debian` |
| `tests/test_kernel_modules.py` | `TestKernelAptUpdate` | +2 tests — `test_debian_style_kernel_up_to_date`, `test_debian_style_kernel_update_available` |

✅ 4140/4140 unit tests (+6 from v1.24.0)

---

## [v1.24.0] — 2026-04-25

### Features

- **CHECK 46 — iptables/nftables audit** (`ufw_audit/checks/iptables_nftables.py`) — new check gated on `not fw_status.active`; when UFW is inactive, audits the underlying firewall layer: infers active firewall layer (nftables preferred, fallback to iptables); checks INPUT default policy (`iptables -S` / `nft list ruleset`); checks FORWARD default policy; checks for ESTABLISHED/RELATED conntrack rule pattern; ALERT −3 pts for INPUT ACCEPT (critical exposure); WARN −1 pt for FORWARD ACCEPT; WARN −1 pt for absent conntrack; FORWARD policy `unknown` → INFO (no deduction); new section `IPTABLES / NFTABLES AUDIT` in runner; new locale section `iptables_nft.*` in en.json / fr.json
- **Audit profile in banner** — active profile (`server` / `desktop` / `container`) shown as ℹ [INFO] immediately after the banner, before any section
- **5 new critical services** (`ufw_audit/data/services.json`) — Telnet Server (23/tcp, `inetutils-telnetd` / `telnetd`, binaries `in.telnetd` / `telnetd`); RDP/xRDP (3389/tcp, `xrdp`); MongoDB (27017/tcp, `mongodb` / `mongodb-org` / `mongodb-server` / `mongodb-server-core`); Elasticsearch (9200/tcp, `elasticsearch`); Memcached (11211/tcp + 11211/udp, `memcached`); registry grows from 23 to **28 services**; `service_risk` locale entries added for all 5 (EN + FR)
- **Installed-but-inactive critical/high services** (`ufw_audit/checks/services.py`, `ufw_audit/runner.py`, `ufw_audit/display.py`) — `_check_single_service`: `INACTIVE_DISABLED` state on `is_high_or_critical` service emits `result.warn("services.state.installed_inactive_critical")` instead of `result.info("services.state.inactive_disabled")` (early return preserved — no port exposure noise); `_check_port_exposure`: `NOT_LISTENING` exposure on high/critical service emits `result.warn()` instead of `result.info()`; `runner.py`: risk context condition extended from `snap.is_active` to `snap.is_active or (snap.installed and not snap.is_active and snap.service.is_high_or_critical)`; `display.py` `build_risk_context_entries` updated with same guard; `services.state.installed_inactive_critical` added to en.json / fr.json

### Fixes & improvements

- **UFW inactive context** (`runner.py`) — when UFW is inactive: services section shows explicit `ufw_inactive_context` INFO banner; NetBIOS-related service ports downgraded from WARN to INFO; services exposure correctly assessed against underlying firewall; IPv6 check downgraded to INFO; "all listening ports covered" message suppressed
- **`iptables_nftables.py` quality pass** — `nft add chain` corrected to `nft chain` in two locations (INPUT line 183, FORWARD line 246); conntrack detection (nftables path) regex hardened from `established` to `ct\s+state\s+[^\n]*\bestablished\b[^\n]*\baccept\b`, adding explicit ACCEPT requirement to prevent false positives on DROP rules; iptables path (`_ipt_has_conntrack`) checks ESTABLISHED pattern only — ACCEPT requirement to be added in v1.25.0; FORWARD policy `unknown` state handled with `result.info(key="iptables_nft.forward_unknown")` instead of being silently ignored; cmd assertions in tests changed to `startswith` for backend-agnostic validation
- **Kernel apt update availability** (`checks/kernel_modules.py`) — `_query_apt_kernel_update() -> Tuple[bool, bool, str]` returns `(checked, update_available, candidate)`; primary path: `apt-cache policy linux-image-generic` (Ubuntu/Mint meta-package); fallback: `apt list --upgradable` scanning for `linux-image-\d` lines (Debian, no meta-package); ✔ [OK] emitted when `apt_checked=True` and `apt_update_available=False`; `apt_update_available`, `apt_candidate_kernel`, `apt_checked` fields added to `KernelModulesSnapshot`; apt update block placed before `len(kernels) <= 1` early return so single-kernel systems also get the apt freshness result

### Tests

| File | Class | Change |
|------|-------|--------|
| `tests/test_iptables_nftables.py` | new file | 51 tests — `TestIPTablesNFTablesSnapshot` (snapshot fields), `TestCheckIPTablesNFTables` (INPUT/FORWARD policies, conntrack, nftables backend, UFW active skipped), `TestForwardPolicy` (both accept + forward accept), `TestConntrackDetection` (regex edge cases), `TestNFTablesBackend` (nft chain cmd), `TestForwardUnknown` (info level) |
| `tests/test_kernel_modules.py` | `TestKernelAptUpdate` | +9 tests — `test_update_available_emits_info`, `test_update_is_info_level`, `test_update_has_apt_cmd`, `test_up_to_date_ok_when_apt_checked`, `test_no_up_to_date_ok_when_apt_not_checked`, `test_no_candidate_no_info`, `test_single_kernel_update_available`, `test_single_kernel_up_to_date`, `test_apt_candidate_in_message` |
| `tests/test_services.py` | `TestInactiveDisabled` | +5 tests — `test_warn_for_critical_inactive_disabled`, `test_warn_for_high_inactive_disabled`, `test_no_deduction_for_critical_inactive`, `test_no_port_check_for_critical_inactive`; `test_info_finding_for_inactive` updated to use `risk="low"` |
| `tests/test_services.py` | `TestPortExposureFindings` | +4 tests — `test_not_listening_critical_adds_warn`, `test_not_listening_high_adds_warn`, `test_not_listening_critical_no_deduction`; `test_not_listening_adds_info` updated to `risk="low"` |

✅ 4134/4134 unit tests (+92 from v1.23.0)

---

## [v1.23.0] — 2026-04-24

### Features

- **`--format=FORMAT`** (`ufw_audit/cli.py`) — new canonical flag accepting `json`, `json-full`, `csv`, `markdown`, `html`; sets the same internal booleans (`json_mode`, `json_full`, `csv_mode`, `markdown_mode`, `html_mode`) as the legacy flags; both `--format=json` and `--format json` forms supported; help text condensed from 5 lines to 2 (`--format=FORMAT` + shorthands `-j / -J`); examples updated to `--format=json | jq`; legacy flags (`--json`, `-j`, `-J`, `--output csv/json/markdown`, `--html`) kept as fully working aliases — zero breaking change
- **`--check=list`** (`ufw_audit/cli.py`, `ufw_audit/__main__.py`) — special value for `--check=` that prints all 31 filterable section names in a columnar layout, notes on prefix matching, always-on core checks, and example usage; executes before `require_root()` — no sudo required; `--check=LIST` help line updated; bash completion suggests `list` + all section names
- **`--manage-logs` log preview** (`ufw_audit/manage_logs.py`) — pressing Enter on a log file opens a full-screen scrollable viewer (`_curses_preview_log`); two modes toggle with `s`: `[FULL]` (raw log) and `[SUMMARY]` (score block + ALERT/WARN findings); `g`/`G` jump to first/last line; `↑↓ / PgUp/PgDn` scroll; Esc returns to list; Enter disabled when files are marked (bulk-delete mode)
- **`_extract_summary_view`** (`ufw_audit/manage_logs.py`) — parses log lines to extract: (1) summary block from last `=*62` separator; (2) all `[ALERT]` findings with 4-space continuation lines; (3) all `[WARN]` findings with continuation lines; section headers `── ALERTS ──` / `── WARNINGS ──`; falls back to `✔ No alerts or warnings.` when clean
- **Risk context scope qualifier** (`ufw_audit/display.py`) — `display_risk_context` gains `is_local: bool = False`; `build_risk_context_entries` gains `network_context: str = ""`; when local, service labels display as `{level} • LAN` (e.g. `CRITIQUE • LAN`); public/DDNS contexts unchanged; `runner.py` and `__main__.py` updated to pass context

### Features (continued)

- **`--install-cron` curses TUI** (`ufw_audit/cron.py`) — `run_install_cron()` now wraps `curses.wrapper()` and falls back to the plain text wizard when curses is unavailable or TTY absent; `_run_install_cron_curses()` provides inline readline via `_curses_readline`, Esc-to-cancel on every prompt, live natural-language schedule preview, and colour headers; plain text path renamed to `_run_install_cron_plain()`
- **`--manage-cron` curses TUI** (`ufw_audit/cron.py`) — `run_manage_cron()` dispatches to `_run_manage_cron_curses()` or `_run_manage_cron_plain()` with the same curses/fallback pattern; new sub-screens: `_curses_edit_sub`, `_curses_email_list_sub`, `_curses_email_store_sub`, `_curses_schedule_wizard`, `_curses_status_flash`, `_curses_readline`; `_CronQuit` exception used for clean sub-screen exits; `_init_colors_cron()` centralises colour-pair setup; `_atomic_write()` helper for safe cron file updates
- **`ufw_audit/_tty.py`** — new module: `read_line(prompt) → str | None`; raw-mode character reader using `termios`/`tty`/`select`; Esc returns `None` (cancel/back), Enter returns `""`, printable chars echoed with backspace support; 50 ms `select` window drains arrow-key escape sequences to distinguish from standalone Esc; Ctrl+D returns `None`; graceful `input()` fallback when stdin is not a TTY (tests, pipes)

### Fixes

- **`compare.py` baseline `None` vs `[]` semantics** — `AuditBaseline.finding_keys` type changed from `list[str]` to `list[str] | None`; `None` = pre-v1.22 baseline (key absent in serialised JSON, skip diff to avoid false-positive flood); `[]` = legitimately clean audit (diff produces no new/resolved keys as expected); `load_baseline()` uses `isinstance(raw.get("finding_keys"), list)` guard and returns `None` for absent/invalid; `compute_delta()` gates on `prev.finding_keys is not None` instead of truthiness — an empty `[]` now correctly triggers the diff

### Polish

- **TUI help bar harmonization** (`explain.py`, `manage_logs.py`) — `--explain` picker: `navigate` → `move`; detail screen: `↑↓/PgUp/PgDn` → `↑↓ / PgUp/PgDn`, `Esc: back to list` → `Esc: back`; preview viewer: `PgUp PgDn` → `PgUp/PgDn`
- **Bash completion** — `--format=` with 5 completions; `--check=` suggests `list` + 31 section names; `--html` added to `long_opts`
- **`history.py` atomic write** — `_HISTORY_FILE.write_text()` replaced by `os.open(O_WRONLY|O_CREAT|O_TRUNC, 0o600)` + `os.fdopen()` + `os.replace()` for permissions-correct crash-safe rotation; prevents truncated history file on process kill during write
- **`report_markdown.py` link handling** — `_inline_format()`: Markdown link regex applied before `html.escape()` so URL characters (`&`, `<`, `>`) are not mangled; `<li>` items in the audit-log-to-HTML converter now wrapped in explicit `<ol>` blocks; unused `import email` removed from `send_html_email()`
- **Checks subprocess hardening** — `auth_log.py` and `logs.py` now pass `env=_C_LOCALE_ENV` to ensure ASCII output from system commands; bare `except Exception` replaced with `except (OSError, subprocess.SubprocessError, subprocess.TimeoutExpired)` in both; `ssl_certs.py` cert-date subprocess gains `timeout=10`; `sysinfo.py` uses `removeprefix("^")` instead of `lstrip("^")` for safe regex anchor stripping
- **`markdown_output.py` engine access** — uses `engine.breakdown` instead of `getattr(engine, "_deductions", [])` for public API access to deductions

### Test suite hardening

- **`tests/helpers.py`** — new shared utilities module centralising helpers previously duplicated across all test files: `_t(key, **kw) → str` (translation stub returning raw key), `levels(result) → list[str]`, `_has_finding(result, key, level) → bool`, `_get_finding(result, key)`, `_finding_level(result, key) → FindingLevel`, `_deduction_keys(result) → list[str]`, `_deduction_points(result) → int`; 62 test files updated to `from tests.helpers import _t` (and other helpers as needed), removing ~200 lines of boilerplate

### Tests

| File | Class | Change |
|------|-------|--------|
| `tests/test_cli.py` | `TestFormatFlag` | +22 tests — all 5 formats, space form, invalid, conflicts, legacy aliases |
| `tests/test_cli.py` | `TestCheckSkipFlags` | +4 tests — `--check=list`, space form, case-insensitive, default |
| `tests/test_manage_logs.py` | `TestExtractSummaryView` | +7 tests — summary block, ALERT/WARN, continuation lines, empty, no-summary fallback |
| `tests/test_display_explain_hint.py` / `tests/test_runner.py` | scope qualifier | +2 tests — `is_local=True` appends `• LAN`; `network_context="local"` in `build_risk_context_entries` |

✅ 4042/4042 unit tests (+35 from v1.22.3)

---

## [v1.22.3] — 2026-04-20

### Bugfixes

- **`checks/ports.py`**: `_split_addr_port()` signature changed from `(addr, port)` to `(addr, port, iface)` — the interface scope suffix (e.g. `%virbr0`) is now captured and returned separately; `ListeningPort` gains `iface: str = ""` field; `is_all_interfaces` returns `False` when `iface` is set — fixes `0.0.0.0%virbr0:67` (dnsmasq bound to KVM virbr0 bridge) appearing as an all-interfaces port in the exposure table
- **`exposure.py`**: UDP ports above 32767 excluded from the exposed-ports set in `compute_exposure()` — mirrors the `PortCategory.EPHEMERAL` filter in `check_ports()`; avahi/mDNS ephemeral sockets (e.g. 37238/udp, 52289/udp) no longer appear in the attack surface table

### Feature

- **`runner.py`**: `ufw status verbose` output printed after UFW rule findings in verbose mode (`-v`) — provides immediate rule context without requiring a separate `sudo ufw status verbose` call

### Tests

| File | Change | Detail |
|------|--------|--------|
| `tests/test_ports.py` | +2 tests | `TestSplitAddrPort`: all assertions updated for 3-tuple return; `test_ipv4_virbr0_iface` added; `TestListeningPort`: `test_is_all_interfaces_false_when_iface_scoped` added |
| `tests/test_exposure.py` | 1 renamed + 1 added (55 total) | `test_high_numbered_listen_port_is_shown` → `test_high_numbered_tcp_port_is_shown`; `test_high_numbered_udp_port_excluded` asserts UDP > 32767 is NOT shown |

✅ 4007/4007 unit tests (+2 from v1.22.2)

---

## [v1.22.2] — 2026-04-20

### Bugfixes

- **`ssl_certs.py`**: snakeoil cert filter moved to a global post-collection step — previously only applied to `/etc/ssl/private` glob; certs referenced from nginx/apache/postfix config were not excluded, causing false ALERT on Ubuntu/Mint systems with default nginx install
- **`exposure.py`**: `compute_exposure` now checks `ddns.warn` in `bad_keys` — adds an `elif` branch returning `⚠ warn` with `internet_facing_ddns` detail when DDNS is active (was unconditionally `✔ ok` for local networks regardless of DDNS)
- **`exposure.py`**: removed `lp.port < 32768` ephemeral-port heuristic from the `exposed` port set — LISTEN-state sockets are always server-side; the filter was incorrectly hiding high-numbered servers (e.g. 49732/tcp for non-standard SSH)
- **`runner.py`**: SSH `local_exposure_note` and `nonstandard_port_note` now emitted as two separate `print_info` calls — previously both were passed as a single string to `display_risk_context`, causing them to appear concatenated on one line
- **`locales/en.json`, `locales/fr.json`**: removed `ℹ ` prefix from `service_risk.local_exposure_note` (double prefix since `print_info` already prepends `ℹ [INFO]`); added `exposure.internet_facing_ddns` key

### Tests

| File | Change | Detail |
|------|--------|--------|
| `tests/test_exposure.py` | 2 tests renamed + 3 added (54 total) | `test_ephemeral_port_excluded` → `test_high_numbered_listen_port_is_shown` (assert port IS in detail); `test_port_32768_is_ephemeral` → `test_port_32768_is_shown` (assert port IS in detail); +3 DDNS tests: `test_ddns_warn_is_warn`, `test_ddns_warn_detail_contains_ddns`, `test_public_overrides_ddns` |

✅ 4004/4004 unit tests (+3 from v1.22.1)

---

## [v1.22.1] — 2026-04-20

### Source fix

- **`recurrence.py`**: unified float-tolerance policy — `update_recurrence` now normalizes floats to `int` via `int(val)` (consistent with `load_recurrence`); removed unused `import os`

### Tests

| File | Change | Detail |
|------|--------|--------|
| `tests/test_correlation.py` | +1 test (51 total) | `test_message_uses_translation_key` — verifies `t(rule.message_key)` is called with the correct key by injecting a `fake_t` returning `"translated:{key}"` |
| `tests/test_exposure.py` | assertion strengthened (51 total) | `test_fw_policy_none_does_not_crash`: `assert color == "alert"` (was too-weak `in (...)`) — documents that `None` falls into the `not in ("deny","reject")` branch |
| `tests/test_recurrence.py` | +1 test (29 total) | `test_float_value_in_prev_is_normalized` — `update_recurrence({"k": 1.9}, {"k"})` → `int(1.9)=1` then `+1` → `2` |

✅ 4001/4001 unit tests (+5 from v1.22.0)

---

## [v1.22.0] — 2026-04-20

### TL;DR
- **Signal correlation** — 5 compound-risk rules (root+no-fail2ban, password-auth+brute-force, root+password, NOPASSWD+SUID, stale+unmonitored, fully-blind); fires post-finalize on ALERT/WARN key combinations
- **Recurring tracker** — per-key consecutive-audit counters; `~/.config/ufw-audit/recurrence.json`; atomic write; load filters invalid entries
- **Exposure analysis** — port exposure grouping; `fw_policy` allowlist fix; direct `lp.port` attribute
- **Comparative report** — `finding_keys` in baseline; `new_finding_keys`/`resolved_finding_keys` in delta; migration guard for pre-v1.22 baselines
- **IPv6 fix** — link-local/ULA-only: WARN −2 downgraded to INFO (no global IPv6 → not internet-reachable)
- **Kernel message fix** — suppress redundant "(running: X, latest: X)" when running == most_recent
- **Snakeoil cert** — filtered from `/etc/ssl/private` scan on Debian/Ubuntu
- **`--explain`** — 87→112 keys (+25 across 7 new groups)
- **`backup` domain** — moved from `hardening` to `disk`

### Signal correlation engine (`correlation.py`)

**New file.** Evaluates compound risk patterns post-finalize.

**`CorrelationRule`:**
- `all_of: frozenset[str]` — every key must be in active ALERT/WARN findings
- `any_of: frozenset[str]` — at least one must be active (empty = no constraint)
- `matches(active: set[str]) -> bool` — pure predicate

**`CorrelatedFinding`:**
- `key`, `level`, `message`, `triggered_by: list[str]` — sorted union of matched keys

**`run_correlations(engine, t)`:**
- Collects active keys from `engine.findings` (ALERT/WARN only)
- Evaluates `_RULES` list; deduplicates by rule key
- Returns `list[CorrelatedFinding]`

**Built-in rules (`_RULES`):**

| Key | all_of | any_of | Level |
|-----|--------|--------|-------|
| `corr.root_no_protection` | `ssh.permit_root_login` | `fail2ban.not_installed`, `fail2ban.service_inactive` | ALERT |
| `corr.password_auth_under_attack` | `ssh.password_auth`, `auth_log.brute_force` | — | ALERT |
| `corr.ssh_root_password` | `ssh.permit_root_login`, `ssh.password_auth` | — | ALERT |
| `corr.privilege_escalation` | `file_perms.sudoers_nopasswd_all`, `suid_audit.unexpected_suid` | — | WARN |
| `corr.stale_unmonitored` | `updates.security_pending` | `fail2ban.not_installed`, `fail2ban.service_inactive` | WARN |
| `corr.fully_blind` | `firewall.logging_off`, `fail2ban.not_installed` | `auditd.not_installed`, `auditd.service_inactive` | WARN |

**Tests:** 49 tests in `tests/test_correlation.py`

### Recurring finding tracker (`recurrence.py`)

**New file.** Counts consecutive audit appearances per finding key.

**Storage:** `~/.config/ufw-audit/recurrence.json` — `{"finding.key": N, ...}`

**`load_recurrence(path=None) -> dict[str, int]`:**
- Filters: key must be non-empty string; value must be `int|float` and `>= 0`; coerced to `int`
- Returns `{}` on any read/parse error

**`save_recurrence(data, path=None) -> None`:**
- Atomic write: `tmp = dest.with_name(dest.name + ".tmp")` defined before `try`
- `tmp.replace(dest)` on success; `tmp.unlink(missing_ok=True)` on `OSError`

**`update_recurrence(prev, active_keys) -> dict[str, int]`:**
- For each key in `active_keys`: `val = prev.get(key, 0)`; if not `int` or `< 0`, `val = 0`; result `val + 1`
- Keys absent from `active_keys` are dropped (finding resolved)

**Tests:** 27 tests in `tests/test_recurrence.py`

### Port exposure analysis (`exposure.py`)

**New file.** Groups exposed listening services by interface scope and risk level.

**Fixes:**
- `fw_policy` check: `elif fw_policy not in ("deny", "reject")` — unknown/None treated as permissive (was `== "allow"`)
- Ephemeral-port filter: `lp.port < 32768` (direct attribute, was `int(lp.port_proto.split("/")[0]) < 32768`)

**Tests:** 43 tests in `tests/test_exposure.py`

### Comparative report — finding-key diff (`compare.py`)

**`AuditBaseline`:**
- New field: `finding_keys: list[str] = field(default_factory=list)` — sorted ALERT/WARN keys from `engine.findings`
- `load_baseline()` now reads and populates `finding_keys` from JSON

**`AuditDelta`:**
- New fields: `new_finding_keys: list[str]` / `resolved_finding_keys: list[str]` — with `field(default_factory=list)` for backwards compat
- `is_empty()` updated to include both new fields

**`compute_delta(prev, curr)`:**
- Migration guard: `if prev_keys:` — when `prev.finding_keys` is empty (older baseline), key diff is skipped entirely
- Prevents false-positive flood on first run after upgrade to v1.22

**`display_delta(delta, t, output_mod)`:**
- New loops: `print_warn` for each `new_finding_keys`; `print_ok` for each `resolved_finding_keys`

### Bug fixes

**Port exposure color consistency (`exposure.py`):**
- Open ports color: `color = "alert" if not fw_active or fw_policy not in ("deny", "reject") else "warn"` — was `fw_policy == "allow"`, causing `"unknown"` and `None` policies to produce `warn` instead of `alert`, inconsistent with the firewall item logic
- New tests: `test_with_fw_allow_policy_port_is_alert`, `test_with_fw_unknown_policy_port_is_alert`, `test_port_32767_is_stable`, `test_port_32768_is_ephemeral`, `test_not_installed_overrides_password_auth`, `test_info_findings_do_not_affect_ssh`, `test_items_order`

**IPv6 false positive (`checks/ipv6.py`):**
- New `IPv6Snapshot.has_global_ipv6: bool = False` field
- `_read_global_ipv6()`: parses `ip -6 addr show`; returns `True` if any address matches `2000::/3`; excludes `::1`, `fe80::/10`, `fc00::/7`
- In `check_ipv6()`: when UFW IPv6 disabled + listeners present + `not has_global_ipv6` → INFO instead of WARN −2 pts; uses new locale key `ipv6.ufw_disabled_listeners_link_local`

**Kernel obsolete message (`checks/kernel_modules.py`):**
- When `running == most_recent`: uses `kernels_obsolete_same` key (no parenthetical)
- When different: uses existing `kernels_obsolete` key with both values
- New locale keys: `kernel_modules.kernels_obsolete_same` (EN + FR)

**Snakeoil cert (`checks/ssl_certs.py`):**
- `if "snakeoil" not in cert.name.lower():` added before `_add_path()` call in `/etc/ssl/private` glob loop
- Prevents Debian/Ubuntu system test cert `ssl-cert-snakeoil.pem` from triggering TLS audit

**Implicit services warning (`display.py`):**
- `print_audit_summary()` gains `fw_policy: str = "deny"` parameter
- Condition: `if implicit_svcs and fw_policy not in ("deny", "reject"):` — suppresses message on default-deny policies
- `__main__.py` passes `fw_policy` to `print_audit_summary()`

**SSH non-standard port note (`runner.py`):**
- When `snap.service.id == "ssh"` and no port starts with `"22/"`: appends `service_risk.nonstandard_port_note` to risk note
- New locale keys: `service_risk.nonstandard_port_note` (EN + FR)

### Quality pass

**`domain_scores.py`:**
- `"backup": "disk"` — moved from `"hardening"` catch-all; backup solutions correctly grouped with disk health

**`explain.py`:**
- 87 → 112 explain keys (+25)
- New groups: Authentication Logs (2), Umask (2), Firewall Logging (1), TLS / SSL Certificates (3), Systemd Timers (3), Firmware (2), Docker (4 moved/added)

**Locale additions (`en.json` / `fr.json`):**
- `compare.key_appeared` / `compare.key_resolved`
- `service_risk.nonstandard_port_note`
- `kernel_modules.kernels_obsolete_same`
- `ipv6.ufw_disabled_listeners_link_local`
- `auth_log.no_logins` updated (shows days count)
- Correlation rule message keys (`corr.*`)

### Tests

| File | Count | Notes |
|------|-------|-------|
| `tests/test_correlation.py` | 42 | New; `TestCorrelationRuleMatches` (8); `TestRunCorrelationsNoMatch` (2); `TestRunCorrelationsMatch` (per rule + multi-rule + dedup); `TestRunCorrelationsEdgeCases` |
| `tests/test_exposure.py` | 50 | New; `FakeEngine` + `_FakePortsSnapshot`; fw_policy allowlist (deny/reject/allow/unknown/None); boundary tests (32767 included, 32768 excluded); `test_not_installed_overrides_password_auth`; `test_info_findings_do_not_affect_ssh`; `test_items_order`; full-exposure scenario |
| `tests/test_recurrence.py` | 27 | New; normalize/filter/atomic-write hardening; `test_no_tmp_file_leftover`; `test_large_volume_round_trip` (10k keys) |
| `tests/test_ipv6.py` | 57 (+26) | `TestReadGlobalIPv6`: global unicast, link-local, ULA fc/fd, loopback, empty, monkey-patch `_run` |
| `tests/test_explain.py` | 63 | Key count assertion updated (87→112) |

✅ **3996/3996 unit tests (+218 from v1.21.0)**

---

## [v1.21.0] — 2026-04-19

### TL;DR
- **CHECK 43** — TLS/SSL cert expiry: Let's Encrypt + `/etc/ssl/private` + nginx/apache2/postfix configs; expired → ALERT −2 pts; <7 d → ALERT; <30 d → WARN; total capped −4 pts
- **CHECK 44** — Systemd timers: curl/wget pipe-to-shell in ExecStart → WARN −2 pts; world-writable .sh → WARN −1 pt; user-created root timer → INFO
- **CHECK 45** — Firmware & microcode: `fwupdmgr get-updates` → WARN −1 pt; CPU microcode dpkg check → WARN −1 pt if missing (Intel/AMD only)
- **`--html`** — standalone HTML export: embedded CSS, colored badges, score circle, deductions table, XSS-safe
- **`--check`/`--skip`** — run-only or exclude named checks; `_section_enabled()` helper replaces 31 guards
- **`--output-dir PATH`** — override report directory for current run, no persist
- **Bug fix** — SSH context note: `snap.service.id == "ssh"` (was comparing derived label `"ssh_server"` against `"openssh"`)
- **auditd** — `no_rules` downgraded to INFO on desktop profile
- **Quality pass** — firmware: 3-state cpu_vendor, dpkg exact column match, fwupd error/updates decoupled; systemd_timers: two-part regex, resolve(), lstrip("-@"), last-service

### CHECK 43 — TLS/SSL certificate expiry (`checks/ssl_certs.py`)

**New file.** Sources scanned (read-only, no network calls):
- `/etc/letsencrypt/live/*/fullchain.pem` — Let's Encrypt certificates
- `/etc/ssl/private/*.{pem,crt,cert}` — manually installed server certs
- nginx: `ssl_certificate` directives in `/etc/nginx/**/*.conf`
- apache2: `SSLCertificateFile` directives in `/etc/apache2/**/*.conf`
- postfix: `smtpd_tls_cert_file` in `/etc/postfix/main.cf`

**Score impact** (per certificate, total capped at −4 pts):
- Expired (`days_left ≤ 0`): ALERT −2 pts
- Expires < 7 days: ALERT −2 pts
- Expires < 30 days: WARN −1 pt
- Valid: OK (no deduction)

**Constants:** `_MAX_CERTS=30`, `_MAX_CONF_FILES=100`, `_MAX_CERT_SIZE=50_000` bytes, `_WARN_DAYS=30`, `_ALERT_DAYS=7`

**Details:**
- `CertEntry` dataclass: `path`, `days_left` (None if unreadable), `expiry_str`, `error`
- `SslCertsSnapshot.from_system()`: deduplicates paths; skips files >50 KB (CA bundles); stops at 30 certs
- Quoted paths in nginx/apache config stripped (`ssl_certificate "/path"` → `/path`)
- Broken symlinks and permission errors skipped gracefully
- `check_ssl_certs()`: groups by severity; deduction accumulated then capped at 4 pts; `openssl x509 -noout -enddate` used to read expiry

**Tests:** 59 tests in `tests/test_ssl_certs.py`

### CHECK 44 — Systemd timers audit (`checks/systemd_timers.py`)

**New file.** Complements `cron_audit.py` (which covers `/etc/cron.*`) by auditing systemd timer units.

**Patterns checked:**
- `ExecStart` containing curl/wget piped to a shell → WARN −2 pts (flat)
- `ExecStart` referencing a world-writable `.sh` script → WARN −1 pt (flat)
- User-created timer (in `/etc/systemd/system/`) running as root (no `User=`) → INFO only

**Detection details:**
- Two-part regex: `_DOWNLOADER_RE` = `\b(curl|wget)\b`; `_PIPE_TO_SHELL_RE` = `|\s*(/[a-z/]*/)?(?:ba)?sh\b` — both must match to avoid false positives from path prefixes (`/bin/bash`)
- `systemctl list-timers --all --no-pager` used to discover timer units
- For each timer, associated `.service` file located via `_SERVICE_DIRS` search order
- `svc_path.resolve().as_posix().startswith("/etc/systemd/system/")` — symlink-safe user-created detection
- `lstrip("-@")` on ExecStart values strips systemd ignore-fail (`-`) and argv0-override (`@`) prefixes
- When a timer line lists multiple `.service` matches, the last one is used
- `_MAX_TIMERS=100`, `_MAX_EXEC_LENGTH=200`

**Tests:** 58 tests in `tests/test_systemd_timers.py`

### CHECK 45 — Firmware & microcode audit (`checks/firmware.py`)

**New file.** Two independent sub-checks.

**fwupd sub-check:**
- Runs `fwupdmgr get-updates` with `--no-unreported-check --no-metadata-check` to use cached metadata without network
- Pending firmware updates → WARN −1 pt; explicit fix command: `sudo fwupdmgr update`
- `fwupdmgr` absent or command error → INFO only (with error text)
- Error and update results fully decoupled: both can appear simultaneously

**CPU microcode sub-check:**
- `_detect_cpu_vendor()` reads `/proc/cpuinfo`; returns `"intel"` | `"amd"` | `"unknown"`
- `_dpkg_installed(package)`: parses `dpkg -l` output; column-based exact match — handles `intel-microcode:amd64` correctly
- Intel → checks `intel-microcode`; AMD → checks `amd64-microcode`; unknown → INFO `microcode_na`
- Missing package → WARN −1 pt; installed → OK

**Constants:** `_FWUPD_TIMEOUT=30`, `_MAX_ERROR_LEN=200`, `_FWUPD_ERROR_RE`

**Tests:** 54 tests in `tests/test_firmware.py`

### HTML export (`html_output.py`)

**New file.** `build_html_output(engine, sys_info)` produces a standalone HTML report.

**Features:**
- No JavaScript, no external resources — self-contained single file
- Embedded CSS: reset, body, h1/h2, table/th/td, `.score-circle`, `.badge`, `code`, `.meta-grid`, footer
- Score summary: colored circle (green ≥8, orange ≥5, red <5) + level label (ALERT/WARN/INFO/OK/UNKNOWN)
- Score deductions table (reason + points)
- Findings grouped by severity with colored badges
- Per-finding: message column + fix command in `<code>` block

**Security:**
- `_h()` wrapper applies `html.escape(quote=True)` to all user-supplied strings — XSS-safe
- `level_label` handles `engine.level is None` with `"UNKNOWN"` fallback
- Deduction access: `getattr(engine, "deductions", getattr(engine, "_deductions", []))` — compatible with public/private attribute naming

**Tests:** 56 tests in `tests/test_html_output.py`

### `--check LIST` / `--skip LIST` — Check-level CLI filters

**New flags** in `cli.py`:
- `--check=ssh,firewall,ports` or `--check ssh,firewall,ports` — run only these checks
- `--skip=clamav,rootkit` or `--skip clamav,rootkit` — exclude these checks
- Mutually exclusive: `--check` and `--skip` together → `CLIError`

**`_section_enabled(section, config, profile)`** in `runner.py`:
- Returns `True` when the section should run
- Respects `config.check_only` (allowlist), `config.skip_checks` (denylist), and `profile.skip_sections`
- `--check` can force a section even if the profile normally skips it (explicit user intent)
- Replaced 31 individual guards spread across `run_checks()`

**`validate_check_filters(config)`** in `runner.py`:
- Warns (INFO to stderr) if an unknown section name is passed to `--check` or `--skip`
- Called before the audit begins

### `--output-dir PATH`

- `AuditConfig.output_dir: str = ""` — new field in `cli.py`
- `get_or_prompt_log_dir(config)` in `manage_logs.py`: when `config.output_dir` is non-empty, returns it directly without prompting or saving to user config
- Does not persist: each run must pass `--output-dir` explicitly to use a custom directory

### Bug fixes

**SSH context note (runner.py):**
- Symptom: "SSH not publicly accessible — exposing it externally increases risk" was never shown in the services section.
- Root cause: `_svc_id` was derived from the service label (`"SSH Server"` → `"ssh_server"`) and compared against `"openssh"` — always failed.
- Fix: `snap.service.id == "ssh"` — the canonical service identifier from the registry.

**auditd profile-aware scoring:**
- `no_rules` finding downgraded from WARN −1 pt to INFO on `desktop` and `workstation` profiles; remains WARN −1 pt on `server` profile.

### Quality pass

**`firmware.py`:**
- `_detect_cpu_vendor()`: 3 clean states (`"intel"`, `"amd"`, `"unknown"`) — eliminates empty-string ambiguity
- `_dpkg_installed()`: `cols[1].split(":")[0] == package` — prevents false matches on arch-qualified names
- fwupd error and updates results fully decoupled

**`systemd_timers.py`:**
- Pipe-to-shell detection: two independent regexes — correctly handles `/bin/bash`, `bash -c`, `| sh -c`
- `svc_path.resolve()` before prefix check — symlink-safe
- `lstrip("-@")` on all ExecStart values
- `services[-1]` on ambiguous timer lines — matches systemd ACTIVATES column behaviour

### Tests

| File | Count | Coverage |
|------|-------|----------|
| `tests/test_ssl_certs.py` | 59 | `SslCertsSnapshot` defaults; `_add_path`; `_collect_from_configs` (nginx, apache2, postfix, quoted paths); `check_ssl_certs()` — expired ALERT, <7d ALERT, <30d WARN, valid OK, cap at −4; `_MAX_CERTS` limit; no-t guard |
| `tests/test_systemd_timers.py` | 58 | `SystemdTimersSnapshot` defaults; 11 parametrized pipe-to-shell cases; ambiguous-line last-service; `TestParseServiceFile`; `TestFromSystem`; check logic; no-t guard |
| `tests/test_firmware.py` | 54 | `FirmwareSnapshot` defaults; `_detect_cpu_vendor`; `_dpkg_installed` (arch-qualified); `check_firmware()` all paths; profile-aware; deduction count assertions |
| `tests/test_html_output.py` | 56 | `build_html_output()` — HTML5 doctype, CSS, score circle color, level label, XSS escaping, deduction table, all severity levels; `FakeEngine`; DOM assertions |
| Existing files | +57 | `test_cli.py`/`test_runner.py`: `--check`/`--skip`/`--output-dir`/`--html`; `test_auditd.py`: desktop INFO; quality pass assertions |

✅ **3778/3778 unit tests** (+284 from v1.20.0)

---

## [v1.20.0] — 2026-04-18

### TL;DR
- **CHECK 40** — UFW logging level: `off` → ALERT −2 pts; `low`/`medium` → OK; `high`/`full` → INFO (verbose, no deduction)
- **CHECK 41** — System umask: `UmaskSnapshot` reads `/etc/login.defs`, PAM, `/etc/profile`, RC files, current process; permissive umask (0002/0000) → WARN −1 pt; all-sources conflict detection
- **CHECK 42** — SSH auth.log analysis: `AuthLogSnapshot` parses `/var/log/auth.log`; brute-force >10 attempts/60 s from same IP → ALERT; last successful logins; top failed sources
- **Score history** — `history.py`; JSONL at `~/.config/ufw-audit/history.jsonl`; `--history` sparkline (▁▂▃▅▇█); 90-entry rotation
- **Ignore list** — `ignore.py`; `--ignore KEY` persists to `ignore.yml`; `--show-ignored`; ignored findings collected but not scored; hint shown in output
- **Bug fixes** — process-aware system port classification (`_SYSTEM_DAEMONS`); `ports.uncovered_default_deny` shows process name; auth_log `days=0` → `no_logins_no_range` key

### CHECK 40 — UFW logging level (`checks/firewall.py`)

- `check_ufw_logging()` added to the existing `firewall.py` check module
- Reads current UFW logging level (`ufw status verbose` header line)
- `off` → `result.alert()` + `add_deduction(points=2, context=network_context)` — no visibility into blocked traffic
- `low` or `medium` → `result.ok(key="firewall.logging_ok")` — standard coverage
- `high` or `full` → `result.info(key="firewall.logging_verbose")` — verbose logging, no deduction
- New locale keys: `firewall.logging_off` (EN/FR), `firewall.logging_ok` (EN/FR), `firewall.logging_verbose` (EN/FR)
- 32 tests in `tests/test_ufw_logging.py`

### CHECK 41 — System umask (`checks/umask.py`)

New module `checks/umask.py`:

- `UmaskSnapshot`: fields `login_defs_umask`, `pam_umask`, `profile_umask`, `current_umask`, `conflict`
- `from_system()`: reads `/etc/login.defs` (`UMASK` line), `/etc/pam.d/common-session` (`pam_umask.so umask=`), `/etc/profile` and `/etc/profile.d/*.sh` (`umask` line), `os.umask()` for current process value
- `check_umask()`:
  - Current umask `0002` or `0000` → WARN, −1 pt; fix = `echo "umask 0022" | sudo tee /etc/profile.d/umask.conf`
  - Conflict between sources → WARN, −1 pt (no fix cmd — manual resolution needed)
  - All OK → OK finding
- `_fix_cmd()`: generates profile.d file command with profile-aware recommended value
- 54 tests in `tests/test_umask.py`

### CHECK 42 — SSH auth.log login analysis (`checks/auth_log.py`)

New module `checks/auth_log.py`:

- `AuthLogEntry`: `timestamp`, `event` ("accepted"/"failed"), `user`, `source_ip`, `source_port`
- `AuthLogSnapshot`: `entries`, `days`, `log_path`
- `from_system()`: reads last N days of `/var/log/auth.log`; `_estimate_days()` returns 0 when file is empty (just rotated)
- `check_auth_log()`:
  - Brute-force: same source IP with >10 failed attempts within any 60 s window → ALERT, −2 pts
  - Last successful logins listed → INFO
  - Top failed-login sources listed → WARN if any
  - `days=0` (empty/rotated log): uses `auth_log.no_logins_no_range` key (no "0 day(s)" in message)
  - `days>0` with no entries: uses `auth_log.no_logins` key as before
- New locale keys: `auth_log.no_logins_no_range`
- 62 tests in `tests/test_auth_log.py`

### Score history (`history.py`)

New module `history.py`:

- `HistoryEntry`: `date` (ISO), `score`, `alerts`, `warns`
- `load_history(path)` / `save_history(path, entries)` — JSONL format, one entry per line
- Automatic rotation: `save_history` trims to last 90 entries
- `render_sparkline(entries)` — maps score 0–10 to █ bars (▁▂▃▄▅▆▇█); returns string with date labels
- `--history` CLI flag: loads and displays history; `--history=N` shows last N entries (default 20)
- History file: `~/.config/ufw-audit/history.jsonl`
- 36 tests in `tests/test_history.py`

### Ignore list (`ignore.py`)

New module `ignore.py`:

- `load_ignore(path)` / `save_ignore(path, keys)` — YAML at `~/.config/ufw-audit/ignore.yml`
- `--ignore KEY` CLI flag: adds KEY to ignore.yml; confirmation printed; exits without running audit
- `--show-ignored` CLI flag: prints all currently ignored keys; exits without running audit
- `ScoreEngine.ignore_keys: frozenset[str]` — populated from ignore.yml before audit runs
- `engine.ignored_findings: list[Finding]` — collects ignored findings for optional display
- Ignored findings receive hint: `Run ufw-audit --ignore <key> to silence this finding permanently`
- Locale key `ignored.hint` uses `{check_key}` placeholder (avoids conflict with `t(key, ...)` signature)
- 44 tests in `tests/test_ignore.py`

### Bug fixes — `checks/ports.py`

- **Process-aware system port classification**: `_SYSTEM_DAEMONS` frozenset added (`avahi-daemon`, `systemd-*`, `dnsmasq`, `named`, `NetworkManager`, …, `""` for unknown owner)
  - `_categorize_port()` now checks `lport.process in _SYSTEM_DAEMONS` before classifying as `SYSTEM_INTERNAL`
  - User-space apps (e.g. Spotify on `1900/udp`) fall through to standard exposure checks instead of being silently classified as system-internal
  - Empty process string `""` included — when owner cannot be determined, treat as system daemon to avoid false positives
- **Process name in `uncovered_default_deny` INFO**: `pp_info = f"{pp} ({lport.process})" if lport.process else pp` — INFO message now reads `57621/tcp (spotify)` when process is known

### Bug fix — `checks/auth_log.py`

- `_estimate_days()` returns `0` when auth.log is empty (size 0 or just rotated)
- Previous behaviour: `check_auth_log()` injected `days=0` into `auth_log.no_logins` template → output showed "0 dernier(s) jour(s)" / "last 0 day(s)"
- Fix: `if days == 0: result.ok(message=_t("auth_log.no_logins_no_range"), key="auth_log.no_logins")` — dedicated key with no day-count interpolation

### Locale additions (`en.json` / `fr.json`)

| Key | EN | FR |
|-----|----|----|
| `auth_log.no_logins_no_range` | No successful SSH logins recorded in the available auth.log | Aucune connexion SSH réussie enregistrée dans le journal d'authentification disponible |
| `ignored.hint` | Run `ufw-audit --ignore {check_key}` to silence this finding permanently | Exécutez `ufw-audit --ignore {check_key}` pour masquer ce résultat définitivement |
| `firewall.logging_off` | UFW logging is disabled — no visibility into blocked traffic | La journalisation UFW est désactivée — aucune visibilité sur le trafic bloqué |
| `firewall.logging_ok` | UFW logging active ({level}) | Journalisation UFW active ({level}) |
| `firewall.logging_verbose` | UFW logging set to {level} — verbose mode (high I/O) | Journalisation UFW en mode {level} — mode verbeux (I/O élevé) |

### Tests

| File | Tests | Coverage |
|------|-------|---------|
| `tests/test_auth_log.py` | 62 | `AuthLogSnapshot` defaults; `_estimate_days()` — empty file (0), normal; `check_auth_log()` — no entries with days>0 (OK, `no_logins`), no entries with days=0 (OK, `no_logins_no_range`), brute-force (ALERT, deduction), last logins listed, top failures listed; message format; key assertions |
| `tests/test_history.py` | 36 | `HistoryEntry` dataclass; `load_history()` — empty file, valid JSONL, malformed lines skipped; `save_history()` — creates file, rotation at 90, overwrites; `render_sparkline()` — empty, single entry, scale mapping, date labels; `--history` CLI integration |
| `tests/test_ignore.py` | 44 | `load_ignore()` — missing file (empty set), valid YAML, malformed; `save_ignore()` — creates file, overwrites; `ScoreEngine.ignore_keys` — ignored finding not scored, collected in `ignored_findings`; `ignored.hint` locale key uses `check_key=`; `--ignore` CLI; `--show-ignored` CLI |
| `tests/test_umask.py` | 54 | `UmaskSnapshot` defaults; `from_system()` paths (login.defs/pam/profile/current); `check_umask()` — permissive 0002 (WARN, −1 pt, key, deduction key, cmd), permissive 0000 (WARN), strict 0027 (OK), default 0022 (OK), conflict (WARN −1 pt), no finding when OK; `_fix_cmd()` per profile; constants |
| `tests/test_ufw_logging.py` | 32 | `check_ufw_logging()` — off (ALERT, −2 pts, key, deduction key, cmd), low (OK, key, no deduction), medium (OK), high (INFO, key, no deduction), full (INFO); network context deduction doubling; level in message; no_t |
| Existing files | +7 | `tests/test_ports.py`: `_SYSTEM_DAEMONS` import; UPnP owned by Spotify → `UNCOVERED_PUBLIC`; unknown owner → `SYSTEM_INTERNAL`; `test_auth_log.py`: days=0 OK uses `no_logins_no_range` |

- ✅ **3494/3494 unit tests (+235 from v1.19.0)**

---

## [v1.19.0] — 2026-04-17

### TL;DR
- **SSH `PermitRootLogin` OK cases** — `no` → OK; `prohibit-password`/`forced-commands-only` → OK restricted; `yes` → ALERT −3 pt (unchanged); unknown value → INFO
- **SUID scan performance** — `find /` → `_SCAN_ROOTS` targeted list; scan time <1 s; SGID whitelist adds `camel-lock-helper-1.2`, `support-tool-launcher`
- **IoT dominance display fix** — `local_dominance` INFO finding silently dropped; fixed by explicit key check in `display_log_results`
- **Domain score labels i18n** — `render_domain_scores` passes labels through `t()`; `samba`/`disk` added to locales
- **Hardening 6 sysctl checks** — tcp_syncookies, accept_source_route, accept_redirects_v6, send_redirects, protected_hardlinks, protected_symlinks — all WARN −1 pt, all read via `/proc/sys/`

### SSH audit (`checks/ssh.py`)

- `_check_sshd_config`: `PermitRootLogin` check now complete
  - `yes` → `result.alert()` + `add_deduction(points=3)` (unchanged)
  - `no` → `result.ok(key="ssh.permit_root_login_disabled")`
  - `prohibit-password` or `forced-commands-only` → `result.ok(key="ssh.permit_root_login_restricted", value=prl)`
  - unknown value → `result.info(key="ssh.permit_root_login", value=prl)`
- Default assumed value: `prohibit-password` (SSH default)
- New locale keys: `ssh.permit_root_login_disabled`, `ssh.permit_root_login_restricted`
- 7 new tests: `test_permit_root_login_no_is_ok`, `test_permit_root_login_prohibit_password_is_ok`, `test_permit_root_login_forced_commands_is_ok`, `test_permit_root_login_default_is_ok`, `test_permit_root_login_no_deduction_when_ok`, `test_permit_root_login_unknown_value_is_info`, `test_permit_root_login_no_no_alert`

### SUID/SGID scan (`checks/suid_audit.py`)

- `_SCAN_ROOTS` tuple replaces full-filesystem `find /`: `/bin`, `/sbin`, `/usr/bin`, `/usr/sbin`, `/usr/local/bin`, `/usr/local/sbin`, `/usr/local/lib`, `/usr/lib`, `/usr/lib64`, `/lib`, `/lib64`, `/usr/libexec`, `/opt`
- `from_system()` filters `_SCAN_ROOTS` to existing directories; constructs `find` command with combined SUID+SGID perm filter
- `_KNOWN_SGID` extended: `"camel-lock-helper-1.2"`, `"support-tool-launcher"`
- Timeout remains 15 s (`_FIND_TIMEOUT`)

### Display fix (`display.py`)

- `display_log_results` iterated only WARN findings; `logs.local_dominance` (INFO) was silently skipped
- Fixed: after top-ports loop, iterate all INFO findings; print those with `key == "logs.local_dominance"`

### Domain scores i18n (`domain_scores.py`)

- `render_domain_scores(scores, t=None)` — inner `_label(domain, fallback)` helper added
- `_label` calls `t(f"domain_scores.{domain}")`; returns English fallback if key not yet translated
- `labels` dict built per-domain; `label_width` derived from translated labels
- New locale keys: `domain_scores.samba` (EN: "Samba Security" / FR: "Sécurité Samba"), `domain_scores.disk` (EN: "Disk Health" / FR: "Santé des disques")

### Hardening sysctl checks (`checks/hardening.py`)

New fields in `HardeningSnapshot` (all read via `_read_sysctl_bool` / `_read_sysctl_int` from `/proc/sys/`):

| Field | Key | Default | OK condition | Deduction |
|-------|-----|---------|--------------|-----------|
| `tcp_syncookies` | `net.ipv4.tcp_syncookies` | 1 | ≥ 1 | −1 pt if 0 |
| `accept_source_route` | `net.ipv4.conf.all.accept_source_route` | False | False | −1 pt if True |
| `accept_redirects_v6` | `net.ipv6.conf.all.accept_redirects` | False | False | −1 pt if True |
| `send_redirects` | `net.ipv4.conf.all.send_redirects` | False | False | −1 pt if True |
| `protected_hardlinks` | `fs.protected_hardlinks` | True | True | −1 pt if False |
| `protected_symlinks` | `fs.protected_symlinks` | True | True | −1 pt if False |

All fix commands target `/etc/sysctl.d/99-hardening.conf`.

### Tests

- `tests/test_hardening.py`: `make_snapshot` gains 6 new keyword defaults; `TestTcpSyncookies` (6), `TestAcceptSourceRoute` (5), `TestAcceptRedirectsV6` (5), `TestSendRedirects` (5), `TestProtectedHardlinks` (4), `TestProtectedSymlinks` (4) — 29 new tests
- `tests/test_ssh.py`: 7 new `PermitRootLogin` tests
- **Total: 3259/3259 (+530 from v1.18.0)**

---

## [v1.18.0] — 2026-04-16

### TL;DR
- **CHECK 34** — AppArmor / SELinux MAC policy: `aa-status` enforce/complain count + `getenforce` mode → OK if enforcing; WARN −1 pt for no MAC, AppArmor inactive, no enforce profiles (server), SELinux disabled; desktop: no enforce → INFO
- **CHECK 35** — Backup solution audit: detects borgmatic, borg, restic, timeshift, duplicati, bacula, rclone, tarsnap, deja-dup; active = binary + config/service artefact; installed = binary only; WARN −1 pt if no tool (server); INFO on desktop/container
- **Kernel listing** — `check_kernel_modules` always emits `kernels_listed` INFO when dpkg data is available; annotated list in message (`6.x.y-z-generic (*)` for running); single/custom/within-retention cases all show the listing
- **Profile override fix** — `apply_profile()` sets `finding.nature = ""` when downgrading to INFO; prevents downgraded findings from appearing in the action/improvement buckets of the summary box
- **Summary box cleanup** — `structural_items` block removed from `print_audit_summary()`; summary now shows only action and improvement items
- **Profile pass** — `desktop.conf` +6 overrides; `container.conf` +12 `skip_sections`
- **`--explain` 76 → 86 keys** — CHECKs 31/32/33 with CIS Ubuntu 22.04 L1/L2 references
- **bash-completion Debian fix** — `long_opts` single-line
- **`--manage-logs` UX** — move prompt on location change; multi-directory view with continuous index
- **2729/2729 tests** (+222 vs v1.17.0)

### Changes

**`checks/mac_policy.py`** (CHECK 34 — new file)
- `MacPolicySnapshot`: `apparmor_installed`, `apparmor_active`, `apparmor_enforcing`, `apparmor_complain`, `selinux_installed`, `selinux_mode`
- `from_system()`: `aa-status` → parse enforce/complain counts; `/sys/module/apparmor` fallback for partial install; `getenforce` → selinux_mode
- `_parse_aa_count(output, mode)`: regex `^\s*(\d+)\s+profiles?\s+are\s+in\s+(\w+)\s+mode` (MULTILINE)
- `check_mac_policy()`: SELinux enforcing → OK (short-circuit); AppArmor enforcing → OK; AppArmor active 0 enforce → WARN −1 pt (server) / INFO (desktop); AppArmor inactive → WARN −1 pt; SELinux permissive (no AppArmor) → INFO + WARN `no_enforce` −1 pt; SELinux disabled (installed=True) → WARN −1 pt `selinux_disabled`; no MAC → WARN −1 pt `no_mac`
- `se_mode` normalised to lowercase once at function entry

**`checks/backup.py`** (CHECK 35 — new file)
- Config artefact constants: `_BORGMATIC_CONFIGS`, `_BORG_KEYS_DIR`, `_TIMESHIFT_CONFIG`, `_RCLONE_CONFIGS`, `_TARSNAP_CONFIGS`
- `BackupSnapshot`: `active_tools: List[str]`, `installed_tools: List[str]`
- `from_system()`: borgmatic → borg (only if borgmatic not active) → restic (installed-only) → timeshift → duplicati/bacula (service active) → rclone/tarsnap → deja-dup; dedup with `dict.fromkeys()`
- `_borgmatic_config_exists(path)`: True if non-empty dir or existing file
- `_service_active(service)`: `systemctl is-active` → `out.lower() == "active"`
- `check_backup()`: active → OK + optional `also_installed` INFO; installed-only → INFO; no tool server → WARN −1 pt; no tool desktop → INFO; `sorted()` applied to tool lists for deterministic output

**`checks/kernel_modules.py`**
- `_check_installed_kernels()` restructured: early return only when `not installed or not running`
- `kernels_listed` INFO finding: message contains annotated kernel list; emitted for single kernel, custom (non-dpkg) kernel, or within-retention cases
- `reboot_pending` and `annotated` list now computed before any branching

**`profiles.py`**
- `apply_profile()`: `finding.nature = ""` added after `_remove_deductions_for_key()` when downgrading to INFO

**`display.py`**
- `print_audit_summary()`: `structural_items` list and its display block removed; action and improvement items only

**`desktop.conf`**
- New overrides: `ssh.password_auth = info`, `ssh.x11_forwarding = info`, `ssh.allow_tcp_forwarding = info`, `password_policy.no_quality_module = info`, `rootkit.no_scan = info`, `rootkit.scan_old = info`

**`container.conf`**
- New `skip_sections`: `kernel_modules`, `secure_boot`, `auditd`, `rootkit`, `file_integrity`, `disk`, `memory`, `fail2ban`, `clamav`, `ntp`, `mac_policy`, `backup`

**`explain.py`**
- 3 new groups: `"Auditd"` (4 keys), `"Secure Boot"` (2 keys), `"File Integrity"` (4 keys)
- Total: 76 → 86 keys

**`locales/en.json` + `fr.json`**
- `mac_policy.*`: 12 new keys (no_mac, apparmor_inactive, apparmor_no_enforce, apparmor_ok, selinux_enforcing, selinux_permissive, selinux_disabled, no_enforce + detail/reason variants)
- `backup.*`: 8 new keys (active, also_installed, installed_only, no_backup + detail variants)
- `kernel_modules.kernels_listed`: new key (annotated list in message, no detail)
- `explain.auditd.*`, `explain.secure_boot.*`, `explain.file_integrity.*`: 10 new explain entries
- `explain_cis.auditd.*`, `explain_cis.secure_boot.*`, `explain_cis.file_integrity.*`: CIS Ubuntu 22.04 L1/L2 references

**`ufw_audit/data/ufw-audit.bash-completion`**
- `long_opts` written on a single line (Debian bash completion multiline parsing fix)

**`manage_logs.py`** — UX improvements
- Move prompt: when changing location via `c`, if reports exist and destination differs → `[y/N]` prompt; `shutil.move` each file; confirms count moved
- Multi-directory view: `_get_extra_dirs` / `_set_extra_dirs` / `_add_extra_dir` helpers backed by `log_dirs_extra` JSON key in user_config; current dir always first, previous dirs shown under `─── Previous location: /path ───` header; flat continuous index across all dirs
- Auto-cleanup: extra dirs that are empty or non-existent are removed from the list each iteration
- New locale keys: `current_label`, `previous_label`, `move_logs_prompt`, `move_logs_done`

**Tests**
- `tests/test_mac_policy.py` (new): 67 tests — `_parse_aa_count`, AppArmor inactive/no_enforce/enforcing, SELinux enforcing/permissive/disabled, snapshot defaults, deduction invariants
- `tests/test_backup.py` (new): 62 tests — active/installed/no_backup, priority logic, borg/borgmatic standalone, deduction invariants, `_borgmatic_config_exists`
- `tests/test_manage_logs.py` (new): 29 tests — `parse_log_selection`, extras helpers, change location (no logs, same path, move yes/no, cancel), extra dir display/cleanup, cross-dir delete, `all`
- `tests/test_profiles.py`: +6 regression tests for `nature` clearing (`TestApplyProfileNatureCleared`)
- `tests/test_kernel_modules.py`: `TestKernelCleanupNoOp` updated; +8 tests for `kernels_listed` finding
- `tests/test_explain.py`: 76→86 key count; 6 new content tests for auditd/secure_boot/file_integrity
- **2729/2729 tests** (+222)

---

## [v1.17.0] — 2026-04-15

### TL;DR
- **CHECK 31** — Linux Audit Framework (auditd): installation, service active, rules loaded, sensitive files watched → WARN −1 pt each for inactive / no rules / uncovered files (server profile)
- **CHECK 32** — Secure Boot: mokutil/efivars/bootctl detection → WARN −1 pt if disabled on desktop; INFO if disabled on server/VM or BIOS/unknown
- **CHECK 33** — File integrity monitoring (AIDE/Tripwire): installed, DB initialised, last check ≤30 days → WARN −1 pt each
- **`--explain` profile variants**: 17 keys show `[ server ]` / `[ desktop ]` / `[ container ]` sections; uniform yellow note for keys with no profile difference; ESC delay reduced to 25 ms
- **`workstation` → `desktop` profile**: renamed; `workstation` alias kept for backward compatibility
- **`cmd_type`**: `Finding` dataclass gains `cmd_type: str = "fix"` / `"check"`; different prefix in the summary box
- **Bug fixes**: IPv6 avahi false alarm, logs journald fallback (Debian 13), hardening sysctl persistence, disk smartmontools hint
- **UX**: services sorted by severity, panorama alphabetical, profile in summary box, risk context colors, group header title centred
- **Trusted Publishing**: `.github/workflows/publish.yml` — OIDC → PyPI; no API token
- **2507/2507 tests** (+215 vs v1.16.0)

### Changes

**`checks/auditd.py`** (CHECK 31 — new file)
- `AuditdSnapshot`: `installed: bool`, `service_active: bool`, `rules_loaded: int`, `watched_files: list[str]`
- `from_system()`: `shutil.which("auditctl")` → installed; `systemctl is-active auditd` → service_active; `auditctl -l` → parse rule count and extract watched paths; sensitive targets: `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`
- `check_auditd()`: not installed → INFO; service inactive → WARN −1 pt `auditd.service_inactive`; no rules → WARN −1 pt `auditd.no_rules`; sensitive files not watched → WARN −1 pt (server) / INFO (desktop) `auditd.missing_watches`; all ok → OK `auditd.ok`

**`checks/secure_boot.py`** (CHECK 32 — new file)
- `SecureBootSnapshot`: `state: str` ("enabled" / "disabled" / "no_uefi" / "unknown"), `method: str`
- Detection priority: `mokutil --sb-state` → `/sys/firmware/efi/efivars/SecureBoot-*` byte read → `bootctl status` grep
- `check_secure_boot()`: enabled → OK; disabled on desktop → WARN −1 pt `secure_boot.disabled`; disabled on server → INFO; no_uefi / unknown → INFO

**`checks/file_integrity.py`** (CHECK 33 — new file)
- Constants: `_CHECK_WARN_DAYS = 30`; AIDE DB paths (`/var/lib/aide/aide.db*`); Tripwire DB dir + log dir
- `FileIntegritySnapshot`: `tool: str` ("aide" / "tripwire" / ""), `db_exists: bool`, `last_check_date: Optional[str]`
- `from_system()`: detects AIDE first (preferred); DB existence via path list; last check from log file mtime; Tripwire: newest `.txt` in log dir
- `_check_age_days(iso_date)`: UTC-aware — `datetime.strptime(...).replace(tzinfo=timezone.utc)` + `datetime.now(timezone.utc)`
- `check_file_integrity()`: not installed → INFO; no db → WARN −1 pt; no check → WARN −1 pt; check > 30 days → WARN −1 pt; ok → OK

**`explain.py`**
- `_EXPLAIN_PROFILES = ("server", "desktop", "container")`
- `_has_profile_variants(key, t)`: probes `t(f"explain.{key}.server.why")`; checks both bare key and `[bracketed]` form (handles real i18n vs mock t())
- `run_explain()`: if variants → print `[ profile ]` + divider + profile WHY + HOW (profile-specific or fallback to generic); else → print generic WHY/HOW + yellow uniform note (`\033[33m...\033[0m` when `sys.stdout.isatty()`)
- `_detail_screen._build_lines()`: same logic in curses; uniform note uses `color_pair(2)` (COLOR_YELLOW)
- `os.environ.setdefault("ESCDELAY", "25")` before `curses.wrapper()` call

**`locales/en.json` + `fr.json`**
- Profile variant entries added for 17 keys: `updates.unattended_not_configured`, `updates.security_pending`, `hardening.rp_filter_disabled`, `hardening.rp_filter_loose`, `hardening.redirects_enabled`, `hardening.log_martians_disabled`, `ipv6.port_no_v6_rule`, `ipv6.ufw_disabled_listeners_present`, `memory.swappiness_ssd_wear`, `memory.swappiness_unjustified`, `services_state.enabled_inactive`, `clamav.db_very_outdated`, `clamav.db_outdated`, `clamav.scan_very_old`, `clamav.scan_old`, `kernel_modules.risky_fs`, `kernel_modules.risky_net`
- Structure per key: `explain.KEY.server.why`, `explain.KEY.desktop.why`, `explain.KEY.container.why`; optional `explain.KEY.container.how` for sysctl/kernel/memory keys where the fix differs
- New sections: `auditd`, `secure_boot`, `file_integrity` locale keys in both languages

**`scoring.py`**
- `Finding` dataclass: `cmd_type: str = "fix"` field; propagated to all `result.ok/warn/alert/info()` methods

**`output.py`**
- `print_check_cmd()`: prints `ℹ Check: cmd` (vs `→ cmd` for fix)
- `print_group()`: group title now centred within the `━` full-width separator
- `orange` + `orange_bold` added to `_Colours`
- `print_risk_context()`: `risk_tier` parameter — red=critical, orange=medium, yellow=low

**`checks/ipv6.py`**
- `ss -tuln` → `ss -tulnp` to capture process names
- `_INTERNAL_PROCESSES` frozenset: avahi-daemon, systemd-resolve, dnsmasq, containerd, dockerd
- `_extract_ipv6_listeners()`: filters out internal processes; no longer suggests UFW rules for avahi/cups/loopback
- Warning `ufw_disabled_listeners_present` gains `detail=t("ipv6.listeners_list", ports=...)` showing affected ports

**`checks/logs.py`**
- `LogsSnapshot`: new `log_source: str` field ("file" / "journald" / "none")
- `from_system()`: falls back to `_read_from_journald(log_days)` when `/var/log/ufw.log` absent; `journalctl -k --output=short-iso`
- `check_logs()`: discrete INFO if `source=journald`; `no_logfile` message updated (mentions journald alternative)

**`checks/hardening.py`**
- `rp_filter_disabled` / `rp_filter_loose` / `redirects_enabled` / `log_martians_disabled`: fix commands use `sysctl -w ... && echo ... >> /etc/sysctl.d/99-hardening.conf` for persistence

**`checks/disk.py`**
- `disk.smartctl_missing` finding: `cmd="sudo apt install smartmontools"` added

**`manage_logs.py`**
- `run_manage_logs()` refactored with `while True` — menu stays open after each delete action; log list refreshed each iteration; exit: Enter or `q`

**`runner.py`**
- `_snap_severity()`: CRITICAL(0) → HIGH(1) → MEDIUM(2) → LOW(3) → inactive(4)
- `snapshots = sorted(snapshots, key=_snap_severity)` before the display loop
- CHECK 31 inserted at the head of GROUP 5 (DETECTION & HEALTH); CHECK 32 before CHECK 29; CHECK 33 after CHECK 30

**`panorama.py`**
- `build_panorama_rows()`: `return sorted(rows, key=lambda r: r["label"].lower())`

**`display.py`**
- `print_audit_summary()`: `profile_name: str = "server"` parameter; profile line added to summary box
- `display_risk_context()`: detects risk tier from translated level text → passes to `print_risk_context()`

**`profiles.py`**
- `load_profile()`: `workstation` alias → `desktop`

**`data/profiles/desktop.conf`** (new file)
- Same overrides as the former `workstation.conf`; `container.conf` updated to `extends = desktop`

**`.github/workflows/publish.yml`** (new file)
- Trusted Publishing workflow: `on: push tags v*`; jobs: test → build → publish
- `environment: release`; `id-token: write` permission; `pypa/gh-action-pypi-publish@release/v1`

### Tests

| File | Change | Coverage |
|------|--------|----------|
| `tests/test_auditd.py` | New — 41 tests | `AuditdSnapshot` defaults; `from_system()` paths; `check_auditd()` — not installed, inactive, no rules, missing watches (server/desktop), all ok |
| `tests/test_secure_boot.py` | New — 21 tests | `SecureBootSnapshot` defaults; detection methods; `check_secure_boot()` — enabled, disabled desktop (WARN), disabled server (INFO), no_uefi (INFO), unknown (INFO) |
| `tests/test_file_integrity.py` | New — 33 tests | `FileIntegritySnapshot` defaults; `_check_age_days()` edge cases; `check_file_integrity()` — not installed, no db (aide/tripwire), no check, check old, clean; unknown tool fallback; `TestEdgeCases` (invalid date, priority, unknown tool) |
| `tests/test_explain.py` | +81 tests | `TestHasProfileVariants` (12); `TestRunExplainProfileVariants` (24 × profile sections); `TestRunExplainUniform` (yellow note, no sections); branching in `test_known_key_shows_why_and_how_headers` |
| Other modified test files | +39 tests | `test_cli.py`, `test_desktop_apps.py`, `test_disk.py`, `test_fail2ban.py`, `test_hardening.py`, `test_ipv6.py`, `test_logs.py`, `test_memory.py`, `test_profiles.py`, `test_updates.py`, `test_virtualization.py` |

---

## [v1.16.0] — 2026-04-12

### TL;DR
- **CHECK 19** — Desktop application detection: 30+ GUI apps (Steam, Discord, Zoom, Signal, RustDesk, Wireshark, Betterbird, virt-manager…) running as processes → INFO, no deduction
- **CHECK 28** — NTP time synchronisation: systemd-timesyncd/chronyd/ntpd active and synchronised → WARN −1 pt if not
- **CHECK 29** — Fail2ban intrusion prevention (standalone): service state, active jails, SSH jail → WARN −1 pt if inactive or no jails
- **CHECK 30** — Rootkit & integrity scan: rkhunter/chkrootkit DB freshness and last scan date → WARN −1 pt each
- **`--target N` exit code 4** — returns `EXIT_TARGET_MISSED = 4` when score < target; takes priority over codes 1/2
- **CLI validation** — `--explain=`, `--profile=`, `--lang=`, `--webhook=`, `--target=` with empty value raise `CLIError`
- **5 thematic group headers** — output reorganised into 5 groups; `print_group()` with full-width `━` cyan separator
- **Fail2ban removed from hardening** — dedicated standalone check in GROUP 5 (DETECTION & HEALTH)
- **Quality pass** — `desktop_apps.py`: `_KNOWN_APPS` keys lowercase, duplicate removed, simplified lookup
- **2292/2292 tests** (+153 vs v1.15.1)

### Changes

**`checks/desktop_apps.py`** (CHECK 19 — new file)
- `_KNOWN_APPS`: dict of `{lowercase_comm: display_name}` for 30+ known GUI applications across 7 categories: gaming (Steam), browsers (Firefox, Brave, Chromium), communication (Discord, Zoom, Teams, Slack, Skype, Telegram, Signal, WhatSie, Element, Nheko, Fractal), email (Betterbird, Thunderbird), file sync (kDrive), media (Spotify, VLC, OBS, Transmission), remote/security (RustDesk, Wireshark), virtualisation (virt-manager); all keys ≤15 chars (Linux `comm` truncation)
- `DesktopAppsSnapshot`: `detected: List[Tuple[str, str]]` (display name, process name)
- `DesktopAppsSnapshot.from_system()`: reads `ps -eo comm` output; deduplicates by display name (multiple process names can map to same app)
- `check_desktop_apps()`: no apps → empty result (section not emitted); per detected app → INFO finding; no deduction

**`checks/ntp.py`** (CHECK 28 — new file)
- `NtpSnapshot`: `ntp_service`, `ntp_active`, `ntp_synced`
- `NtpSnapshot.from_system()`: detects systemd-timesyncd/chronyd/ntpd via `systemctl is-active`; parses `timedatectl show` key=value for `NTP=yes` and `NTPSynchronized=yes`
- `check_ntp()`: not installed → INFO; active+synced → OK; active+not synced → WARN −1 pt `ntp.not_synced`; inactive → WARN −1 pt `ntp.inactive`

**`checks/fail2ban.py`** (CHECK 29 — new file)
- `_SSH_JAIL_PATTERNS = ("sshd", "ssh")`
- `Fail2banSnapshot`: `installed`, `service_active`, `active_jails`, `ssh_jail`
- `Fail2banSnapshot.from_system()`: `shutil.which("fail2ban-client")` → installed; `systemctl is-active` → service_active; fallback: `fail2ban-client ping` → "pong"; `fail2ban-client status` → `_parse_jails()`; SSH jail via `next(generator, "")`
- `_parse_jails(status_output)`: scans for "Jail list:" line (case-insensitive), splits on `,`
- `check_fail2ban()`: not installed → INFO; inactive → WARN −1 pt `fail2ban.service_inactive`; no jails → WARN −1 pt `fail2ban.no_jails`; jails active → OK `fail2ban.active`; SSH jail → additional OK `fail2ban.ssh_jail_active`

**`checks/rootkit.py`** (CHECK 30 — new file)
- Constants: `_DB_WARN_DAYS = 7`, `_SCAN_WARN_DAYS = 30`
- `RootkitSnapshot`: `rkhunter_installed`, `chkrootkit_installed`, `tool`, `db_age_days`, `last_scan_date`
- `RootkitSnapshot.from_system()`: `shutil.which()` for both tools; rkhunter DB age via `_RKHUNTER_DB` mtime; last scan date: reads last 100 KB of `/var/log/rkhunter.log` (full scans generate 130 KB+), confirms a completed scan via `_RKHUNTER_SCAN_RE`, returns file mtime as date (robust against rkhunter 1.4.x which logs `[HH:MM:SS]` only, no date on content lines); chkrootkit via `/var/log/chkrootkit/log.today` mtime
- `check_rootkit()`: neither → INFO; DB outdated → WARN −1 pt `rootkit.db_outdated`; no scan → WARN −1 pt `rootkit.no_scan`; scan old → WARN −1 pt `rootkit.scan_old`; all OK → OK `rootkit.ok`

**`checks/hardening.py`**
- Removed: `fail2ban_active: bool` field from `HardeningSnapshot`
- Removed: fail2ban detection block in `from_system()`
- Removed: fail2ban check block in `check_hardening()` (keys `hardening.fail2ban_ok` / `hardening.fail2ban_missing`)

**`__main__.py`**
- `EXIT_TARGET_MISSED = 4` constant added
- Exit logic: `if config.target > 0 and engine.score < config.target: return EXIT_TARGET_MISSED` — checked before `EXIT_ALERTS`/`EXIT_WARNINGS`

**`output.py`**
- `print_group(title)`: prints full-width `━` bar + bold title in cyan; called once per thematic group in `runner.py`

**`report.py`** (`AuditReport`)
- `write_group(title)`: writes `=== TITLE ===` separator block to the report file

**`report_markdown.py`** (`MarkdownReport`)
- `write_group(title)`: writes `# TITLE` markdown heading (for consistency)

**`runner.py`**
- All checks reorganised into 5 thematic groups with `print_group()` + `report.write_group()` calls:
  - GROUP 1 — FIREWALL & NETWORK: firewall status, rules, IPv6, ports, logs, DDNS, docker, virtualisation
  - GROUP 2 — EXPOSURE & SERVICES: services, firewall stack, network context
  - GROUP 3 — ACCESS CONTROL: SSH, file permissions, user accounts, password policy
  - GROUP 4 — SYSTEM HARDENING: hardening, updates, kernel modules, cron, services state, disk, memory, Samba, ClamAV, SMTP, IoT dominance
  - GROUP 5 — DETECTION & HEALTH: desktop apps, NTP, fail2ban, rootkit
- Added imports for `Fail2banSnapshot`, `check_fail2ban`, `RootkitSnapshot`, `check_rootkit`, `print_group`

**Locales (`en.json` + `fr.json`)**
- Added: `"groups"` section with 5 keys (`groups.firewall_network`, `groups.exposure_services`, `groups.access_control`, `groups.system_hardening`, `groups.detection_health`)
- Added: `"sections.ntp"`, `"sections.fail2ban"`, `"sections.rootkit"`, `"sections.desktop_apps"`
- Added: `"ntp.*"` (4 keys), `"fail2ban.*"` (5 keys), `"rootkit.*"` (4 keys), `"desktop_apps.*"` (3 keys)
- Removed: `hardening.fail2ban_ok`, `hardening.fail2ban_missing`

**`explain.py`**
- Removed: `"hardening.fail2ban_missing"` from `_EXPLAIN_GROUPS` Hardening section
- Key count: 77 → 76; groups: 17 → 19

**Tests**
- `test_desktop_apps.py`: new — snapshot defaults, `_KNOWN_APPS` keys, `from_system()`, `check_desktop_apps()` all branches
- `test_ntp.py`: new — snapshot defaults, `timedatectl` parsing, service detection, all `check_ntp()` branches
- `test_fail2ban.py`: new — 42 tests; `_parse_jails()`, snapshot, `from_system()` paths, all `check_fail2ban()` branches
- `test_rootkit.py`: new — 38 tests; snapshot, both tools, all `check_rootkit()` branches
- `test_exit_codes.py`: new — 18 tests; constants, `_decide_exit()` priority logic
- `test_hardening.py`: `TestFail2ban` removed (−3); composite tests use `log_martians=False`
- `test_explain.py`: key count 77→76; `hardening.fail2ban_missing` removed
- **2292 tests** (all passing)

---

## [v1.15.1] — 2026-04-12

### Hotfix — bash-completion

- `--explain` was listed as `--explain=` in `long_opts` → trailing `=` removed; now completes correctly without `=`
- `compopt -o nospace` added: suppresses trailing space when the single completion result ends with `=` (e.g. `--target=`, `--log-days=`, `--profile=`)

---

## [v1.15.0] — 2026-04-12

### TL;DR
- **CHECK 26** — IoT/local source dominance in UFW logs (≥ 70% blocked traffic from one private IP)
- **CHECK 27** — SMTP local exposure (Postfix/Exim listening on 0.0.0.0:25 vs 127.0.0.1:25)
- **C1** — `--fix` dry-run by default; `--fix --apply` to execute; `--fix --apply --yes` auto-confirm
- **C2** — `--target N` score cible: shows gap or success in summary box
- **`--explain` TUI fixes** — clamped nav, in-curses detail screen, ESC/q behavior fixed, group headers restored on scroll-up
- **`--explain` 73→77 keys** — `user_accounts` group (+4 keys)
- **`q` cancels wizards** — `--install-cron`, `--manage-cron`, `--manage-logs`
- **Quality pass `smtp.py`** — `*` wildcard bug, multi-bind worst-case, IPv6 bracket stripping, Postfix-specific fix cmd
- **2139/2139 tests** (+93 vs v1.14.0)

### Changes

**`checks/logs.py`** (CHECK 26)
- `_dominant_local_source(entries)`: counts blocked entries per private source IP; returns `(ip, count, pct)` when one IP ≥ 70% and total ≥ 50
- `check_logs()`: calls `_dominant_local_source()` after bruteforce/service checks; emits `logs.local_dominance` WARN −1 pt when triggered
- Constants `_LOCAL_DOMINANCE_THRESHOLD = 0.70`, `_LOCAL_DOMINANCE_MIN_COUNT = 50`

**`checks/smtp.py`** (CHECK 27 — new file)
- `SmtpSnapshot`: `installed`, `mta_name`, `listening`, `bind_address`, `exposed`
- `SmtpSnapshot.from_system()`: MTA detection via `ps -eo comm` (`_MTA_BINARIES`); port-25 check via `_check_port_25()` (ss → netstat fallback)
- `_LOCAL_BIND_RE`: matches `127.*`, `::1`, `localhost` as safe bind addresses
- `check_smtp()`: not installed → OK; installed not listening → INFO; local only → INFO; exposed → WARN −1 pt (context `public`)

**`cli.py`**
- New `apply: bool = False` field in `AuditConfig`
- `--apply` flag parsed; requires `--fix`
- `--yes` now requires `--fix --apply` (was `--fix`)
- `--quiet`/`--json` incompatibility now scoped to `--fix --apply` (dry-run mode is compatible)
- New `target: int = 0` field; `--target=N` / `--target N` parsed (1–10)
- `--target` validation: non-numeric, 0, or >10 → `CLIError`
- `--target=` added to AUDIT section of `--help`

**`fixes.py`**
- Dry-run branch: `if not getattr(config, "apply", False):` — shows `fixes.dry_run_hint` + `→ cmd` preview for each item, then returns without executing

**`display.py`**
- `print_audit_summary()`: reads `config.target`; appends target line to summary box when set; green `✔` when reached, yellow `▲` with gap when not

**`explain.py`**
- `_picker()`: clamped navigation (no wrap at list boundaries); Enter calls `_detail_screen()` inline; only `q`/`Q` quit
- `_detail_screen()`: in-curses detail view; scrollable with ↑↓/PgUp/PgDn; only ESC closes
- Group headers reappear on scroll-up (looks back one item to include header)
- `user_accounts` group added: `uid_zero`, `empty_password`, `expired_account`, `no_shadow`

**`cron.py`** / **`manage_logs.py`**
- `q` cancels at any wizard step in `--install-cron`, `--manage-cron`, `--manage-logs`
- `prompt_emails()`: `q. Cancel — back to menu` now displayed as an explicit list entry so users know they can exit without modifying anything (`email_prompt.cancel` locale key); behaviour unchanged — `q` already returned `None`
- `--manage-cron` shows one line per email address in listing

**Locales (`en.json` + `fr.json`)**
- Added: `logs.local_dominance`, `smtp.*` (5 keys), `fixes.dry_run_hint`
- Added: `scoring.target_label`, `scoring.target_reached`, `scoring.target_gap`
- Added: `install_cron.quit_hint`, `install_cron.cancelled`, `manage_cron.cancelled`, `manage_logs.cancelled`
- Added: `email_prompt.cancel`

**Bash completion**
- Added `--apply`, `--target=`

**Tests**
- `TestApplyFlag` (12 tests), `TestTargetFlag` (10 tests), `TestDryRun` (8 tests)
- `TestDominantLocalSource` (13 tests, `test_logs.py`)
- `test_smtp.py` (31 tests)
- Updated `test_cli.py`: `test_yes`, `test_json_and_fix_raises`, `test_quiet_and_fix_raises` for new semantics
- `test_explain_flag_without_value_raises` → `test_explain_flag_without_value_launches_interactive`
- **2130 tests** (all passing)

**Quality pass — `checks/smtp.py`**
- `_LOCAL_BIND_RE`: removed `\*$` — `*` in `ss` output signals all-interface binding (was incorrectly classified as local-only, producing false negatives on `*:25` systems)
- `_check_port_25()`: collects all bind addresses for port 25 in a single pass; strips `[` `]` brackets from IPv6 addresses before regex matching (`[::1]` → `::1`, `[::]:25` → `::` → exposed); returns the most exposed address when multiple sockets coexist (`127.0.0.1:25` + `0.0.0.0:25` → returns `0.0.0.0`)
- `check_smtp()`: fix command is now Postfix-specific (`sudo postconf -e 'inet_interfaces = loopback-only'`); `note` field carries the restart hint; `cmd` is empty for Exim/other MTAs so the finding appears as a manual action
- `smtp.exposed_restart_postfix` locale key added (`en.json` + `fr.json`)
- `test_smtp.py`: `test_wildcard_star` → `test_wildcard_star_is_exposed` (inverted assertion); +2 `_LOCAL_BIND_RE` edge-case tests; `TestSmtpCmd` (4 tests — postfix has cmd, exim/unknown have no cmd); `TestSmtpWildcardExposed` (3 tests — `*`/`::` exposed, `::1` local)
- **2139 tests** (all passing)

---

## [v1.14.0] — 2026-04-10

### TL;DR
- **CHECK 24 — Samba Security Audit** (`checks/samba.py`) — SMB1, null passwords, guest shares, server signing, map-to-guest; 6 findings; new Samba domain
- **CHECK 25 — ClamAV Antivirus Audit** (`checks/clamav.py`) — installation detection, DB freshness, last scan age; local-time naive datetime for log parsing
- **`--diff` fix** — `info_count` now tracked and included in baseline delta
- **`--explain` 63→73 keys** (17 groups) — Samba (6) + Disk (5) added
- **2045/2045 tests** (+155 vs v1.13.0)

### Changes

**`checks/samba.py`**
- `SambaSnapshot` + `check_samba()` — pure snapshot/logic separation
- SMB1 enabled → ALERT −2; null passwords → ALERT −3; guest writable share → WARN −1; guest read-only → INFO; server signing disabled → WARN −1; map to guest → WARN −1
- 12 locale keys in `en.json` + `fr.json`

**`checks/clamav.py`** (+ quality pass)
- `ClamavSnapshot` + `check_clamav()` — installation via `clamav-daemon`, `freshclam`, or clamd socket (`_CLAMD_SOCKETS`)
- DB age via `datetime.fromtimestamp(st_mtime, tz=timezone.utc)` + `.days`; ≥14 d → ALERT −2, ≥7 d → WARN −1
- Last scan age parsed from `/var/log/clamav/clamav.log` as **naive local time** (ClamAV logs local time); ≥30 d → ALERT −2, ≥14 d → WARN −1
- `(?i)` on `_END_DATE_RE`; `_CLAMD_SOCKETS` module-level constant for socket fallback

**`compare.py`**
- `build_baseline()` now includes `info_count`; `compute_delta()` reports `info_count` changes in diff output

**`explain.py`**
- 73 keys across 17 groups; added Samba (6) and Disk (5) keys

**Tests**
- `tests/test_samba.py`: 52 tests
- `tests/test_clamav.py`: 52 tests; uses naive datetime for scan age; tests freshclam-only and clamd socket fallback

---

## [v1.13.0] — 2026-04-10

### TL;DR
- **CHECK 22 — Disk Health** (`checks/disk.py`) — SMART health (`smartctl -H/-A`) + partition usage (`df -P`); new `disk` domain (6th); 22 locale keys; NVMe support; SMART tips
- **CHECK 23 — Memory & Swap** (`checks/memory.py`) — SSD wear detection, unjustified swap (3-condition), profile-aware swappiness; routes to `hardening` domain; 9 locale keys
- **Partition table display** — `display_disk_partitions()` with colored progress bars (green/yellow/red) in DISK HEALTH section
- **`--explain` 33 → 63 keys** — 30 new keys across 15 groups; `--explain list` now displays labeled group headers
- **Quality pass** — disk.py (NVMe, SMART line-specific matching); memory.py (3-condition swap, swapon --show=NAME, /proc errors="ignore")
- **Tests: 1890/1890** (+187: `test_disk.py` 60 tests, `test_memory.py` 37 tests)

### CHECK 22 — Disk Health (`checks/disk.py`)

**Snapshot** (`DiskSnapshot`):
- `smartctl_available`: bool — True if `smartctl` is on PATH
- `smart_results`: List[SmartResult] — one entry per physical disk (`lsblk -d -n -o NAME,TYPE`)
- `partitions`: List[PartitionInfo] — non-pseudo mounted filesystems (`df -P --block-size=1G`)

**SmartResult** fields: `device`, `model`, `passed` (None = unknown), `virtual` (VM/unsupported), `reallocated_sectors`, `pending_sectors`, `uncorrectable_errors`

**Check logic** (`check_disk`):
| Condition | Level | Deduction |
|-----------|-------|-----------|
| SMART FAILED | ALERT | −3 pts |
| Reallocated sectors > 0 | WARN | −1 pt |
| Pending sectors > 0 | WARN | −1 pt |
| Uncorrectable errors > 0 | WARN | −1 pt |
| Partition ≥ 90% full | WARN | −1 pt |
| Partition ≥ 80% full | INFO | none |
| SMART not available | INFO | none |
| Virtual/unsupported device | INFO | none |

**Helpers**:
- `_detect_block_devices()`: `lsblk -d -n -o NAME,TYPE` → `/dev/{name}` for type=disk
- `_query_smart(device)`: `smartctl -iH` (info + health) + `smartctl -A` (attributes); detects virtual/unsupported by keywords; SMART health matched on "SMART overall-health" line only
- `_parse_nvme_attrs(output)`: maps NVMe health counters — Media and Data Integrity Errors → `uncorrectable_errors`, Error Information Log Entries → `pending_sectors`
- `_parse_smart_attr(output, attr_id)`: parses RAW_VALUE at column index 9 (standard smartctl -A format); handles inline parenthetical notation
- `_read_partition_usage()`: skips tmpfs, devtmpfs, squashfs, overlay, udev, cgroupfs, proc, sysfs, etc.; `--block-size=1G` for GB display
- `disk.smart_tips` INFO finding: `smartctl -a` per disk + guided commands for short/long tests, watch, abort (`-X`), history (`-l selftest`)

**New `disk` domain** in `domain_scores.py`:
- Added as 6th entry in `DOMAINS` list (between `hardening` and `firewall`)
- `_LABELS["disk"] = "Disk Health"`
- `_PREFIX_TO_DOMAIN["disk"] = "disk"`

### CHECK 23 — Memory & Swap (`checks/memory.py`)

**Snapshot** (`MemorySnapshot`):
- `mem_total_kb`, `mem_available_kb`: from `/proc/meminfo` (with `errors="ignore"`)
- `swap_total_kb`, `swap_free_kb`: from `/proc/meminfo`
- `swappiness`: from `/proc/sys/vm/swappiness` (with `errors="ignore"`)
- `swap_on_ssd`: bool — `/sys/block/{dev}/queue/rotational` = 0; handles NVMe partition stripping
- `swap_devices`: List[str] — from `swapon --show=NAME --noheadings --raw`

**Check logic** (`check_memory`, `profile_name="server"`):
| Condition | Level | Deduction |
|-----------|-------|-----------|
| No swap configured | INFO | none |
| Swap on SSD + swappiness > 30 | WARN | −1 pt |
| Swap used ≥ 32 MB AND RAM > 50% free AND swappiness > recommended | WARN | none |
| swappiness suboptimal (default 60) | INFO | none |
| swappiness optimal | OK | none |

Profile-aware recommended swappiness: server → 1; workstation → 10.
Unjustified swap requires all 3 conditions to avoid false positives from kswapd LRU aging.

**Domain**: findings with prefix `memory` route to `hardening` via `_PREFIX_TO_DOMAIN`.

**Constants**: `_SSD_SWAPPINESS_THRESHOLD = 30`, `_RAM_FREE_THRESHOLD = 0.50`, `_MIN_SWAP_USED_KB = 32 * 1024`

### Locale (`en.json`, `fr.json`)

**Disk keys** (27): `disk.ok`, `disk.smartctl_missing`, `disk.smartctl_missing_detail`, `disk.smart_ok`, `disk.smart_failed`, `disk.smart_failed_detail`, `disk.smart_failed_reason`, `disk.smart_virtual`, `disk.smart_unknown`, `disk.reallocated_sectors`, `disk.reallocated_sectors_detail`, `disk.reallocated_sectors_reason`, `disk.pending_sectors`, `disk.pending_sectors_detail`, `disk.pending_sectors_reason`, `disk.uncorrectable_errors`, `disk.uncorrectable_errors_detail`, `disk.uncorrectable_errors_reason`, `disk.partition_critical`, `disk.partition_critical_detail`, `disk.partition_critical_reason`, `disk.partition_warn`, `disk.smart_tips`, `disk.smart_tips_detail`, `disk.col_mountpoint`, `disk.col_size`, `disk.col_used`

**Memory keys** (9): `memory.no_swap`, `memory.swap_stats`, `memory.swappiness_ok`, `memory.swappiness_ssd_wear`, `memory.swappiness_ssd_detail`, `memory.swappiness_unjustified`, `memory.swappiness_unjustified_detail`, `memory.swappiness_suboptimal`

**Section keys**: `sections.memory = "MEMORY & SWAP"`, `sections.disk = "DISK HEALTH"`

### Display (`display.py`)

- `display_disk_partitions(snapshot, t, output_module)` — partition table in DISK HEALTH section
  - Columns: mountpoint, device, size (GB), colored progress bar, usage%
  - Bar: `█` (filled) + `░` (empty), 10 chars wide; color: green < 70%, yellow < 90%, red ≥ 90%
  - Size: `< 1 GB` when < 0.5 GB, else `N GB`; `_disk_bar()` and `_gb_str()` helpers
  - Rows use `print()` directly (not `print_dim`) to preserve embedded ANSI color codes

### Runner (`runner.py`)

- `display_disk_partitions` imported and called after `display_result(disk_result, ...)` inside `if not config.quiet:`
- `--explain` list: grouped display with 15 labeled sections via `_EXPLAIN_GROUPS`

### `--explain` (`explain.py`)

- `_EXPLAIN_GROUPS`: 15 groups, 63 keys — single source of truth from which `EXPLAIN_KEYS` is derived
- New groups: SSH — Authorized Keys (5 keys), SSH — Client Config (3 keys), Firewall Rules (2 keys), IPv6 (2 keys), Password Policy (2 keys), Disk (3 keys), Memory (2 keys)
- `run_explain(key="list")` now iterates `_EXPLAIN_GROUPS` and prints group headers
- `tests/test_explain.py`: `test_has_sixty_three_keys` asserts `len(EXPLAIN_KEYS) == 63`

### Tests

- `tests/test_disk.py` — 60 tests across 9 classes (+3 NVMe tests):
  - `TestSnapshotDefaults`, `TestSmartctlMissing`, `TestSmartVirtual`, `TestSmartUnknown`, `TestSmartPassed`, `TestSmartFailed`, `TestSmartAttributes`, `TestNvmeAttrs`, `TestMultipleDisks`, `TestPartitionUsage`, `TestAllClear`, `TestParseSmartAttr`, `TestEdgeCases`
- `tests/test_memory.py` — 37 tests across 8 classes (+6 robustness tests):
  - `TestSnapshotDefaults`, `TestNoSwap`, `TestSsdWear`, `TestUnjustifiedSwap`, `TestSuboptimalSwappiness`, `TestProfileAware`, `TestSwapStats`, `TestEdgeCases`

---

## [v1.12.0] — 2026-04-10

### TL;DR
- **CLI pass** — `--help` redesigned with 7 sections; 6 new short options; bash completion fixed (7 missing opts + smart completions)
- **Fix #1** — Risk context block now shown for all active services; 11 new `service_risk` entries for medium/low services (Apache, Nginx, Transmission, qBittorrent, Avahi, CUPS, Jellyfin, Plex, Gitea, Syncthing, Ollama)
- **Fix #2** — GeoIP wget command now includes `sudo mkdir -p /usr/share/GeoIP` prefix (absent on Debian by default)
- **Fix #3** — `unattended-upgrades` compound risk demoted to INFO (no extra −1 pt) on `workstation` profile
- **Fix #4** — Expired accounts show ISO date per account; system accounts (UID < 1000) excluded from expiry check
- **Tests: 1703/1703** (+16 new: workstation profile, date assertions, dict fixtures)

### `--help` redesign (`cli.py`)
- 7 sections: AUDIT / OUTPUT / FIXES / INTEGRATIONS / CONFIGURATION / MAINTENANCE / STANDALONE
- Each section has a one-line description; STANDALONE groups no-sudo commands
- EXIT CODES section clarified for scripting use

### New short options (`cli.py`)
| Short | Long            | Purpose                    |
|-------|-----------------|----------------------------|
| `-J`  | `--json-full`   | Full JSON export           |
| `-C`  | `--manage-cron` | Manage cron jobs           |
| `-e`  | `--explain KEY` | Explain a finding key      |
| `-D`  | `--diff`        | Diff mode                  |
| `-w`  | `--webhook URL` | Webhook URL                |
| `-p`  | `--profile NAME`| Audit profile              |

### Bash completion (`data/ufw-audit.bash-completion`)
- Added 7 previously missing long options: `--lang=`, `--profile=`, `--reset-baseline`, `--explain=`, `--diff`, `--webhook=`, `--webhook-format=`
- Added 6 new short options: `-J -C -p -e -D -w`
- Smart completions: `--profile=` → server/workstation/container; `--lang=` → en/fr; `--webhook-format=` → auto/generic/slack; `-p <value>` → server/workstation/container

### Risk context for all services (`en.json`, `fr.json`, `runner.py`, `display.py`)
- `service_risk` entries added for: `apache_web_server`, `nginx_web_server`, `transmission_web_ui`, `qbittorrent_web_ui`, `avahi_local_network_discovery`, `cups_network_printing`, `jellyfin`, `plex_media_server`, `gitea`, `syncthing`, `ollama_llm_server`
- `runner.py:150`: `is_high_or_critical` gate removed — risk context shown for all active services
- `display.py:build_risk_context_entries`: same gate removed for JSON report entries

### GeoIP wget fix (`en.json`, `fr.json`, `display.py`)
- `geoip2_no_db_cmd` now: `sudo mkdir -p /usr/share/GeoIP && sudo wget -O /usr/share/GeoIP/GeoLite2-Country.mmdb ...`
- Fallback hardcoded cmd in `display.py` updated identically

### Unattended-upgrades profile-aware (`checks/updates.py`, `runner.py`)
- `check_updates()` gains `profile_name: str = "server"` parameter
- When `profile_name == "workstation"`: compound risk branch (`security pending + no automation`) emits INFO instead of WARN with no extra deduction
- `runner.py`: passes `profile_name=profile.name if profile else "server"`

### Expired accounts with dates (`checks/user_accounts.py`)
- `UserAccountsSnapshot.expired_accounts`: `List[str]` → `Dict[str, str]` (username → ISO date)
- `from_system()`: tracks UIDs from `/etc/passwd`; skips accounts with UID < 1000 (system accounts managed by package manager)
- `check_user_accounts()`: formats finding message as `"alice (2023-06-15), bob (2022-01-01)"`

### Tests
- `test_cli.py`: 8 new tests — `test_diff_short`, `test_explain_short`, `test_profile_short`, `test_json_full_short`, `test_manage_cron_short`, `test_webhook_short`, `test_explain_short_with_space`, `test_explain_short_list`
- `test_updates.py`: `TestWorkstationProfile` — 5 new tests covering workstation INFO demotion and server WARN preservation
- `test_user_accounts.py`: `expired_accounts` fixtures converted to dict; `test_date_in_message`, `test_multiple_expired_all_in_message`, `test_empty_dict_expired_produces_ok` added

---

## [v1.11.0] — 2026-04-07

### TL;DR
- **`--explain` Phase A2** — `EXPLAIN_KEYS` expanded from 20 to 33 (11 new SSH keys + `fail2ban_missing` + 2 kernel module keys + `pipe_to_shell` + `enabled_inactive`); locale entries + CIS refs for all 13 new keys
- **User Account Audit** (CHECK 17) — UID 0 non-root (ALERT −3), empty password on login-capable account (ALERT −2), expired accounts (INFO); reads `/etc/passwd` always + `/etc/shadow` when root
- **Password Policy Audit** (CHECK 18) — no PAM quality module (WARN −1), explicit `minlen < 8` (WARN −1), `PASS_MAX_DAYS ≥ 365` (INFO only, per NIST SP 800-63B); reads `login.defs` + `common-password` + `pwquality.conf`
- `user_accounts` → `file_perms` domain; `password_policy` → `hardening` domain
- Quality pass: snapshot immutability tests; boundary tests; `test_no_t_does_not_crash` for both new checks
- 1675/1675 unit tests (+134)

### `--explain` Phase A2 (`explain.py`)

`EXPLAIN_KEYS` grows from 20 to 33 entries, organized by category with comments:

```python
# SSH — authentication (6)
# SSH — access control (8)
# SSH — cryptography (3)
# Files & access (4)
# Updates (2)
# Hardening (5)
# Kernel modules (2)
# Cron (2)
# Services (1)
```

New keys: `ssh.max_auth_tries`, `ssh.allow_tcp_forwarding`, `ssh.x11_forwarding`, `ssh.permit_user_env`, `ssh.ignore_rhosts_disabled`, `ssh.host_based_auth`, `ssh.strict_modes_disabled`, `ssh.client_strict_host_no`, `ssh.weak_ciphers`, `ssh.weak_macs`, `ssh.weak_kex`, `hardening.fail2ban_missing`, `kernel_modules.risky_fs`, `kernel_modules.risky_net`, `cron_audit.pipe_to_shell`, `services_state.enabled_inactive`.

Both `en.json` and `fr.json` receive title/why/how/CIS entries for all 13 new keys.

### User account audit (`checks/user_accounts.py` — CHECK 17)

**Snapshot** (`UserAccountsSnapshot`):
- `/etc/passwd` always readable — populates `uid_zero_accounts` (UID 0 ≠ root) and `login_shells` map
- `/etc/shadow` root-only — sets `shadow_readable`, populates `empty_password_accounts` (field 1 empty + login shell) and `expired_accounts` (field 7 non-zero integer < today)
- Accounts with `nologin`/`/bin/false` shells excluded from empty-password check

**Check logic** (`check_user_accounts`):
| Condition | Level | Deduction |
|-----------|-------|-----------|
| UID 0 non-root account(s) | ALERT | −3 pts flat |
| Empty password on login-capable account | ALERT | −2 pts flat |
| Expired account expiry date | INFO | none |
| `/etc/shadow` unreadable | INFO | none |

All account lists use `dict.fromkeys` deduplication; snapshot is never mutated.

### Password policy audit (`checks/password_policy.py` — CHECK 18)

**Snapshot** (`PasswordPolicySnapshot`):
- `/etc/login.defs` — `PASS_MAX_DAYS`, `PASS_MIN_DAYS`
- `/etc/pam.d/common-password` — detects `pam_pwquality.so` or `pam_cracklib.so`; captures inline `minlen=`
- `/etc/security/pwquality.conf` — captures `minlen` (takes precedence over inline option)

**Check logic** (`check_password_policy`):
| Condition | Level | Deduction |
|-----------|-------|-----------|
| No PAM quality module | WARN | −1 pt |
| Explicit `minlen < 8` (module configured) | WARN | −1 pt |
| `PASS_MAX_DAYS ≥ 365` | INFO | none |

`no_quality_module` and `weak_minlen` use `elif` — mutually exclusive. Rationale: you cannot have a consciously weakened minlen without a configured module.

---

## [v1.10.0] — 2026-04-07

### TL;DR
- **`--explain` hint in summary box** (Phase A1) — every actionable finding now shows `? ufw-audit --explain <key>` when the key is explainable
- **Kernel Module Audit** (CHECK 14) — detects risky loaded kernel modules (filesystem: cramfs, hfs, squashfs, usb_storage…; network: dccp, sctp, rds, tipc)
- **Cron Job Audit** (CHECK 15) — flags `curl/wget | sh/bash/zsh` pipes, world-writable cron scripts, unexpected user crontabs; `/etc/cron.d` parsed as crontab format
- **Service State Audit** (CHECK 16) — two-step `systemctl` query; warns when a security service is enabled at boot but currently inactive/failed
- `kernel_modules`, `cron_audit`, `services_state` map to the `hardening` domain in domain scores
- Quality pass: `shlex.quote` in fix cmds; `key=` on all `firewall.py` rule findings; 9 test files expanded (19→29, 25→63, 47→54, 52→62, 37→42, 17→20…)
- 1541/1541 unit tests (+209)

### `--explain` hint in summary box (`display.py` — Phase A1)

Inside `print_audit_summary()`, the `_add_finding_lines()` closure now injects a hint line under each finding whose key resolves to an explainable key:

```
? ufw-audit --explain <normalized_key>
```

- Uses `normalize_key()` from `explain.py` — `file_perms.shadow.world_writable` → `file_perms.world_writable`
- Only shown when the normalized key is in `EXPLAIN_KEYS`
- Hint is built directly as an f-string (no locale lookup needed — the command syntax is language-agnostic)
- New test file: `tests/test_display_explain_hint.py` — 25 tests (normalize_key unit, EXPLAIN_KEYS membership, integration with `print_audit_summary`)

### Kernel module audit (`checks/kernel_modules.py` — CHECK 14)

New module implementing CHECK 14 in `runner.py`:

**`KernelModulesSnapshot`** — collected via `from_system()` using `lsmod`:
- `lsmod_available` — whether `lsmod` exists on this system
- `loaded_modules` — full list of currently loaded module names, normalized to lowercase at collection

**`check_kernel_modules(snapshot, t)`**:
- `_RISKY_FS` — cramfs, freevxfs, jffs2, hfs, hfsplus, squashfs, udf, usb_storage
- `_RISKY_NET` — dccp, sctp, rds, tipc
- Risky FS loaded → WARN `kernel_modules.risky_fs`, −1 pt (flat); cmd: `sudo modprobe -r <modules>` (shell-safe via `shlex.quote`)
- Risky net loaded → WARN `kernel_modules.risky_net`, −1 pt (flat)
- Max −2 pts; both categories are independent
- `lsmod` unavailable → INFO `kernel_modules.no_lsmod`, no deduction
- `None`-safe: `loaded_modules or []` guard
- New test file: `tests/test_kernel_modules.py` — 48 tests

### Cron job audit (`checks/cron_audit.py` — CHECK 15)

New module implementing CHECK 15 in `runner.py`:

**`CronAuditSnapshot`** — collected via `from_system()`:
- `pipe_to_shell_entries` — cron lines matching `\b(curl|wget)\b.*|\S*sh\b` (covers `/bin/sh`, `zsh`, `/usr/bin/bash -s`)
- `/etc/cron.d` parsed as crontab format (script paths extracted from lines); `cron.daily/hourly/weekly/monthly` stat'd directly
- `world_writable_scripts` — world-writable `.sh` scripts found via both paths (deduped)
- `unexpected_user_crons` — usernames in `/var/spool/cron/crontabs/` not in `_EXPECTED_CRONTAB_USERS` (default: `root`)

**`check_cron_audit(snapshot, t)`**:
- Pipe-to-shell → WARN `cron_audit.pipe_to_shell`, −2 pts (flat, `nature="action"`)
- World-writable script → WARN `cron_audit.world_writable`, −1 pt (flat); cmd: `sudo chmod o-w <scripts>` (shell-safe via `shlex.quote`)
- Unexpected user crontab → INFO `cron_audit.unexpected_users`, no deduction
- Max −3 pts total; `None`-safe
- New test file: `tests/test_cron_audit.py` — 47 tests (incl. regex parametrize, shell injection quoting)

### Service state audit (`checks/services_state.py` — CHECK 16)

New module implementing CHECK 16 in `runner.py`:

**`ServicesStateSnapshot`** — collected via `from_system()` using two-step `systemctl` query:
1. `systemctl list-unit-files --type=service` → collect `enabled` / `enabled-runtime` services
2. `systemctl list-units --all --type=service` → filter by active state, skip if not in enabled set
- `systemctl_available` — whether `systemctl` exists
- `enabled_inactive` — services that are both `enabled` AND currently `inactive` or `failed`

**`check_services_state(snapshot, t)`**:
- Monitored services (`SECURITY_SERVICES`): ufw, fail2ban, apparmor, auditd, clamav-daemon, clamav-freshclam, ssh, sshd, crowdsec, ossec
- One WARN per inactive service (`nature="action"`), −1 pt each; cmd: `sudo systemctl restart <svc> && sudo journalctl -u <svc> -n 50` (shell-safe via `shlex.quote`)
- Deductions capped at −3 pts; findings emitted for all inactive services regardless
- `systemctl` unavailable → INFO `services_state.no_systemctl`, no deduction
- `None`-safe
- New test file: `tests/test_services_state.py` — 35 tests

### Domain scores update

`kernel_modules`, `cron_audit`, and `services_state` deductions now map to the `hardening` domain in `_PREFIX_TO_DOMAIN` (previously fell to `firewall` catch-all).

### Quality pass

**Source changes:**
- `checks/firewall.py` — added `key=` to all findings in `_check_duplicates`, `_check_open_any`, `_check_ipv6_coverage`

**Test improvements:**

| File | Before | After | Key changes |
|------|--------|-------|-------------|
| `test_check_rules.py` | 19 | 29 | Key-based assertions; `TestOpenAny`/`TestDuplicates`/`TestIPv6Coverage`/`TestCombined` classes |
| `test_cli.py` | 25 | 63 | All defaults/flags/combos; `TestWebhook`, `TestExplain`, `TestMutuallyExclusiveModes` |
| `test_compare.py` | 47 | 54 | `SimpleNamespace` for data objects; module-level `_make_delta()`; `skipif` Windows |
| `test_cron.py` | 52 | 62 | Parametrized `TestOrdinal`; French weekdays; `_parse_dom("")` edge case |
| `test_ddns.py` | 37 | 42 | Quoted hostname; empty value; fallback regex; malformed rule no-crash |
| `test_degraded.py` | 17 | 20 | Real `LogEntry`; `check_firewall(inactive)` + empty ports/rules combos |

### Tests summary

| File | Tests | Coverage |
|------|-------|----------|
| `test_display_explain_hint.py` | 25 | normalize_key, EXPLAIN_KEYS, hint injection, no-hint cases, multi-finding, normalized vs raw key |
| `test_kernel_modules.py` | 48 | lsmod unavailable, all-OK, risky FS, risky net, combined, _unload_cmd (incl. shell quoting), snapshot defaults, RISKY_MODULES set, edge cases |
| `test_cron_audit.py` | 47 | all-OK, pipe-to-shell, world-writable, unexpected users, combined, _chmod_cmd (incl. shell quoting), regex parametrize (sh/bash/zsh/bin/sh), snapshot defaults, edge cases |
| `test_services_state.py` | 35 | systemctl unavailable, all-OK, inactive services, cap at 3, cmd content, nature, SECURITY_SERVICES set, edge cases |

---

## [v1.9.0] — 2026-04-06

### TL;DR
- **System Updates Audit** (CHECK 13) — apt pending security/regular packages, unattended-upgrades detection
- **`--explain KEY`** — WHY/HOW/CIS explanations for 20 finding keys
- **Webhooks** (`--webhook`) — generic and Slack payloads, non-fatal
- **Domain scores** — 5-domain sub-scores in terminal, JSON, and webhook
- **`--diff` mode** — silent audit, delta-only display
- Code quality pass on domain_scores, updates, webhook, explain
- 1332/1332 unit tests (+228)

### System updates audit (`checks/updates.py`)

New module implementing CHECK 13 in `runner.py`:

**`UpdatesSnapshot`** — collected via `from_system()`:
- `apt_available` — `_command_exists("apt-get")`
- `pending_security` / `pending_regular` — parsed from `apt-get -s upgrade` Inst lines; `-security` suite regex
- `unattended_installed` / `unattended_enabled` — dpkg-query + apt-conf + systemd timer

**`check_updates(snapshot, t)`**:
- `pending_security` non-empty → WARN `updates.security_pending`, −2 pts (flat, order-preserving dedup via `dict.fromkeys`)
- `pending_regular` non-empty → INFO `updates.regular_pending`, no deduction
- `!uu_ok + pending_security` → WARN `updates.unattended_not_configured`, −1 pt (compound risk)
- `!uu_ok + no security` → INFO `updates.unattended_not_configured`, no deduction
- `pending_security or []` / `pending_regular or []` — `None`-safe guard at top of function

### `--explain KEY` (`explain.py`)

- `EXPLAIN_KEYS` — 20 canonical keys: SSH ×11, file_perms ×4, updates ×2, hardening ×2, firewall ×1
- `normalize_key(key)` — regex `^(file_perms)\.(?:[^.]+\.)+(…)$` strips middle segments; handles deep nesting
- `run_explain(key, t)` — prints title / WHY IT IS A RISK / HOW TO FIX / CIS reference; `key="list"` mode
- `explain_cis` locale section — 20 keys × CIS Ubuntu 22.04 benchmark control (EN + FR)
- No root required — `__main__.py` exits before privilege check when `--explain` is set

### Webhooks (`webhook.py`)

- `_is_slack_url(url)` — detects `hooks.slack.com` or `/services/t` (case-insensitive)
- `detect_format(url, requested)` — `auto` delegates to `_is_slack_url`; `generic`/`slack` explicit override
- `build_generic_payload()` — includes `source`, `version`, `host`, `timestamp` (UTC), `score`, `max_score`, `risk`, `alerts`, `warnings`, `domain_scores`, `findings`
- `build_slack_payload()` — colour-coded attachment (red/orange/green), findings truncated at 2500 chars
- `send_webhook()` — `urllib.request` only; raises `WebhookError` on HTTP error/URL error/OSError/non-2xx; `--offline` suppresses call
- Config persistence: `UserConfig.get/set_webhook_url()`, `get/set_webhook_format()` with validation

### Domain scores (`domain_scores.py`)

- `DOMAINS = ["ssh", "file_perms", "updates", "hardening", "firewall"]`
- `_key_to_domain(key)` — maps `key.split(".", 1)[0]` to domain; unknown prefix → `"firewall"`; `None`/non-str → `None`
- `compute_domain_scores(engine)` — aggregates `engine.breakdown` deductions by domain; `max(0, min(10, 10 − pts))`; synthetic/empty keys excluded via `_key_to_domain`
- `render_domain_scores(scores, t)` — █/░ bar chart; `int()` fill (no rounding artefacts); empty-safe
- Always included in `build_json_data()` and `build_generic_payload()`; displayed in terminal after `print_audit_summary()`

### CLI additions (`cli.py`)

| Flag | Default | Behaviour |
|------|---------|-----------|
| `--explain=KEY` | `""` | Calls `run_explain()` and exits (no root required) |
| `--diff` | `False` | Sets `quiet=True`, shows only delta |
| `--webhook=URL` | `""` | POSTs result after audit |
| `--webhook-format=FMT` | `"auto"` | `auto\|generic\|slack`; invalid → `CLIError` |

### Tests

| File | Tests | Coverage |
|------|-------|----------|
| `test_updates.py` | 34 | apt unavailable, security/regular pending, unattended-upgrades, combined, edge cases (None lists, duplicates, invariants, mutation guard) |
| `test_explain.py` | ~94 | normalize_key (deep nesting, over-strip guard, all canonical), EXPLAIN_KEYS list, run_explain (unknown, list, all 20 keys ×3 parametrized + snapshot), CLI parsing |
| `test_domain_scores.py` | ~48 | _key_to_domain (None, ".", double-dot), deduction attribution, floor/ceiling, multi-deduction stacking, cross-domain isolation, rendering (order, partial bar), CIS all-20-keys, JSON/webhook structure |
| `test_webhook.py` | ~54 | URL detection, format selection, generic/Slack payloads (structure, content, domain_scores, JSON serializable), HTTP mocking (status, Content-Type, body, errors, timeout, format dispatch), UserConfig persistence, CLI parsing, combined flags |

---

## [v1.8.0] — 2026-04-05

### TL;DR
- **SSH Security Audit** (CHECK 11) — full `sshd_config` analysis, private key audit, `authorized_keys`, `~/.ssh/config`, `known_hosts`
- Targets `SUDO_USER`'s home directory, not root's
- Distro-aware install command hints (apt/dnf/pacman/zypper/apk)
- i18n fix: "What to do?" label was hardcoded French in all locales — now fully translated via `output.recommendation_label`
- INFO findings now display their detail text in verbose mode (`-v`)
- 1104/1104 unit tests (+138)

### SSH audit (`checks/ssh.py`)

New module implementing CHECK 11 in `runner.py`:

**`SSHSnapshot`** — collected via `from_system()`:
- `sshd_installed` / `sshd_active` via `which sshd` + `systemctl is-active`
- `install_cmd` — distro-aware: checks for apt > apt-get > dnf > yum > pacman > zypper > apk
- `config_lines` — first-value-wins parse of `/etc/ssh/sshd_config` + drop-ins in `/etc/ssh/sshd_config.d/*.conf`
- `private_keys` — scans `~/.ssh/` for files starting with `id_` (non-public); `_has_passphrase()` decodes OpenSSH new format (binary header, cipher field) and PEM fallback (`Proc-Type: 4,ENCRYPTED`)
- `authorized_keys` — reads `~/.ssh/authorized_keys`; each entry parsed for type and options
- `client_config_lines` — reads `~/.ssh/config` if present
- `known_hosts_count` — line count in `~/.ssh/known_hosts`
- `ssh_dir_perms` — octal permissions on `~/.ssh/`

**`check_ssh(snapshot, t)`** — calls 6 sub-checks:

- `_check_sshd_config` — 15 directives: `PasswordAuthentication`, `PermitRootLogin`, `X11Forwarding`, `PermitEmptyPasswords`, `MaxAuthTries` (> 3 → WARN), `LoginGraceTime` (> 60s → INFO), `IgnoreRhosts`, `HostbasedAuthentication`, `PermitUserEnvironment`, `StrictModes`, `AllowTcpForwarding` (enabled → WARN −1 pt), `PubkeyAuthentication` (disabled → ALERT −3 pts), `AllowUsers`/`AllowGroups` absence (INFO); plus weak crypto (CBC ciphers, HMAC-MD5/SHA1 MACs, DH group1/14/exchange-sha1 KEX) → WARN
- `_check_private_keys` — DSA → ALERT; RSA < 2048 → ALERT; ECDSA 256/384/521 bits → OK; ed25519 → OK; no passphrase → WARN −1 pt; unreadable key → INFO
- `_check_authorized_keys` — `ak_found_issue` flag prevents `authorized_keys_ok` from appearing alongside errors; deprecated options (no-pty, command=) → INFO; `from=` restriction → OK note
- `_check_ssh_dir_perms` — `~/.ssh` not 700 → WARN −1 pt
- `_check_client_config` — checks `StrictHostKeyChecking no` → WARN
- `_check_known_hosts` — empty `known_hosts` (SSH used but no hosts tracked) → INFO

**RSA bit extraction** — `_rsa_bits_from_blob(blob)`: decodes SSH RSA wire format `[ktype_len][ktype][e_len][e][n_len][n]`; modulus byte count × 8 = bit size.

**Bounds-checked binary parsing** — `_has_passphrase()` guards all `struct.unpack_from` calls with length checks; no crashes on truncated key files.

### i18n / display fixes

- `output.recommendation_label` i18n key added to `en.json` ("What to do?") and `fr.json` ("Que faire ?")
- `output.print_recommendation()` now imports `t()` lazily to avoid circular imports; uses `_t('output.recommendation_label')` instead of hardcoded French
- `display.py`: INFO findings now show their `detail` text in verbose mode — same branch as WARN/ALERT

### Tests (`tests/test_ssh.py`)

93 new tests (new file):

| Group | Tests | Coverage |
|-------|-------|----------|
| not installed / not active | 3 | install hint, active=False early return |
| `_check_sshd_config` | 26 | all 15 directives (incl. AllowTcpForwarding, PubkeyAuthentication), weak Ciphers/MACs/KEX, first-value-wins, multiple issue accumulation |
| `_check_private_keys` | 14 | DSA ALERT, RSA < 2048 ALERT, RSA ≥ 2048 OK, ed25519 OK, passphrase warn/ok, unreadable INFO |
| `_check_authorized_keys` | 12 | empty, no-file INFO, ok-suppressed-by-error, from= note, deprecated opts |
| `_check_ssh_dir_perms` | 4 | 700 ok, 755 warn, 777 warn |
| `_check_client_config` | 5 | StrictHostKeyChecking no warn, ok, absent |
| `_check_known_hosts` | 6 | count ok, empty info, absent info, comma-separated host duplicate detection |
| integration | 2 | combination (4 issues, ≥ 4 deductions), clean snapshot (score 0) |
| helpers | 21 | `_has_passphrase` (OpenSSH/PEM/none/truncated/empty), `_rsa_bits_from_blob`, `_detect_ssh_install_cmd` |

**Test helpers:** `_has_finding(result, key, level)` — combined key+level assertion; `_make_rsa_blob(bits)` — builds valid RSA public key wire-format blob; `base_snapshot(**kwargs)` — always used for constructing snapshots.

### Sensitive files & sudoers (`checks/file_perms.py`)

New module implementing CHECK 12 in `runner.py`:

**`FilePermsSnapshot`** — collected via `from_system()`:
- `sensitive_files` — `/etc/passwd` (644), `/etc/shadow` (640), `/etc/gshadow` (640), `/etc/group` (644), `/etc/sudoers` (440); permissions collected via `stat.S_IMODE`
- `ssh_host_key_issues` — `/etc/ssh/ssh_host_*_key` files (not `.pub`) with permissions ≠ 600
- `sudoers_nopasswd_all` / `sudoers_nopasswd_specific` — lines from `/etc/sudoers` + `/etc/sudoers.d/*` containing NOPASSWD, split by `_is_nopasswd_all()`

**`check_file_perms(snapshot, *, t)`** — pure logic:
- World-writable file (`mode & 0o002`): ALERT, −3 pts
- Extra permission bits beyond max_mode: WARN, −1 pt per file, capped at 3 total
- SSH host key wrong permissions: WARN, −1 pt, capped at 2 total
- `NOPASSWD:ALL` in sudoers: WARN per line, −2 pts (single deduction regardless of count)
- `NOPASSWD:<specific cmd>`: INFO, no deduction
- All clear: OK

**`_is_nopasswd_all(line)`** — extracts the command portion after `NOPASSWD:` and checks if it starts with `ALL`.

### Tests (`tests/test_file_perms.py`)

43 new tests (new file):

| Group | Tests | Coverage |
|-------|-------|----------|
| All OK | 4 | empty snapshot, correct perms, absent files |
| World-writable | 6 | ALERT level, −3 pts, correct key, mode 002 check, multiple files, no OK alongside |
| Too-permissive | 5 | WARN level, −1 pt, cap at 3 deductions, 4th file still gets finding |
| SSH host keys | 4 | WARN + −1 pt, cap at 2 deductions, 3 findings still emitted |
| Sudoers NOPASSWD ALL | 5 | WARN, −2 pts, key, multiple lines single deduction, no OK alongside |
| Sudoers NOPASSWD specific | 4 | INFO, no deduction, count, no OK |
| Combined | 3 | permissive+nopasswd_all, world_writable+host_key, all files correct |
| `_is_nopasswd_all` | 9 | true/false parametrize (full/specific/no-NOPASSWD/empty) |
| Dataclass | 3 | FilePermsSnapshot defaults, FileInfo fields |

---

## [v1.7.0] — 2026-04-04

### TL;DR
- **Audit profiles** — named profiles (`server`, `workstation`, `container`) in INI format; `--profile=NAME` flag, persisted in `~/.config/ufw-audit/config.conf`
- **`Deduction.key`** — deterministic deduction removal by key; replaces heuristic string matching on translated messages
- **Multi-email cron** — `--install-cron` now supports multiple notification recipients with loop + ✔ marker UI
- **Bulk cron delete** — `--manage-cron`: `d:1,3` (comma list), `d:1-3` (range), `d:all` (all jobs)
- **Ephemeral port filter** — `build_baseline()` excludes ports ≥ 32768; eliminates false-positive "new port" noise
- **`--reset-baseline`** — deletes `~/.config/ufw-audit/last_baseline.json` and exits
- 966/966 unit tests (+38)

### Audit profiles (`profiles.py`)

- `AuditProfile` dataclass: `name`, `description`, `overrides: dict[str, str]`, `skip_sections: set[str]`
- INI profile format: `[profile]` name/extends/description; `[overrides]` key=level; `[skip_sections]` section names
- `extends` chain resolved recursively, depth guard `_MAX_EXTENDS_DEPTH = 8`
- Override levels: `info | warn | alert | skip`
- Built-in profiles: `server.conf` (default), `workstation.conf`, `container.conf`
- User profiles in `~/.config/ufw-audit/profiles/` override built-ins
- `apply_profile(result, profile)` — post-check, mutates `CheckResult` in-place; section skipping applied upstream in `runner.py`
- `_find_profile_file()` cached with `@lru_cache(maxsize=32)`
- Override keys normalized with `strip().lower()`

### `Deduction.key`

- `key: str = ""` added to `Deduction` dataclass
- `add_deduction(key=)` added to `CheckResult`
- All scored deductions in `checks/hardening.py` and `checks/ipv6.py` carry matching `key=`
- `_remove_deductions_for_key()` simplified: `result.deductions = [d for d in result.deductions if d.key != key]`

### `--install-cron` multi-email

- `prompt_emails(t) -> list[str]` replaces `prompt_email(t) -> str`
- Loop: after each selection, "Add another email? [y/N]"; already-selected addresses shown with ✔
- `prompt_email(t)` kept as backward-compatible wrapper
- Bash script uses `NOTIFY_EMAILS` (CSV); `IFS="," read -ra _ADDRS` sends to each recipient individually

### `--manage-cron` bulk delete

- Delete expression extended: `d:N` | `d:N,M,...` | `d:N-M` | `d:all`
- Confirmation message adapts: single name / list of names / "ALL N cron jobs"

### Comparative report

- `_is_stable_port()` helper: excludes ports `>= 32768` from baseline
- `--reset-baseline` flag: `require_root()`, unlinks `_BASELINE_PATH`, returns `EXIT_OK`
- `_BASELINE_PATH` exported from `compare.py` as a public name

### Tests

- `tests/test_profiles.py` — 36 tests (new file)
- `tests/test_compare.py` — +2 (`test_ephemeral_ports_excluded`, `test_stable_ports_included`)
- `tests/test_ipv6.py` — +2 (`test_malformed_ss_output_returns_empty`, `test_malformed_ufw_lines_returns_empty`)
- `autouse` fixture `_clear_profile_cache` — clears `lru_cache` between tests

### Migration note

Run `sudo ufw-audit --reset-baseline` once after upgrading from v1.6.0 to discard any baseline that may contain ephemeral ports.

---

## [v1.6.0] — 2026-04-04

### TL;DR
- New **HARDENING** section: fail2ban, auto-updates, AppArmor, rp_filter, ICMP redirects, log_martians, ICMP broadcasts
- New **IPv6 CONSISTENCY** section: detects IPv6 listeners not covered by UFW v6 rules
- New **COMPARATIVE REPORT**: baseline saved after each audit — score delta, port changes, service changes displayed on next run
- New **Plugin check API**: drop Python files in `~/.config/ufw-audit/plugins/` to add custom checks
- JSON output (`--json-full`) extended with `hardening` and `ipv6` objects
- 926/926 unit tests (+160)

### New sections

- **HARDENING** (`checks/hardening.py`) — new check:
  - `fail2ban` active → OK, missing → INFO (no deduction — optional layer)
  - `unattended-upgrades` installed and configured → OK; missing → WARN (−1 point)
  - AppArmor enforce mode → OK; permissive/inactive/not installed → INFO (no deduction)
  - `rp_filter=1` (strict) → OK; `=2` (loose) → INFO; `=0` (disabled) → WARN (−1 point)
  - ICMP redirects accepted → WARN (−1 point); disabled → OK
  - `log_martians` disabled → INFO (no deduction)
  - ICMP broadcast echo not ignored → INFO (no deduction)

- **IPv6 CONSISTENCY** (`checks/ipv6.py`) — new check:
  - Detects when `net.ipv6.conf.all.disable_ipv6=1` or UFW `IPV6=no` conflicts with active IPv6 listeners
  - Each IPv6 listener without a matching UFW v6 rule → WARN (−1 point, capped at 3)

### Comparative report

- `compare.py` — `AuditBaseline` + `AuditDelta`:
  - Baseline saved to `~/.config/ufw-audit/last_baseline.json` after every audit (atomic write, mode 0o600)
  - On next run: score delta, alert/warn delta, new/closed ports, started/stopped services
  - `AuditDelta.is_empty()` — no output when nothing changed

### Plugin check API

- `plugin_checks.py` — `PluginCheck` protocol + `load_plugin_checks()`:
  - Plugins: Python files in `~/.config/ufw-audit/plugins/` exporting `CHECK_NAME` (str) and `run(t) -> CheckResult`
  - ANSI/control characters stripped from `CHECK_NAME`; plugin errors logged with full traceback, never crash the audit
  - Module names namespaced with file hash to prevent collisions

### Tests

- `tests/test_hardening.py` — 49 tests (new file)
- `tests/test_ipv6.py` — 33 tests (new file)
- `tests/test_compare.py` — 49 tests (new file)
- `tests/test_plugin_checks.py` — 29 tests (new file)

---

## [v1.5.0] — 2026-04-04

### TL;DR
- Enriched banner: kernel version, iptables version + backend, nftables version
- New **FIREWALL STACK ANALYSIS** section: raw iptables bypass, nftables parallel rules, unexpected ip_forward
- New **NETWORK CONTEXT** section: interface table (type/status/IP) + established TCP connections
- JSON output (`--json-full`) extended with `firewall_stack` and `network_context` objects
- Code quality pass: 12 modules hardened (XSS fix, atomic writes, input validation, CLI guards, i18n fallback…)
- 766/766 unit tests (+89)

### New sections

- **FIREWALL STACK ANALYSIS** (`checks/firewall_stack.py`) — new check after UFW Rules Analysis:
  - Raw `ACCEPT` rules in the iptables INPUT chain that do not jump to a `ufw-*` chain → WARN + 2-point deduction per rule
  - Raw `ACCEPT` rules in FORWARD chain: WARN if no Docker/WireGuard/libvirt detected; INFO if routing daemon is present
  - nftables tables running alongside UFW: flagged only when non-UFW, non-iptables-compat tables exist (`filter`, `nat`, `mangle`, `raw`, `security` are iptables-nft translations — excluded)
  - `ip_forward=1` without Docker, WireGuard, or libvirt/KVM → WARN + 1-point deduction
  - libvirt/KVM detected via `libvirtd`/`virtqemud` binary or `/var/lib/libvirt` directory

- **NETWORK CONTEXT** (`checks/network_context.py`) — new check after Firewall Stack:
  - Interface table: all non-loopback, non-veth interfaces with name, categorised type (ethernet/wifi/bridge/tunnel/other), operational state (UP/DOWN from `state` field), primary IPv4 address
  - Established TCP connections: count + top 3 external IPs (from `ss -tnp state established`)
  - Tunnel interface active (tun/tap UP) → INFO
  - Established connection to external IP on sensitive port (MySQL 3306, PostgreSQL 5432, Redis 6379, MongoDB 27017, CouchDB 5984) → WARN + 2-point deduction

### Banner enriched

- `sysinfo.py` — `get_system_info()` now collects:
  - `iptables_version`: from `iptables --version`, regex captures version + backend e.g. `"1.8.10 (nf_tables)"`
  - `nftables_version`: from `nft --version`, regex captures version e.g. `"1.0.9"`
  - Empty string returned when tool is not installed
- `report.py` — `SystemInfo` dataclass extended with `iptables_version: str` and `nftables_version: str`
- `output.py` — `print_banner()` extended: label column widened to 14 chars; `kernel`, `iptables`, `nftables` rows added; `"not installed"` shown when empty
- `locales/en.json` + `fr.json` — new keys: `banner.kernel`, `banner.iptables`, `banner.nftables`, `banner.not_installed`, `sections.firewall_stack`, `sections.network_context`, `firewall_stack.*` (7 keys), `network_context.*` (14 keys)

### JSON output

- `json_output.py` — `build_json_data()` extended (full mode):
  - `"firewall_stack"`: `input_bypasses` (list), `forward_bypasses` (list), `nftables_active` (bool), `ip_forward` (bool), `docker_present`, `wireguard_present`, `libvirt_present`
  - `"network_context"`: `interfaces` (list of `{name, type, up, address}`), `connections_count` (int), `top_remote_ips` (list of `[ip, count]`)

### Tests

- `tests/test_firewall_stack.py` — 38 tests (new file): `TestCleanSystem`, `TestInputChainBypass`, `TestForwardChain`, `TestNftables`, `TestIPForwarding`, `TestParseRawAccepts`, `TestHasUserNftRules`
- `tests/test_network_context.py` — 51 tests (new file): `TestCheckNetworkContext`, `TestTunnelInterface`, `TestSensitiveRemotePort`, `TestInterfaceType`, `TestParseInterfaces`, `TestParseConnections`, `TestSplitAddrPort`, `TestIsPrivateOrLoopback`, `TestTopRemoteIps`
- `tests/test_report.py` — `SystemInfo` fixture updated with `iptables_version="1.8.9"`, `nftables_version=""`

### Code quality pass

Twelve modules hardened with no behaviour change for clean audits. Each fix was driven by a specific failure mode or security concern:

| Module | Fixes |
|--------|-------|
| `report_markdown.py` | XSS via link URL (`_safe_url()` allows only `http://`/`https://`); timestamp coherence (`created_at` set once in `open()`, reused in header); table column normalization (row padded/truncated to header width); file extension `.log` → `.md` |
| `registry.py` | Port range 1–65535 enforced (rejects `99999/tcp`); Python keyword guard on `config_key` (`keyword.iskeyword()`); `__iter__` typed `-> Iterator[Service]`; plugin-before-init ordering documented |
| `cli.py` | `--lang=CODE` accepts any language code (`--french` kept as alias); `--quiet`+`--json` raises `CLIError`; `--json`+`--fix` raises `CLIError`; `--log-days` capped at 3650 (was only lower-bounded); unused `field` import removed; `no_color` docstring placement fixed |
| `config.py` | Atomic write via `.tmp` + `Path.replace()` in `UserConfig._save()` and `EmailStore._save()` (prevents corruption on crash); email validated with `r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$"`; `set()` rejects keys that fail `.isidentifier()` |
| `cron.py` | Email regex tightened (same pattern as `config.py`); cron line parser captures script path with `(.+)$` + `.strip()` (supports spaces in path); `_validate_custom_cron()` checks minute (0–59) and hour (0–23) for plain-integer fields |
| `fixes.py` | `manual_items` list now displayed after auto-fixes (was collected but never shown — UX bug); UFW delete regex anchored: `^(?:sudo\s+)?ufw\s+.*--force\s+delete\s+\d+$`; shell operator guard (`&&`, `\|\|`, `;`, `\|`, `>`, `<`, `` ` ``, `$(`) before `subprocess.run`; `cmd.replace("\n"," ")` before display; `done_summary` locale key added (EN + FR) |
| `i18n.py` | Per-key EN fallback: when FR locale is loaded, missing keys fall back to English instead of `[key]`; `_load_locale()` validates JSON root is `dict`; key depth guard (`_MAX_KEY_DEPTH = 10`); `_load_locale()` extracted to avoid duplication; `logger.debug` uses `_lang` (actual loaded lang) not `lang` param |
| `manage_logs.py` | `"all"` delete now requires explicit `[y/N]` confirmation; locale key `manage_logs.confirm_all` added (EN + FR) |
| `panorama.py` | `PanoramaRow TypedDict` replaces opaque `dict`; `getattr(snap, "state", None)` guard; `snap.exposures or {}` guard; `str(p)` for port values; `risk` normalized to `.lower()` |
| `completion.py` | `src.exists()` checked before `shutil.copy2` (clear error if data file missing after install); distinct messages when `SUDO_USER` absent vs binary not found in `~/.local/bin` |
| `_paths.py` | `.strip()` on `UFW_AUDIT_SHARE` env var (prevents rejected paths from leading/trailing whitespace); `resolve(strict=True)` raises early on non-existent paths |
| `pyproject.toml` | `readme = { file = "README.md", content-type = "text/markdown" }` (explicit MIME type for PyPI); Python 3.11 classifier added |

---

## [v1.4.2] — 2026-04-04

### Fixed

- **NetBIOS 137/138 warned despite UFW rule** (`checks/ports.py`) — In `_categorize_port()`, the `NETBIOS` branch was evaluated before the UFW coverage check. Any port in `(137, 138)` always returned `PortCategory.NETBIOS` regardless of whether a UFW rule existed. Moved the `_is_covered_by_ufw()` check before the NetBIOS branch so that a covered port returns `COVERED` and produces no warning or deduction.

---

## [v1.4.1] — 2026-04-04

### Fixed

- **Bash completion — `--install-completion` missing** (`ufw_audit/data/ufw-audit.bash-completion`) — The flag was not listed in `long_opts`, so pressing Tab after `--install-c` produced no suggestion. Added to the long options list.

---

## [v1.4.0] — 2026-04-04

### TL;DR
- `services.d` plugin system: drop JSON files in `~/.config/ufw-audit/services.d/` to add custom service definitions
- UFW default deny awareness: uncovered public ports downgraded to INFO when UFW default policy is `deny`/`reject`
- `__main__.py` split into 4 focused modules; now a pure orchestrator (~160 lines)
- 11-fix hardening pass across 7 modules
- 676/676 unit tests (+24)

### New features

- **`services.d` plugin system** (`registry.py`, `_paths.py`) — Users can drop JSON files into `~/.config/ufw-audit/services.d/` (or `/root/.config/ufw-audit/services.d/` when run via `sudo`) to define custom service definitions that are loaded alongside the built-in `services.json`. Each plugin file follows the same schema as a built-in service entry. If a plugin defines an `id` already present in the registry, it overrides the built-in. Invalid files (malformed JSON, missing required fields, invalid port format, path traversal attempts) are silently skipped. Future `.deb` packaging will migrate the directory to `/etc/ufw-audit/services.d/` for system-wide definitions.

- **UFW default deny awareness** (`checks/ports.py`, `locales/en.json`, `locales/fr.json`) — `check_ports()` now accepts a `default_incoming_policy` parameter (forwarded from `FirewallStatus.incoming_policy`, already parsed — zero extra subprocess calls). When the UFW default incoming policy is `deny` or `reject`, ports that have no explicit rule are already blocked at the firewall level; the finding is downgraded from ALERT/WARN to INFO with a dedicated locale message (`ports.uncovered_default_deny`). An `unknown` policy still triggers ALERT.

### Refactoring

- **`__main__.py` split into 4 modules** — The original monolith is now a pure orchestrator (~160 lines). Extracted:
  - `ufw_audit/completion.py` — `install_completion() -> int`: handles `--install-completion` (bash completion script + sudo PATH symlink)
  - `ufw_audit/runner.py` — `init_report()` + `run_checks() -> ChecksResult`: sequentially executes all 8 audit checks, owns all check imports and display calls
  - `ufw_audit/json_output.py` — `build_json_data() -> dict`: JSON serialization of audit results
- **`run_checks()` → `ChecksResult` NamedTuple** (`runner.py`) — Return type changed from opaque `tuple` to `ChecksResult(snapshots, ports_snapshot)`. `fw_status` removed from the return (was discarded at the call site).

### Bug fixes

- **`__main__.py` — `CLIError` exit code** — Was returning `1`, which is `EXIT_WARNINGS`. Changed to `EXIT_ERROR (3)` to match the constant and eliminate the ambiguity.
- **`__main__.py` — stdout not restored on exception** — The `sys.stdout` redirect to `/dev/null` (JSON mode) was only restored in the happy path. Wrapped in `try/finally` to guarantee restoration and `_devnull.close()` even when an exception propagates.
- **`firewall.py` — duplicate rule detection** — The heuristic `rule[:20] in seen` (first 20 chars) could produce false positives for rules with identical prefixes but different destinations. Replaced with a `found_duplicate` boolean and exact match.
- **`logs.py` — year-boundary syslog timestamps** — Syslog timestamps lack a year. A log entry from December parsed in January was assigned the current year, placing it in the future. Fixed: if parsed timestamp > `datetime.now()`, the year is decremented by 1.
- **`logs.py` — GeoIP2 `.mmdb` symlink exclusion** — The `is_symlink()` guard was rejecting valid `.mmdb` files on Debian/Ubuntu, where MaxMind databases are managed via `update-alternatives` and are always symlinks. Guard removed.
- **`_run.py` — centralized `_is_safe_config_path()`** — The path safety check was copy-pasted between `ddns.py` and `services.py`. Moved to `checks/_run.py` as a single authoritative implementation; both modules now import it.
- **`cron.py` — multiple fixes**:
  - `read_text()` called without `encoding=` (Python default is locale-dependent); now `encoding="utf-8"` on all occurrences
  - Range cap: `min(int(end_s), int(start_s) + 999)` prevents unbounded memory allocation while preserving downstream "out of range" validation
  - NOTIFY_EMAIL regex: now matches both single- and double-quoted email values (was matching only double-quoted)
- **`json_output.py` — UTC timestamp** — `datetime.now()` depends on the system timezone, making timestamps non-comparable across machines. Changed to `datetime.now(timezone.utc)`.
- **`completion.py` — guard for missing bash_completion.d** — On distros without `bash-completion` installed, `/etc/bash_completion.d/` may not exist. Added an explicit check with a descriptive error message before attempting the copy.
- **`completion.py` — symlink overwrite safety** — The previous code would `unlink()` any file at `/usr/local/bin/ufw-audit`, including a real binary installed by another tool. Changed to: unlink only if the path is a symlink; refuse with an error message if it is a regular file.

### Improvements

- **`json_output.py` — typed parameters** (`SystemInfo`, `list[ServiceSnapshot]`) — Previously typed as bare `sys_info` and `list`, hiding the expected structure from IDEs and static analysis tools.
- **`json_output.py` — `schema_version: "1"` field** — Consumers (SIEM, scripts, CI tools) can detect format changes without parsing the `version` string.
- **`display.py`** — Removed dead `print_info` alias (was unused after a prior refactor).
- **`manage_logs.py`** — Removed unused `home = get_user_home()` variable and its import in the `change` branch.
- **`sysinfo.py`** — `open("/etc/os-release")` now uses `encoding="utf-8", errors="replace"`.

### Tests

- **`TestFinding`** (`tests/test_scoring.py`) — 5 new tests: `note` field default value; `note` propagated via `warn()`, `alert()`, `add_finding()`; `note` absent when not provided
- **Process-aware port tests** (`tests/test_ports.py`) — 4 new tests: process name appears in finding message; process name triggers WARN (not ALERT); finding includes disclaimer note; note is empty when process unknown
- **Default deny awareness tests** (`tests/test_ports.py`) — 7 new tests: deny policy downgrades to INFO; no deduction applied; INFO message shown; reject policy also downgrades; allow policy keeps ALERT; unknown policy keeps ALERT; multiple ports all downgraded
- **Plugin isolation + loading** (`tests/test_registry.py`) — `no_plugins` fixture patches `_PLUGIN_DIR` to a non-existent path; 9 `TestPluginLoading` tests: valid plugin loaded; malformed JSON skipped; missing required field skipped; duplicate ID skipped; port format validated; path traversal rejected; plugin merged with built-in; plugin overrides built-in risk; multiple plugins loaded
- **Parametrized CLI flags** (`tests/test_cli.py`) — 5 flag pairs converted to `@pytest.mark.parametrize`: `--verbose`/`-v`, `--detailed`/`-d`, `--yes`/`-y`, `--help`/`-h`, `--offline`/`-o`

---

## [v1.3.0] — 2026-03-31

### TL;DR
- i18n completeness: all `Deduction.reason` strings translated via `t()` — zero hardcoded strings in score breakdown
- Network robustness: `--offline` mode, 3-provider IP fallback chain, IPv6 public address detection
- 652/652 unit tests (+13)

### New features

- **i18n — deduction reasons fully translated** (`checks/docker.py`, `checks/ports.py`, `checks/logs.py`, `checks/services.py`, `locales/en.json`, `locales/fr.json`) — All five `Deduction.reason` strings that were hardcoded in English are now passed through `_t()`. New `"deduction"` namespace added to both locale files with keys: `docker_bypass`, `netbios_no_rule`, `port_no_rule`, `brute_force`, `service_open_world`. Score breakdown now renders in the active language.

- **`--offline` / `-o` flag** (`cli.py`, `sysinfo.py`, `__main__.py`) — New CLI flag that skips all external HTTP calls. `get_public_ip(offline=True)` returns `""` immediately without touching the network. Useful for air-gapped machines, cron jobs in restricted environments, or when a fast audit without network latency is preferred. Wired through `AuditConfig.offline` → `detect_network_context(offline=)` → `get_public_ip(offline=)`.

- **`get_public_ip()` — 3-provider fallback chain** (`sysinfo.py`) — Previously used only `api.ipify.org`. Now tries `api.ipify.org` → `ifconfig.me/ip` → `icanhazip.com` in order, returning the first valid IPv4 response. Returns `""` if all three fail or if `offline=True`.

- **`detect_network_context()` — IPv6 public address detection** (`sysinfo.py`) — After checking IPv4 addresses from `ip addr show`, the function now scans `inet6` entries for public IPv6 addresses. Addresses matching `::1` (loopback), `fe80:` (link-local), or `fc`/`fd` prefixes (ULA) are excluded. A machine with a public `2001:db8::1` address is now correctly reported as `"public"`.

- **Bash completion updated** (`ufw_audit/data/ufw-audit.bash-completion`) — Added `--offline` to long options and `-o` to short options.

### Tests

- `tests/test_sysinfo.py` — 11 new tests: `TestGetPublicIp` (5 tests: offline guard, first-provider success, fallback to second provider, all-providers-fail, invalid-response skip) + `TestDetectNetworkContext` (6 tests: private gateway, offline forwarding, public IPv4, public IPv6, link-local IPv6 ignored, subprocess failure fallback)
- `tests/test_cli.py` — `test_offline_long`, `test_offline_short` added; `offline: False` added to defaults assertion

---

## [v1.2.1] — 2026-03-31

### Removed

- **`install.sh` definitively removed** — Deprecated since v1.0 when PyPI packaging was introduced. The canonical installation method is `pipx install ufw-audit` + `sudo ufw-audit --install-completion`. The file has been marked deprecated for two release cycles and is no longer maintained.

### Packaging

- **`pyproject.toml` — `license-files = ["LICENSE"]`** — Was explicitly set to `[]`, causing the `LICENSE` file to be excluded from the package metadata. Corrected to include the file; verified present in both sdist and wheel (`dist-info/licenses/LICENSE`).
- **`pyproject.toml` — `Python :: 3 :: Only` classifier added** — Makes it explicit that the package does not support Python 2. Consistent with `requires-python = ">=3.9"`.
- **`pyproject.toml` — `Repository` URL replaced with `Issues`** — `Homepage` and `Repository` were identical (both pointing to the GitHub repo). `Repository` replaced with the GitHub Issues URL for better PyPI metadata.

---

## [v1.2.0] — 2026-03-30

### TL;DR
- Code quality pass based on senior review: 12 defensive fixes across 8 modules
- No behaviour changes, no new features
- 639/639 unit tests

### Bug fixes

- **`i18n.current_lang()` returns requested locale instead of loaded locale** (`i18n.py`) — When a language falls back to `DEFAULT_LANG` (e.g. requesting `"de"` loads `en.json`), `_lang` was still set to `"de"`. Fixed by assigning `locale_path.stem` after loading, so `current_lang()` reflects what was actually loaded.

- **`manage_logs.py` — unguarded `unlink()` calls** (`manage_logs.py`) — All three deletion paths (single, multi, all) now wrap `f.unlink()` in `try/except OSError`, printing an error message per file instead of raising.

- **`i18n.init()` — bare `JSONDecodeError` on malformed locale** (`i18n.py`) — Malformed locale JSON raised a raw `json.JSONDecodeError`. Now caught and re-raised as `ValueError` with a clear diagnostic message.

- **`resolve_share_dir()` — unguarded `Path.resolve()`** (`_paths.py`) — `Path.resolve()` can raise `OSError` on dangling symlinks. Wrapped in `try/except OSError`; returns `None` on failure with a warning log.

- **`registry.py` — weak `config_key` and port format validation** (`registry.py`) — `VALID_CONFIG_KEYS` was defined but never enforced. `config_key` is now validated: must be one of `{"fixed", "auto", "ask"}` or a valid Python identifier. Port strings are validated against `^\d{1,5}/(tcp|udp)$`. Services with `config_key="fixed"` and an empty ports list now raise `ValueError`.

- **`report_markdown.py` — table detection breaks on indented lines** (`report_markdown.py`) — Table detection used `line.startswith("|")` which failed if the line had leading whitespace. Changed to `line.strip().startswith("|")`.

- **`report_markdown.py` — ASCII box filter causes false positives** (`report_markdown.py`) — `_audit_log_to_html()` used `any(c in line for c in "╔╗...")` which triggered on any line containing a box character (e.g. paths). Replaced with `re.match(r"^[╔╗╚╝║═┌┐└┘─┼ ]+$", line.strip())` — only matches lines composed entirely of box characters.

- **`report_markdown.py` — `send_html_email()` checks for `mail` but calls `sendmail`** (`report_markdown.py`) — `shutil.which("mail")` was used as the availability check, but the actual subprocess call uses `sendmail`. Changed to `shutil.which("sendmail")`.

- **`output.py` — panorama column overflow on long labels/ports** (`output.py`) — Label and port strings were formatted with `f"{label:<{COL_SVC}}"` without truncation. Strings longer than the column width break the table layout. Both are now truncated to `COL_SVC` / `COL_PORT` characters before formatting.

- **`scoring.py` — cap not visible in score breakdown** (`scoring.py`) — When a cap reduced the score (e.g. firewall inactive → max 3), the cap reason never appeared in the breakdown list. `finalize()` now injects a synthetic `Deduction(context="structural")` for the capped delta so the reason is visible in the score breakdown.

- **`scoring.py` — `Deduction.context` not validated** (`scoring.py`) — `context` accepted any string. Added `VALID_CONTEXTS = {"local", "public", "structural"}` and a `__post_init__` check that raises `ValueError` on invalid values.

- **`sysinfo.py` — `172.` private IP regex too broad** (`sysinfo.py`) — `re.search(r"via\s+(10\.|192\.168\.|172\.)", ...)` matched all `172.x.x.x` addresses, including public ranges (RFC 1918 only covers `172.16–31`). Centralised a single `_PRIVATE_IPV4_RE` pattern (reused from the `ip addr` branch) and applied it in both network detection paths. `kernel` and `user` strings now pass through `_sanitize()` for consistency.

### Tests

- `tests/test_i18n.py` — `test_init_unknown_lang_falls_back_to_english`: assertion updated from `current_lang() == "de"` to `current_lang() == "en"`
- `tests/test_registry.py` — `test_main_port_empty`: uses `config_key="auto"` (ports=[] now rejected for `config_key="fixed"`)

---

## [v1.1.1] — 2026-03-30

### Bug fix

- **Panorama UFW column — false ✖ for `NO_RULE` exposures** (`panorama.py`) — Services whose port has no explicit UFW rule (e.g. Avahi 5353/udp classified as `Exposure.NO_RULE`) were shown with ✖ in the panorama. This is incorrect: when UFW is active with a default deny policy (checked in the firewall section), a port with no rule is blocked by that policy and should show ✔. Removed the `has_no_rule → "none"` branch; `NO_RULE` now falls through to `"ok"` like other covered exposures.

### Tests

- `test_no_rule_shows_none` renamed to `test_no_rule_shows_ok` — assertion updated to `"ok"`

---

## [v1.1.0] — 2026-03-30

### TL;DR
- Summary box redesigned: word-wrap, inline fix commands, red disclaimer
- vsftpd `listen_port` and Transmission `rpc-port` (JSON) now detected
- Internal code quality pass across 7 modules (no behaviour changes)
- 639/639 unit tests (+5)

### New features

- **Summary box — word-wrap** (`display.py`) — Replaced `_truncate()` (hard cutoff at 48 chars) with `_wrap_for_box()`, which distributes long messages across multiple lines within the box border. No finding text is ever truncated.

- **Summary box — inline fix commands** (`display.py`) — Each finding in the "Possible improvements" and "Action required" blocks now shows its associated `→ cmd` on the line immediately below the message, when a command is available.

- **Summary box — red disclaimer** (`display.py`) — A red disclaimer line is shown after the "Possible improvements" block: *"Commands shown are suggestions — verify and adapt to your network before running"*. Applied every time the block is displayed. Locale key: `summary.block_improve_disclaimer`.

### Bug fixes

- **vsftpd `listen_port` not detected** (`checks/services.py`) — `_auto_detect_port()` regex only matched `port`, `listen`, and `Port` directives. Added `listen_port` to the alternation so `listen_port=2121` in `/etc/vsftpd.conf` is correctly picked up.

- **Transmission `rpc-port` not detected** (`checks/services.py`) — Transmission stores its configuration in JSON (`/etc/transmission-daemon/settings.json`). The generic `_auto_detect_port()` parser only handled key=value and key: value text formats. Added a JSON branch: files with a `.json` suffix are parsed with `json.loads()` and the `rpc-port` key is extracted directly.

### Internal improvements

- **`checks/_run.py`** — `_run()` gains an optional `timeout: int = _CMD_TIMEOUT` parameter, allowing per-call overrides. Debug log now includes the full `stderr` of the failed subprocess.

- **`checks/ddns.py`** — Domain validation regex replaced with an RFC-compliant pattern (`^(?!-)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}$`) that rejects leading hyphens and single-label names. `Optional[set[str]]` typing applied (4 occurrences).

- **`checks/docker.py`** — `ContainerPort.is_public` now uses `ipaddress.ip_address().is_loopback` instead of a hardcoded `("0.0.0.0", "::")` check — correctly identifies specific-interface bindings (e.g. `192.168.1.10`) as public. `_get_exposed_ports()` deduplicates by `(container_name, host_port, proto)` to avoid double-counting IPv4+IPv6 pairs. Distinct locale key `docker.no_public_ports` for the "no exposed ports" case.

- **`checks/firewall.py`** — `lines: list[str]` annotation added to all three helper functions (`_check_duplicates`, `_check_open_any`, `_check_ipv6_coverage`).

- **`checks/logs.py`** — Large log files are now read from the end (seek to `file_size - 10 MB`) to capture recent entries instead of oldest. Date cutoff changed from string comparison to `datetime` object (`ts < cutoff_dt`).

- **`checks/ports.py`** — Removed unused `_PRIVATE_ADDR` regex (dead code since `_LOOPBACK` and `_ALL_INTERFACES` were introduced).

- **`checks/services.py`** — `Optional[set[str]]` typing applied in `_build_snapshot`, `collect`, `collect_all` (4 occurrences).

### Tests

- 639/639 (+5 new): `test_vsftpd_listen_port`, `test_vsftpd_commented_listen_port_ignored`, `test_transmission_json_rpc_port`, `test_transmission_json_default_port`, `test_transmission_json_invalid_falls_back`
- `test_docker.py`: `test_not_public_private` renamed to `test_public_specific_interface` — assertion updated to `is_public is True` for `192.168.1.10` (correct behaviour after `ipaddress` fix)
- `test_logs.py`: all `_parse_log(content, "YYYY-MM-DD")` calls updated to `_parse_log(content, datetime(Y, M, D))` after signature change

---

## [v1.0.4] — 2026-03-29

### Bug fixes

- **Ephemeral ports in OVERVIEW** — `display_ports_overview()` was printing the full raw `ss` output, bypassing the ephemeral filter applied in `check_ports()`. The display layer now filters out ephemeral UDP ports (port > 32767) before computing the count and printing the table.

---

## [v1.0.3] — 2026-03-29

### Bug fixes

- **Ephemeral port output flood** — Each ephemeral UDP port generated an individual INFO finding. On active desktop systems running Samba or with many open UDP sockets, this produced hundreds of lines of noise in the ports section. Ephemeral ports are now silently discarded (`continue` with no finding). The `ports.ephemeral_ignored` locale key is no longer used.

### Tests

- `test_ephemeral_info` renamed to `test_ephemeral_silent` — asserts no INFO finding is produced and the section ends with the `all_covered` OK.

---

## [v1.0.1] — 2026-03-29

### Bug fixes

- **SSH port auto-detection** — SSH on a non-standard port was always reported as using port 22. Root cause: `config_key` was set to `"ssh_port"` in the registry but `_resolve_ports()` only triggers auto-detection for `"auto"`. Additionally, `_auto_detect_port()` regex required `=` or `:` as separator, whereas sshd_config uses a space (`Port 49732`). Both fixed: `config_key` changed to `"auto"`, regex updated to `(?:\s*[=:]\s*|\s+)`.
- **TCP LISTEN ports classified as ephemeral** — Ports above 32767 on TCP were wrongly marked as ephemeral and silently ignored. TCP sockets returned by `ss -tuln` are always in LISTEN state (server sockets) — they can never be ephemeral. The ephemeral filter now applies to UDP only.

### Tests

- 634/634 — 15 new tests: `test_ephemeral_udp`, `test_tcp_high_port_not_ephemeral`, `test_sshd_config_space_format`, `test_sshd_config_commented_port_ignored`

---

## [v1.0] — 2026-03-29

### TL;DR
- PyPI packaging — `pipx install ufw-audit` is now the recommended installation method
- New `--install-completion` flag — installs bash completion and `/usr/local/bin/` symlink for sudo PATH
- Bug fix: `services.exposure.not_listening` translation key was displayed raw in audit output
- `install.sh` deprecated in favour of pip/pipx

### New features

- **`pyproject.toml`** — Package declared with setuptools>=77. Entry point `ufw-audit = "ufw_audit.__main__:main"` registered. Data files (`data/*`, `locales/*.json`) bundled inside the package. Enables `pipx install ufw-audit` and `pip install ufw-audit`.

- **`--install-completion`** — New CLI flag. Copies the bundled bash completion script to `/etc/bash_completion.d/ufw-audit`. Creates a symlink `/usr/local/bin/ufw-audit → ~/.local/bin/ufw-audit` so that `sudo ufw-audit` works when installed via pipx (which places the binary in `~/.local/bin/`, outside sudo's restricted PATH). Uses `SUDO_USER` to resolve the real user's home directory.

- **`ufw_audit/data/ufw-audit.bash-completion`** — Bash completion script bundled inside the package so it is available after `pipx install` without requiring a git clone.

### Bug fixes

- **`locales/en.json` + `locales/fr.json` — `services.exposure.not_listening` key missing** — Ports classified as `Exposure.NOT_LISTENING` (in registry but not actively listening on the system) displayed the raw translation key `[services.exposure.not_listening]` in the audit output. Added the missing key: EN `"not actively listening — port in registry but not detected on this system"`, FR `"n'écoute pas activement — port présent dans le registre mais non détecté sur ce système"`.

### Deprecations

- **`install.sh`** — Shell installer is deprecated. The recommended installation method is `pipx install ufw-audit` followed by `sudo ufw-audit --install-completion`. The script is kept for systems without pip/pipx.

### Removed

- **`ufw-audit.bash-completion` (repo root)** — Removed duplicate. The completion script is now bundled inside the package at `ufw_audit/data/ufw-audit.bash-completion`.

### Infrastructure

- **`.github/workflows/tests.yml`** — CI now upgrades pip before installing, installs the package with `pip install -e .`, and verifies the entry point. Python 3.8 removed from the test matrix (EOL since October 2024; `setuptools>=77` requires Python 3.9+). Matrix: Python 3.9, 3.10, 3.12.

- **`pyproject.toml` — minimum Python raised to 3.9** — `setuptools>=77` (required for PEP 639 `license-files = []`) does not support Python 3.8. `requires-python` updated to `>=3.9`.

---

## [v0.22.1] — 2026-03-29

### TL;DR
- Hotfix: UFW detected as inactive on French-locale systems

### Bug fix

- **`checks/_run.py` — French locale causes false "firewall inactive"** — All subprocess calls now run with `LC_ALL=C`, `LANG=C`, and `LANGUAGE=""`. Without clearing `LANGUAGE`, gettext (used by UFW, a Python script) overrides `LC_ALL` and outputs `État : actif` instead of `Status: active`, causing the firewall to be incorrectly reported as inactive. Affected any system with `LANGUAGE` set to a non-English locale.

---

## [v0.22] — 2026-03-29

### TL;DR
- Internal quality pass: 5 modules refactored, no new features
- Box-border alignment fixed across all UI frames (wide Unicode + wrong padding formula)
- `meta: dict` removed from `CheckResult` — replaced by typed `open_ports: list[str]`
- `FirewallStatus` caches subprocess output — no duplicate `ufw status` calls
- `__main__.py` split into `_run()` + `main()` for clean error handling

### Bug fixes

- **`output.py` — box border misalignment** — All box-drawing functions (`print_section`, `print_summary_box`, `print_banner`, `fixes.py`, `cron.py`, `manage_logs.py`) had incorrect padding formulas causing the right `║` border to appear shifted. Two separate bugs: (1) padding overhead counted as 2 instead of 4/6; (2) wide Unicode characters (emoji `🏠`) counted as 1 column in `len()` but occupy 2 in the terminal. Fixed by introducing `_visual_width()` using `unicodedata.east_asian_width` and correcting all overhead constants.

### Refactors

- **`__main__.py`** — Split `_bootstrap()` into `require_root()` (raises `PermissionError`) + `_run(argv)` audit body + `main(argv)` global error guard. Version moved to `ufw_audit/__init__.py` as single source of truth. Removed duplicate `ufw status` subprocess call — reuses cached `fw_status.numbered_output` / `fw_status.ufw_output`. Score caps from `check_firewall` processed automatically by `engine.apply()`, no manual `engine.cap()` call.

- **`checks/firewall.py`** — `FirewallStatus` gains `numbered_output: str` (cached `ufw status numbered`) and `ipv6_ufw_enabled: bool` (reads `/etc/default/ufw`). `check_firewall()` uses `result.set_cap()` instead of `meta`. `check_rules()` split into three private helpers: `_check_duplicates`, `_check_open_any`, `_check_ipv6_coverage`. IPv6 warning suppressed when `IPV6=no` in `/etc/default/ufw`.

- **`checks/services.py`** — `_STATE_PRIORITY` dict replaces fragile first-match logic in `_detect_state()`. `_detect_single_unit_state()` extracted for per-unit state detection. `_build_snapshot()` classmethod deduplicates `collect()` / `collect_all()`. `NOT_LISTENING` state now emits an `INFO` finding instead of silently passing.

- **`scoring.py`** — `_Cap` renamed to `ScoreCap` (public). `CheckResult` gains `caps: List[ScoreCap]` and `set_cap()`. `meta: dict` removed — replaced by `open_ports: List[str]` (used by DDNS check). `ScoreEngine.apply()` processes embedded caps automatically.

---

## [v0.21] — 2026-03-28

### TL;DR
- Pre-v1.0 quality pass: 78 new tests + 3 bug fixes
- Suite reaches 619/619
- `virtualization.py` now fully covered (was the only untested core module)
- Two false-positive bugs fixed: CGNAT/IPv6 private ranges, commented config lines
- `--manage-cron` gains a full email address book: add, delete by number/range/all

### Bug fixes

- **`checks/services.py` — `_classify_exposure` — CGNAT and IPv6 private ranges** — Rules allowing access from CGNAT (`100.64.0.0/10`) or IPv6 private ranges (`::1`, `fe80::/10`, `fc00::/7`, `fd00::/8`) were incorrectly classified as `OPEN_WORLD` instead of `OPEN_LOCAL`, triggering false-positive score deductions. The inline `_PRIVATE` regex was replaced by a module-level `_PRIVATE_ADDR` constant covering all private/local ranges.

- **`checks/services.py` — `_auto_detect_port` — commented config lines** — Lines like `# port = 2121` in service config files were matched by the port-detection regex. The function now strips comment lines before searching, so only active directives are considered.

- **`cli.py` — `parse_args` — mutually exclusive modes** — `--manage-logs`, `--install-cron`, `--manage-cron` and `--fix` could previously be combined without error. Any combination now raises `CLIError` with a clear message.

### New feature

- **`--manage-cron` — email address book** — New `m` command in the cron management TUI opens a dedicated sub-menu to manage the `EmailStore` directly, without going through `--install-cron`:
  - Lists all saved addresses with numbers
  - `a` — add a new validated address
  - `N` — delete address number N
  - `1,3` or `1-3` — delete a comma-separated list or a range
  - `all` — delete all saved addresses

### Test suite — 619/619

New tests by area (+78):

| File | New | Coverage added |
|------|-----|---------------|
| `tests/test_virtualization.py` | 24 | Full coverage of `check_virtualization()`: empty snapshot, each hypervisor type, snap packages, interface prefix matching (virbr/vboxnet/vmnet/lxdbr/lxcbr) |
| `tests/test_email_store_mgmt.py` | 24 | `_manage_email_store()`: quit, add valid/invalid/duplicate, delete all, delete single, comma-list, range, out-of-range, garbage input |
| `tests/test_services.py` | 16 | `_classify_exposure`: CGNAT, IPv6 ULA (fc/fd), link-local (fe80), loopback (::1), public IP regression; `TestAutoDetectPort` (9 tests): all directives, commented lines, missing file, proto detection |
| `tests/test_cli.py` | 10 | `TestMutuallyExclusiveModes`: all 6 invalid pairs raise `CLIError`; 4 valid single-mode cases pass |
| `tests/test_logs.py` | 7 | `_max_in_window`: 60s boundary (included), 61s (excluded), unsorted input; `_detect_bruteforce`: exactly-threshold (not detected), threshold+1, different IPs, unsorted timestamps |

---

## [v0.20] — 2026-03-28

### TL;DR
- 17 new degraded-mode tests: behaviour when `ss`, UFW rules output, or the log file are absent
- New test file `tests/test_degraded.py` — 4 classes covering each degraded scenario + a combined class
- Suite reaches 548/548

### Test suite — 548/548

**`tests/test_degraded.py`** (new file — 17 tests)

| Class | Tests | Scenario |
|-------|-------|---------|
| `TestSSNotAvailable` | 4 | `ss` absent → empty `PortsSnapshot` → OK, zero deductions, no alert |
| `TestCheckRulesEmptyOutput` | 5 | `check_rules` called with `""`, whitespace, or status-header-only output → zero deductions |
| `TestLogFileDegraded` | 4 | `log_found=False` and empty entries → INFO/OK, zero deductions |
| `TestCombinedDegradation` | 4 | All three modules degraded simultaneously — no crash, no compounding deductions |

---

## [v0.19] — 2026-03-28

### TL;DR
- GitHub Actions CI: pytest runs automatically on every push and pull request
- Matrix: Python 3.8, 3.10, 3.12 — all three versions validated on every change

### CI

- **`.github/workflows/tests.yml`** — New workflow `Tests` triggered on push/PR for all branches. Runs `python -m pytest tests/ -v --tb=short` on `ubuntu-latest` with a 3-version Python matrix (3.8, 3.10, 3.12). No external dependencies beyond `pytest` — the project is stdlib-only.

---

## [v0.18] — 2026-03-28

### TL;DR
- 26 new unit tests for `fixes.py` — `run_fixes()` was the last untested core module
- Tests cover: item classification, UFW delete sort order, subprocess success/failure/timeout, interactive mode, auto mode (`--yes`), and auto summary
- Suite reaches 531/531

### Test suite — 531/531

**`tests/test_fixes.py`** (new file — 26 tests)

Covers `run_fixes()` in `fixes.py`:

- **Item classification** — `action + cmd` → auto item; `action + no cmd` → counted in header but skipped in loop; `improvement`/`structural`/`ok` → ignored (early `fixes.none` path)
- **UFW delete sort order** — deletes are sorted descending by rule index to prevent renumbering side effects (deleting rule 5 before rule 3)
- **Non-delete ordering** — non-delete commands run after all UFW deletes
- **No-items path** — empty engine and OK-only engines both show `fixes.none`, no subprocess/input calls
- **Subprocess success** — `returncode=0` → `fixes.applied` shown; correct command split passed to `subprocess.run`
- **Subprocess failure** — non-zero return code → `fixes.manual` shown; exit code included in output
- **Subprocess timeout / OSError** — `TimeoutExpired` and `OSError` both fall through to `fixes.manual`
- **Interactive no** — `input()` returns `"n"` → subprocess skipped, item shown as manual
- **Auto mode (`--yes`)** — `input()` never called; all auto items applied; auto mode banner shown
- **Auto summary** — applied commands listed after `--yes` run; no summary when all fail; `fixes.done` always shown

---

## [v0.17] — 2026-03-28

### TL;DR
- Full unit test suite reaches 505/505 — 15 pre-existing failures across 6 files fixed
- Two code fixes: DuckDNS domain extraction and `cron_to_human` range fallback
- No functional change to the audit itself

### Bug fixes

- **`checks/ddns.py` — `_extract_duckdns_domain`** — Returned `www.duckdns.org` when parsing a DuckDNS update URL of the form `?domains=myhost&token=...`. Fixed: `?domains=` query parameter is now parsed first and reconstructed as `myhost.duckdns.org`; the simple regex fallback is kept for content that already contains a full domain.

- **`cron.py` — `cron_to_human`** — A cron expression with a DOW range such as `0 */6 * * 1-5` was routed to the weekday path because `dow != "*"` was the only guard. Fixed: the weekday path now requires `dow` to match `[\d,]+`. Ranges, steps, and day names fall through to the custom expression fallback.

### Test suite — 505/505

- **`test_check_rules.py`** — `has_warn` used `FindingLevel.WARNING` (non-existent); corrected to `FindingLevel.WARN`.
- **`test_firewall.py`** — `TestIPv6Consistency` called `check_firewall()` but the IPv6 check lives in `check_rules()`. Rewritten to call `check_rules("", rules_text, t)`. Combined scenario `test_allow_policy_plus_no_ipv6` now calls both functions and sums deductions.
- **`test_cli.py`** — `test_yes_short` / `test_yes_long` called `parse_args(["-y"])` alone; the CLI requires `--yes` with `--fix`. Updated to `parse_args(["-y", "--fix"])`.
- **`test_docker.py`** — Four tests assumed `check_docker` emits `alert` and deducts in `local` context for an iptables bypass; the implementation emits `warn` and only deducts in `public` context. Tests updated to match actual behaviour.

---

## [v0.16] — 2026-03-28

### TL;DR
- Two panorama false-positive fixes discovered during live regression testing
- Registry ports not actively listening no longer show ✖ (`Exposure.NOT_LISTENING`)
- Loopback-only ports with no UFW rule now show ✔ (`Exposure.LOOPBACK_NO_RULE`)
- Full regression test suite completed — C6 (9 services), C8 (OPEN_LOCAL), E1 validated, zero `pending` entries

### Bug fixes

- **`checks/services.py` — `Exposure.NOT_LISTENING`** — Service ports in the registry but with no active listener (e.g. Mosquitto `8883/tcp` when TLS is not configured) were classified as `NO_RULE`, causing a false ✖ in the panorama. A new `Exposure.NOT_LISTENING` variant is set for any registry port absent from the active listener set (`ss`). Panorama treats it as `ok` (✔). No message emitted.

- **`checks/services.py` — `Exposure.LOOPBACK_NO_RULE`** — Service ports bound exclusively to loopback *without* a UFW rule (e.g. Redis `6379/tcp` default config) were classified as `NO_RULE`, also causing a false ✖. A new `Exposure.LOOPBACK_NO_RULE` variant overrides `NO_RULE` when the port is in the loopback-only set. Panorama treats it as `ok` (✔). Message: *"bound to localhost only — no UFW rule needed (covered by default deny)"*.

### Infrastructure

- **`__main__.py`** — `all_listening_ports` set computed from `loopback_only_ports | active_external_ports` and passed to `ServiceSnapshot.collect()` and `display_services_panorama()`.
- **`display.py`** — `display_services_panorama()` signature extended to accept and forward `all_listening_ports`.

### Testing

- **`TESTING.md` / `TESTING_FR.md`** — Full regression test suite completed on Linux Mint 22.3 VM. C6 extended to 9 services (VNC, FTP, PostgreSQL, Mosquitto, WireGuard, Gitea, Jellyfin, Home Assistant, Cockpit). C8 added (OPEN_LOCAL — SSH restricted to LAN). E1 validated (loopback, no UFW rule). Zero `pending` entries remaining. Avahi panorama ✖ anomaly documented (cosmetic, no score impact).

---

## [v0.15.1] — 2026-03-27

### TL;DR
- Install script is now transactional — failure mid-install triggers automatic rollback, no partial installs left on disk
- Bug fix: edge-case UFW output no longer generates an invalid fix command
- Fix UI cleaner — UFW subprocess output no longer leaks to terminal
- Installation design documented (why global install, no virtualenv)

### Install script — robustness

- **Trap + rollback on failure** — every file copied and directory created is now tracked in memory. If any step fails (`set -e`), a `trap` fires on exit and removes what was installed so far, leaving the system clean. A partial install without a manifest is no longer possible.
- **`do_copy_dir` removed** — dead helper using unfiltered `cp -r` (would have copied `__pycache__`, `.pyc`, `.git` artefacts if ever called). All copies already use explicit file lists or `*.json` globs.
- **Manifest header** — three consecutive `echo >> file` replaced by a single `{ } >> file` block (one file open instead of three).

### Bug fixes

- **`checks/firewall.py`** — open-any rule line with no `[N]` index prefix (unexpected UFW output format) generated `sudo ufw --force delete ?` as the fix command. Now falls back to `cmd=""`, making it a manual item in the fix UI instead of an invalid command.
- **`fixes.py`** — `subprocess.run()` called without `capture_output`; UFW output leaked to the terminal mid-fix UI. Added `capture_output=True`; stderr is now shown only on failure (`exit N — <stderr>`), keeping the UI clean on success.

### Housekeeping

- **`locales/en.json`, `locales/fr.json`** — `_meta.version` was still `0.13`; updated to `0.15`.

### Documentation

- **`README_TECH.md` (EN + FR)** — Added *Installation design* subsection explaining the global `/usr/local/` layout (no PyPI deps, runs as root, same convention as Ansible/Certbot), why a virtualenv is not used, Python system shebang behaviour on upgrade, and the new rollback trap.

---

## [v0.15] — 2026-03-27

### TL;DR
- Full security audit: 8 issues fixed across 3 rounds (cron permissions, path traversal, HTML injection, log bounds)
- DRY refactoring: shared `checks/_run.py` and `_paths.py` modules, duplicate code eliminated across 7 files
- Bug fix: IPv6 wildcard rules (`ufw allow from any`) now fully detected and removed by `--fix`
- 6 install script correctness fixes (missing `__init__.py`, Python version check, glob copy)

### Security hardening — full code audit

Complete security and code quality review of all modules. No high-severity vulnerabilities found. Five medium and three low-severity issues addressed.

#### Fixes

- **`fixes.py` (M1)** — `subprocess.run()` called without `timeout`; added `timeout=30` and `subprocess.TimeoutExpired` to the caught exception types. Prevents indefinite hang if a UFW command stalls.
- **`i18n.py` (M2)** — `UFW_AUDIT_SHARE` path validation used `is_symlink()` on the final component only, missing intermediate symlinks in the chain. Replaced with `Path.resolve()` which follows the full symlink chain before checking.
- **`registry.py` (M3)** — Same symlink chain vulnerability as `i18n.py`. Same fix: `Path.resolve()`.
- **`manage_logs.py` (M4)** — `prompt_path()` returned a raw user-supplied path without normalisation. Added `.resolve()` to expand and canonicalise the path, neutralising `..` traversal sequences.
- **`cron.py` (M5)** — Cron files in `/etc/cron.d/` were created with `0o644` (world-readable), exposing the notification email address to all system users. Changed to `0o640` (readable by root and group only).
- **`cron.py` (L1)** — Variables written into the generated bash script (`NOTIFY_EMAIL`, `LOG_DIR`, `PYTHONPATH` prefix, binary path) were embedded with double-quote wrapping. Replaced with `shlex.quote()` for correct shell escaping of all values.
- **`display.py` (L2)** — Magic numbers `48` and `44` (message truncation widths in the summary box) extracted to module constants `_SUMMARY_MSG_LEN` and `_SUMMARY_REASON_LEN`.
- **`report_markdown.py` (L3)** — Bare `except Exception` in the email send function replaced with specific types: `(OSError, subprocess.TimeoutExpired, ValueError)`.

#### Round 2 fixes

- **`cron.py`** — `edit_cron_schedule()` recreated cron files with `0o644` (world-readable), regressing the `0o640` permission set by `run_install_cron()`. Unified to `0o640`.
- **`__main__.py`** — Dead `if False else` branch left over from an i18n transition removed (`t("report.title")` was unreachable; the expression always evaluated to the hard-coded string).
- **`report_markdown.py`** — `_inline_format()` applied bold/code/link regex substitutions before HTML-escaping the input. System-generated content containing `<`, `>`, or `&` (process names, file paths) could produce malformed HTML in email reports. Added `html.escape()` as the first step. Also removed two stale inline `import re` statements (module-level import already present).
- **`checks/ports.py`** — `UNCOVERED_LOCAL` ports (loopback/LAN bindings without a UFW rule) had no deduplication guard. Ports bound on both `127.0.0.1` and `[::1]` — such as Postfix on `25/tcp` — were reported twice. Added `reported_local_ports` set, mirroring the existing guards for other categories.

#### Round 3 fixes

- **`cron.py`** — Two `re.sub()` calls used user-supplied strings (notification email, schedule expression + script path) directly as replacement arguments. A value containing `\1` or other backslash sequences would be interpreted as a backreference by `re.sub()`, causing `re.error` or silently wrong output. Both replacement arguments replaced with lambdas, which `re.sub()` never pattern-interpolates.
- **`report_markdown.py` (`_audit_log_to_html`)** — All dynamic content (section titles extracted from the audit log, log level, timestamp, message, key/value pairs, list items, paragraph text) was inserted into HTML without escaping. System-generated strings containing `<`, `>`, or `&` — such as hostnames, command output, or file paths — would produce malformed HTML in email reports. Applied `html.escape()` at every insertion point. Also narrowed `except Exception` → `except OSError` on the log file read.
- **`checks/firewall.py`** — Redundant `import re` inside `check_rules()` removed (`re` already imported at module level).
- **`output.py`** — Same redundant inline `import re` removed from `_strip_ansi()`.
- **`checks/logs.py`** — After extracting `DPT` from a kernel log line, `int(dpt)` was called without range validation. A malformed log entry with a value outside `1–65535` would silently create a bogus `LogEntry`. Added explicit bounds check before appending.

### Refactoring — DRY extraction

- **`checks/_run.py`** (new) — shared hub for all check modules: `_run()`, `_CMD_TIMEOUT = 10`, `_command_exists()`, `_identity_t()`. All five duplicate implementations across `firewall.py`, `services.py`, `ports.py`, `ddns.py`, `docker.py`, `virtualization.py`, `logs.py` removed.
- **`_paths.py`** (new) — `resolve_share_dir()` extracted from `i18n.py` and `registry.py`. Validates `UFW_AUDIT_SHARE` env var with full symlink-safe `Path.resolve()` before use.
- **`display.py`** — `_truncate(text, max_len)` helper extracted; five inline ternary truncations in `display.py` and `fixes.py` replaced.
- **`checks/ports.py`** — `UNCOVERED_LOCAL` ports (loopback/LAN, no UFW rule) now use a distinct locale key `ports.uncovered_local` instead of `ports.uncovered`. Prevents misleading "listening on all interfaces" messages for services bound to localhost only (e.g. Postfix on `25/tcp`).
- **`checks/logs.py`** — `_MAX_LOG_SIZE` reduced from 100 MB to 10 MB, sufficient for weeks of UFW logs. Prevents memory exhaustion from inflated log files.

### Security — config directory permissions

- **`config.py`** — `_ensure_dir()` called `mkdir(mode=0o700)` but Python's `mkdir` ignores `mode` if the directory already exists. Added explicit `chmod(0o700)` after `mkdir` so the permission is enforced on every write, not just on creation.

### Install script fixes

- **Missing `__init__.py`** — `checks/__init__.py` was listed in a comment as "handled separately" but never actually copied or added to the manifest. Fixed.
- **Python version check logic** — `major >= 3 AND minor >= 8` is wrong for Python 4+. Corrected to `(major > 3) OR (major == 3 AND minor >= 8)`.
- **Dead `LAYOUT` variable** — unused variable removed.
- **Locale copy** — two hardcoded `do_copy` lines replaced with a glob loop over `${SRC_LOCALES}/*.json`; manifest uses the same glob on installed files.
- **Doc copy** — hardcoded list replaced with root files (`README.md`, `README_FR.md`, `LICENSE`) plus a glob over `DOCUMENTS/*.md`.
- **New modules not in lists** — `_paths.py` and `checks/_run.py` added to both the copy loop and the manifest loop.

### Bug fix — IPv6 wildcard detection

- **`checks/firewall.py`** — `open_any_pattern` did not match `Anywhere (v6) ALLOW IN Anywhere (v6)` lines. `ufw allow from any` adds both an IPv4 and an IPv6 rule; only the IPv4 rule was detected and proposed for deletion. The IPv6 wildcard remained after `--fix`, leaving a real security gap. Fixed: pattern extended with `(?:\s+\(v6\))?` on both sides to cover all four variants (`bare`, `/tcp`, `/udp`, `(v6)`). Unit test `test_open_any_v6_both_detected` tightened from `>= 1` to `== 2`.

---

## [v0.14.1] — 2026-03-26

### TL;DR
- False positive fixes: loopback-bound services (Redis on 127.0.0.1) no longer raise an alert
- DDNS false positives eliminated (system ports, dangling rules)
- VERSION banner and `--remove-cron` cleanup left over from v0.14 corrected

### Bug fixes (post-release corrections)

- **False positive ALERT — loopback-bound services**: a service listening exclusively on `127.0.0.1` (e.g. Redis on `6379/tcp`) was incorrectly reported as *"exposed on internet"* when an open UFW rule existed for that port. `PortsSnapshot` is now collected before CHECK 3; ports where all `ss` bindings are loopback get `Exposure.LOOPBACK` (INFO, no deduction) instead of `OPEN_WORLD`.
- **DDNS false positives**: system ports (`53`, DHCP, mDNS) and loopback-only ports were listed as DDNS-exposed. Added `_DDNS_SYSTEM_PORTS` filter and cross-check against actual non-loopback listeners — dangling UFW rules (no active service) and bare rules (no `/proto`) no longer generate phantom entries.
- **`--remove-cron` not removed on release**: the flag was marked deprecated *"will be removed in v0.14"* but was never actually removed. Deleted from `cli.py`, `__main__.py`, `cron.py`, `locales/en.json`, `locales/fr.json`, and `ufw-audit.bash-completion`.
- **VERSION banner**: banner still displayed `v0.13.0b` after the v0.14 release. Fixed.

---

## [v0.14] — 2026-03-25

### TL;DR
- Major refactoring: `__main__.py` reduced from 1820 to 481 lines — 5 new dedicated modules extracted
- `check_rules()` moved to its natural home in `checks/firewall.py`
- Pure orchestrator with no business logic — architecture significantly cleaner

### Refactoring — `__main__.py` modularisation

`__main__.py` reduced from ~1820 to ~481 lines. All business logic and display code extracted into dedicated modules. The file is now a pure orchestrator.

#### New modules

| Module | Content |
|---|---|
| `panorama.py` | `build_panorama_rows()` — services panorama table builder |
| `sysinfo.py` | `collect_system_info()`, `detect_network_context()`, `get_user_home()` |
| `manage_logs.py` | `run_manage_logs()`, `get_or_prompt_log_dir()`, `prompt_path()` |
| `fixes.py` | `run_fixes()` — fix mode UI (interactive and auto-fix) |
| `display.py` | `display_result()`, `display_risk_context()`, `check_single_service_display()`, `display_log_results()`, `print_audit_summary()`, `build_risk_context_entries()` |

#### Moved

- `check_rules()` — moved from `__main__.py` to `ufw_audit/checks/firewall.py` (its natural home alongside `check_firewall()`)

#### Removed dead code

- `_QUIET` module-level global — replaced by explicit `quiet` parameter on `display_result()`
- `_out()` helper — defined but never called

#### Installer

- `install.sh` updated: `display.py`, `fixes.py`, `manage_logs.py`, `panorama.py`, `sysinfo.py` added to the module copy list

### Documentation

- `AUTOMATION_EN.md` renamed to `AUTOMATION.md` (English is the default language)
- `AUTOMATION.md` (French) renamed to `AUTOMATION_FR.md`
- Language toggle links added to `CHANGELOG`, `TESTING`, and `AUTOMATION` files

---

## [v0.13] — 2026-03-24

### TL;DR
- Multi-cron scheduler: multiple named audit jobs, 4-step schedule wizard, `--manage-cron` TUI
- Each cron job has its own name, file, and metadata — no more single `/etc/cron.d/ufw-audit`
- 40+ unit tests added for all cron logic

### New features — Multi-cron scheduler

- **Schedule wizard** — `--install-cron` now launches a 4-step guided wizard:
  1. **Name** — free-form label for the cron job (slug auto-generated for filenames, suggestion provided)
  2. **Schedule type** — choice of: every day / certain days of the week / certain days of the month / custom cron expression
  3. **Time** — `HH:MM` prompt (skipped for custom expressions); default `03:00`
  4. **Email** — optional notification address (unchanged from v0.12)
  - Schedule preview in natural language before confirmation (e.g. *every Monday, Wednesday, Friday at 02:30*)
  - Custom expression mode accepts any valid 5-field cron expression
- **Named cron jobs** — each job is identified by name; files are created as `/etc/cron.d/ufw-audit-{name}` and `/usr/local/bin/ufw-audit-{name}`; cron files include metadata comments (`# name:`, `# email:`) for reliable identification
- **`--manage-cron`** — new interactive management TUI (same pattern as `--manage-logs`):
  - Lists all installed cron jobs with name, schedule in natural language, and email
  - Enter a number to edit the schedule of an existing job (re-runs the schedule wizard)
  - `d:N` to delete a job and its associated script
- **`--remove-cron` updated** — now lists all installed cron jobs and requires explicit number selection before deletion; no implicit removal
- **Legacy compatibility** — cron jobs created by v0.12 (`/etc/cron.d/ufw-audit`) are detected and manageable via `--manage-cron` and `--remove-cron`

### Internals

- `ufw_audit/cron.py` added — isolated cron logic: `CronEntry` dataclass, `list_installed_crons()`, `parse_cron_file()`, `build_schedule_expr()`, `cron_to_human()` (EN/FR), `make_slug()`, `suggest_name()`
- `_run_install_cron()` refactored — wizard replaces the single time/email prompt; paths now dynamic based on slug
- `_run_manage_cron()` and `_edit_cron_schedule()` added to `__main__.py`
- `_run_remove_cron()` updated — uses `list_installed_crons()` instead of hardcoded path
- `manage_cron` flag added to `AuditConfig` / `cli.py`
- New locale keys: `install_cron.prompt_name`, `install_cron.prompt_schedule`, `install_cron.schedule_*`, `install_cron.preview`, `manage_cron.*`, `remove_cron.none_found`, `remove_cron.prompt`, `remove_cron.invalid`
- `install.sh` updated: `cron.py` and `report_markdown.py` (missing since v0.12) added to module copy list; VERSION bumped to `0.13`

### Bug fixes

- `__file__` is `None` on `ufw_audit.__init__` under Python 3.12+ when `__init__.py` is empty — `_run_install_cron()` now uses `Path(__file__)` from `__main__.py` to resolve `PYTHONPATH`, which is always set

### Testing

- `tests/test_cron.py` added — 40+ unit tests covering `build_schedule_expr()`, `cron_to_human()` (EN/FR, all schedule types), `make_slug()`, `suggest_name()`, `parse_cron_file()` (v0.13 metadata, legacy, edge cases), and internal helpers

---

## [v0.12.0] — 2026-03-24

### TL;DR
- Email reports now include an HTML version alongside plaintext — rendered nicely in all mail clients
- Zero external dependencies: markdown → HTML converter written in pure Python stdlib
- Cron nightly script updated to send MIME multipart emails automatically

### New features — Email reporting

- **Markdown report generation** — new `MarkdownReport` class produces markdown-native reports optimized for email delivery (replaces ASCII boxes with clean markdown headers)
- **Zero-dependency HTML conversion** — pure Python markdown → HTML converter (no external libraries); outputs valid, styled HTML suitable for email clients
- **MIME multipart email** — emails sent by cron script now include both plaintext (spam filter friendly) and HTML (visual rendering) versions; uses system `mail` command
- **HTML email rendering** — legacy plaintext audit reports converted to readable HTML for cron notifications; UTF-8 box borders stripped, findings styled with timestamps and colors
- **Nightly script integration** — `--install-cron` generates bash script that converts audit logs to HTML and sends multipart emails; no user-visible changes to cron UX

### Internals

- `ufw_audit/report_markdown.py` added — 750-line module with `MarkdownReport`, `markdown_to_html()`, `send_html_email()`, `send_audit_log_as_html_email()` helpers
- `_run_install_cron()` updated — nightly script now uses Python heredoc to invoke markdown email conversion
- `write_services_panorama()` added to `MarkdownReport` — ready for future integration of services table in email reports

### Testing

- Both `MarkdownReport` API and HTML conversion validated with markdown tables, headers, and plaintext audit log samples
- Bash script generation syntax verified

---

## [v0.11.4] — 2026-03-23

### TL;DR
- Open-any regex fixed: trailing spaces, `/tcp`/`/udp` variants, semantic duplicates now all detected
- Critical/high services exposed to internet now go to *Action required* — not buried in *Improvements*
- `TESTING.md` added: first formal regression test plan with live VM results

### Bug fixes — UFW rule detection

- **Open-any trailing spaces** — `ufw status numbered` pads rule lines with trailing spaces; the `$` anchor in the open-any regex never matched `Anywhere ALLOW IN Anywhere`. Fixed: `Anywhere$` → `Anywhere\s*$`
- **Open-any `/tcp` and `/udp` variants** — `Anywhere/tcp ALLOW IN Anywhere/tcp` and `Anywhere/udp ALLOW IN Anywhere/udp` (all ports, protocol-restricted) were not detected. Pattern extended: `Anywhere(?:/\w+)?` on both sides now covers all three wildcard forms
- **Semantic duplicate detection** — `PORT/proto` rules (e.g. `80/tcp`) are now flagged as redundant when a protocol-less rule for the same port (`80`) already exists with the same action and source. Two-pass detection: first pass collects all proto-less rules; second pass checks each proto-specific rule against that set
- **Comment stripping in duplicate check** — rule comparison now strips inline comments (`# label`) and normalises whitespace before comparison; `80/tcp # test2` and `80/tcp` are treated as the same rule
- **Duplicate config path display** — a stray `print()` in `_print_summary()` was displaying the config path a second time at the end of the summary, with a path reconstructed from `_get_user_home()` that differed from the actual path shown at startup. Removed

### Bug fixes — Service exposure and DDNS

- **Critical/high services → Alert not Warning** — services with `risk: critical` or `risk: high` exposed to internet (`OPEN_WORLD`) now raise `alert()` with `nature="action"`, placing them in the *Action required* block of the summary. Previously all exposed services used `warn()` regardless of risk level, burying critical findings like Redis or SSH in *Possible improvements*
- **DDNS cross-check misses protocol-less rules** — `_find_open_ports()` only matched `PORT/proto` format (e.g. `80/tcp`); bare port rules like `80 ALLOW IN Anywhere` (covering both tcp and udp) were not detected. Now adds both `PORT/tcp` and `PORT/udp` when a bare port rule is found

### Tests

- `tests/test_check_rules.py` added — covers open-any detection (trailing spaces regression, `/tcp`, `/udp` variants), duplicate detection (exact, comment-stripped, semantic TCP/UDP), IPv6 consistency, and false-positive guard for complementary `PORT/tcp` + `PORT/udp` rules
- `TESTING.md` added — manual regression test plan with live VM results for categories A (wildcards), B (duplicates), C (service exposure), D (IPv6), plus documented observations and known behaviour

---

## [v0.11.3] — 2026-03-23

### TL;DR
- `--install-cron`: schedule automated audits with email notifications
- `--manage-logs`: interactive UI to browse and delete saved reports
- Services panorama: compact table of all 22 known services after each audit
- Auto-fix mode (`-y`) now shows a warning banner and full command summary

### New features

- **Log location prompt** — first `-d` run asks where to store reports; path saved in `config.conf` and reused automatically on subsequent runs
- **`--manage-logs`** — standalone interactive UI: lists saved reports (name, size, date), deletes by index or all at once
- **`--install-cron`** — interactive cron setup: prompts for execution time and optional notification email; generates `/usr/local/bin/ufw-audit-nightly` wrapper script and `/etc/cron.d/ufw-audit`; notification sent via system `mail` only when audit detects warnings/alerts (exit code > 0)
- **Services panorama** — new section after the services audit showing all 22 known services in a compact table (SERVICE / STATUT / PORT(S) / UFW), regardless of installation status; non-installed services shown dimmed
- **ASCII art header in `.log` files** — report files now open with a 62-char box containing "UFW-AU" in Doom block art + version/host/user line, replacing the plain text header

### UX improvements

- **`-y / --yes` auditable** — auto-fix mode now shows a prominent `⚠ MODE AUTO-FIX` banner before applying fixes, and prints a summary of every applied command at the end
- **`AUTOMATION.md`** added — full documentation for cron setup, email configuration, and log management

### Internals

- `ServiceSnapshot.collect_all()` added — variant of `collect()` that includes non-installed services (used by panorama)
- `print_services_panorama()` added to `output.py`
- `_get_or_prompt_log_dir()`, `_run_manage_logs()`, `_run_install_cron()`, `_build_panorama_rows()` added to `__main__.py`
- `manage_logs` and `install_cron` flags added to `AuditConfig` / `cli.py`
- New locale keys: `log_dir`, `manage_logs`, `install_cron`, `sections.services_panorama`, `services.panorama.*`, `fixes.auto_mode_banner`, `fixes.auto_summary_title`

---

## [v0.11.2] — 2026-03-22

### TL;DR
- Banner fully redesigned: "UFW-AUDIT" in Doom block ASCII art, 80-char width
- Port exposure messages rewritten to be fully self-explanatory
- Port table now shown only in verbose mode (`-v`) — cleaner default output

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

### TL;DR
- Security patch: 20 vulnerabilities fixed (shell injection, ANSI injection, path traversal, symlink attacks, ReDoS, JSON bomb)
- No functional changes — all v0.11 features identical
- File permissions hardened: report files `0o600`, config directory `0o700`

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

### TL;DR
- Field tested on 3 distributions (Mint, Debian, Kali) — all bugs found fixed
- `--quiet` mode with exit codes (0–3) for scripting and cron automation
- Virtualisation detection: libvirt/KVM, VirtualBox, VMware, LXD, Snap network packages

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

### TL;DR
- `whois` removed — replaced by optional GeoIP2 (faster, offline, cached per session)
- Short CLI flags added (`-f`, `-y`, `-r`, `-n`) — `-h` and `-V` no longer require sudo
- Score scope disclaimer added after each summary

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

### TL;DR
- Complete rewrite from Bash to Python — 421 unit tests, zero PyPI dependencies
- 22 services detected with two-axis risk context (exposure + threat level)
- Transparent installer with manifest, `--uninstall`, `--dry-run`, bash completion
- Bilingual EN/FR interface

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