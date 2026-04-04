*[Lire en français](CHANGELOG_FR.md)* · *[Full changelog](DOCUMENTS/CHANGELOG_FULL.md)*

# ufw-audit — Changelog

| Version | Date | Summary |
|---------|------|---------|
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
