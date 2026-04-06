*[Lire en français](CHANGELOG_FULL_FR.md)* · *[TL;DR](../CHANGELOG.md)*

# UFW-audit — Changelog

All notable changes to this project are documented here.

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