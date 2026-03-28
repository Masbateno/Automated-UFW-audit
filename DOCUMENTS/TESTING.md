*[Lire en français](TESTING_FR.md)*

# UFW-audit — Test plan: dangerous UFW rules

Manual regression tests using deliberately dangerous UFW rules.
Each test verifies that ufw-audit correctly detects (and fixes) a specific misconfiguration.

---

## Unit test history

| Version | Tests | Notes |
|---------|-------|-------|
| v0.9    | 421   | First full suite |
| v0.17   | 505   | 15 pre-existing failures fixed; suite fully green |
| v0.18   | 531   | 26 new tests for `fixes.py`; `run_fixes()` fully covered |
| v0.20   | 548   | 17 degraded-mode tests; `ss`/rules/log absent scenarios |
| v0.21   | 619   | 78 new tests + 3 bug fixes + email store feature; pre-v1.0 quality pass |

### v0.21 — 619/619 (2026-03-28)

**Platform:** Linux Mint 22.3 — `so6minttest` — Python 3.12.3, pytest 7.4.4

```
pytest tests/ -v
619 passed in Xs
```

#### New tests added (+78)

| File | New | Coverage |
|------|-----|----------|
| `tests/test_virtualization.py` | 24 | `check_virtualization()`: empty snapshot, libvirt/VirtualBox/VMware/LXD, snap packages, interface prefix matching (virbr/vboxnet/vmnet/lxdbr/lxcbr) |
| `tests/test_email_store_mgmt.py` | 24 | `_manage_email_store()`: quit, add valid/invalid/duplicate, delete all, delete single, comma list, range, out-of-range, garbage input |
| `tests/test_services.py` | 16 | `_classify_exposure`: CGNAT, IPv6 ULA (fc/fd), link-local (fe80), loopback (::1), public IP regression; `TestAutoDetectPort` (9): directives, commented lines, missing file, proto |
| `tests/test_cli.py` | 10 | `TestMutuallyExclusiveModes`: 6 invalid pairs → `CLIError`; 4 valid single-mode cases |
| `tests/test_logs.py` | 7 | `_max_in_window`: 60s boundary (included), 61s (excluded), unsorted; `_detect_bruteforce`: threshold boundary, different IPs, unsorted timestamps |

#### Bug fixes

- **`checks/services.py` — `_classify_exposure`**: CGNAT (`100.64/10`) and IPv6 private ranges (`::1`, `fe80:`, `fc/fd ULA`) were classified `OPEN_WORLD` instead of `OPEN_LOCAL` (false positive deduction). Fixed with `_PRIVATE_ADDR` module constant.
- **`checks/services.py` — `_auto_detect_port`**: Commented config lines (`# port = 2121`) were matched by the port regex. Fixed by stripping comment lines before searching.
- **`cli.py` — `parse_args`**: `--manage-logs`, `--install-cron`, `--manage-cron` and `--fix` were not mutually exclusive. Any invalid combination now raises `CLIError`.

#### New feature

- **`--manage-cron` — email address book**: New `m` command opens a sub-menu to manage the `EmailStore` directly. Add a new validated address (`a`), delete by number, comma list (`1,3`), range (`1-3`), or clear all (`all`).

---

### v0.20 — 548/548 (2026-03-28)

**Platform:** Linux Mint 22.3 — `so6minttest` — Python 3.12.3, pytest 7.4.4

```
pytest tests/ -v
548 passed in Xs
```

#### New tests added

**`tests/test_degraded.py`** — 17 tests (new file)

| Class | Tests | Coverage |
|-------|-------|----------|
| `TestSSNotAvailable` | 4 | `check_ports` with empty `PortsSnapshot` (no ports, no ss_output) → OK, zero deductions |
| `TestCheckRulesEmptyOutput` | 5 | `check_rules` with `""`, whitespace, or status-header-only → zero deductions, no alert |
| `TestLogFileDegraded` | 4 | `log_found=False` → INFO + zero deductions; empty entries → OK + zero deductions |
| `TestCombinedDegradation` | 4 | All three modules degraded simultaneously — no crash, zero combined deductions |

---

### v0.18 — 531/531 (2026-03-28)

**Platform:** Linux Mint 22.3 — `so6minttest` — Python 3.12.3, pytest 7.4.4

```
pytest tests/ -v
531 passed in Xs
```

#### New tests added

**`tests/test_fixes.py`** — 26 tests (new file)

| Class | Tests | Coverage |
|-------|-------|----------|
| `TestItemClassification` | 6 | `action+cmd` → auto; `action` no cmd → counted but not looped; `improvement`/`structural`/`ok` → ignored |
| `TestDeleteSortOrder` | 2 | Descending delete index order; non-delete after deletes |
| `TestNoItems` | 2 | Empty engine and OK-only engine → `fixes.none`; no subprocess/input |
| `TestSubprocessSuccess` | 2 | `returncode=0` → `fixes.applied`; correct command split |
| `TestSubprocessFailure` | 2 | Non-zero return → `fixes.manual`; exit code in output |
| `TestSubprocessTimeout` | 2 | `TimeoutExpired` → `fixes.manual`; `OSError` → `fixes.manual` |
| `TestInteractiveNo` | 2 | `input()="n"` → subprocess skipped; item shown as manual |
| `TestAutoMode` | 3 | `config.yes=True` → no `input()`; all items applied; auto banner shown |
| `TestAutoSummary` | 3 | Summary after `--yes` run; no summary on failure; applied commands listed |
| `TestDoneMessage` | 1 | `fixes.done` shown at end (not shown on early exit) |

---

### v0.17 — 505/505 (2026-03-28)

**Platform:** Linux Mint 22.3 — `so6minttest` — Python 3.12.3, pytest 7.4.4

```
pytest tests/ -v
505 passed in Xs
```

#### New tests added (v0.16 work, included in v0.17 count)

**`tests/test_services.py`** — 52 tests (previously 34)
- `TestPortExposureFindings` — 5 new tests:
  - `test_loopback_no_rule_adds_info` — `Exposure.LOOPBACK_NO_RULE` emits INFO finding
  - `test_loopback_no_rule_no_deduction` — no score deduction
  - `test_not_listening_no_finding` — `Exposure.NOT_LISTENING` emits no finding
  - `test_not_listening_no_deduction` — no deduction
  - `test_mixed_listening_and_not_listening` — only the listening port generates a finding
- `TestExposureOverrides` — 5 new tests verifying the override logic in `ServiceSnapshot.collect()` directly
- `TestPanoramaNewVariants` — 6 new tests verifying `build_panorama_rows()` UFW indicator for all exposure variants (LOOPBACK, LOOPBACK_NO_RULE, NOT_LISTENING → `ok`; NO_RULE → `none`; OPEN_WORLD → `warn`)

#### Pre-existing failures fixed (15 total)

| File | Count | Root cause |
|------|-------|------------|
| `test_check_rules.py` | 2 | `FindingLevel.WARNING` → `FindingLevel.WARN` (typo) |
| `test_firewall.py` | 4+1 | `TestIPv6Consistency` called `check_firewall()` — IPv6 check is in `check_rules()`; combined scenario fixed to call both |
| `test_cli.py` | 2 | `parse_args(["-y"])` raises CLIError — `--yes` requires `--fix` |
| `test_docker.py` | 4 | `check_docker` emits `warn` not `alert` for iptables bypass; deduction only in `public` context |
| `test_ddns.py` | 1 | `_extract_duckdns_domain` matched `www.duckdns.org` instead of parsing `?domains=myhost` |
| `test_cron.py` | 2 | `cron_to_human("0 */6 * * 1-5")` took DOW path — `dow != "*"` guard insufficient for ranges |

#### Code fixes (behaviour, not test-only)

- **`checks/ddns.py` — `_extract_duckdns_domain`**: now parses `?domains=` query parameter first, reconstructs `myhost.duckdns.org`; falls back to direct regex for pre-formed domains.
- **`cron.py` — `cron_to_human`**: DOW path now guards `re.fullmatch(r"[\d,]+", dow)` — ranges like `1-5`, steps like `*/2`, and day names fall through to the custom expression fallback.

---

**Test VM:** Linux Mint 22.3 — `so6minttest`
**Reference state** (clean baseline after each test):

```bash
sudo ufw --force reset
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp
sudo ufw allow 80
sudo ufw enable
```

---

## Category A — Open-any wildcards

Rules that open all ports to all sources — highest severity.

### A1 — Full wildcard `Anywhere ALLOW IN Anywhere`

```bash
sudo ufw allow from any
```

| Expected | Result |
|----------|--------|
| `✖ [ALERT]` Rule allowing all incoming connections without port restriction | ✔ v0.11.4 |
| `-2` score deduction | ✔ |
| Fix proposed: `sudo ufw --force delete N` | ✔ |
| Fix applied correctly | ✔ v0.15 |
| **IPv6 rule also detected and fixed** (`Anywhere (v6) ALLOW IN Anywhere (v6)`) | ✔ v0.15 |

**Root cause fixed (v0.11.4):** `ufw status numbered` pads lines with trailing spaces — the `$` anchor in the regex never matched. Fixed: `Anywhere$` → `Anywhere\s*$`. (commit `8ccd9b6`)

**Root cause fixed (v0.15):** IPv6 wildcard rules (`Anywhere (v6) ALLOW IN Anywhere (v6)`) escaped detection — `open_any_pattern` did not account for the `(v6)` suffix. Fixed: pattern extended with `(?:\s+\(v6\))?` on both sides. Both IPv4 and IPv6 rules are now flagged and fixed independently.

---

### A2 — TCP wildcard `Anywhere/tcp ALLOW IN Anywhere/tcp`

```bash
sudo ufw allow proto tcp from any to any
```

| Expected | Result |
|----------|--------|
| `✖ [ALERT]` Rule allowing all incoming connections without port restriction | ✔ v0.15 |
| `-2` score deduction | ✔ v0.15 |
| Fix applied correctly | ✔ v0.15 |
| **IPv6 variant also detected** (`Anywhere/tcp (v6) ALLOW IN Anywhere/tcp (v6)`) | ✔ v0.15 |

**Root cause fixed (v0.11.4):** Pattern extended to `Anywhere(?:/\w+)?` on both sides to cover `/tcp`, `/udp` variants. (commit `1dd9ede`)

**v0.15:** Same IPv6 fix as A1 applies here.

---

### A3 — UDP wildcard `Anywhere/udp ALLOW IN Anywhere/udp`

```bash
sudo ufw allow proto udp from any to any
```

| Expected | Result |
|----------|--------|
| `✖ [ALERT]` Rule allowing all incoming connections without port restriction | ✔ v0.15 |
| `-2` score deduction | ✔ v0.15 |
| Fix applied correctly | ✔ v0.15 |
| **IPv6 variant also detected** | ✔ v0.15 |

---

### A4 — All three wildcards simultaneously

```bash
sudo ufw allow from any
sudo ufw allow proto tcp from any to any
sudo ufw allow proto udp from any to any
```

| Expected | Result |
|----------|--------|
| 3 distinct `✖ [ALERT]` findings (IPv4 only, IPV6=no) | ✔ v0.15 |
| 6 distinct `✖ [ALERT]` findings (IPv4 + IPv6, IPV6=yes) | ✔ v0.15 |
| Score: 1/10 (IPV6=no), Risk level: CRITICAL | ✔ v0.15 |
| 6 fixes proposed and applied in reverse index order (avoids renumbering) | ✔ v0.15 |

---

### A5 — False positive: source-restricted rule

```bash
sudo ufw allow from 192.168.1.0/24
```

| Expected | Result |
|----------|--------|
| `✔ [OK]` No 'allow from any' rule without port restriction detected | ✔ v0.15 |
| Source-restricted rule is NOT flagged as open-any | ✔ |

> `ufw status numbered` shows `Anywhere ALLOW IN 192.168.1.0/24` — destination is `Anywhere` but source is restricted. Pattern correctly requires BOTH sides to be `Anywhere` to flag.

---

## Category B — Duplicate rules

### B1 — Exact duplicate

```bash
sudo ufw allow 80/tcp
sudo ufw allow 80/tcp   # UFW says: "Skipping adding existing rule"
```

| Expected | Result |
|----------|--------|
| UFW natively prevents true exact duplicates | ✔ confirmed |
| Not testable via CLI — would require direct file manipulation | noted |

> **Note:** Exact duplicates can only arise from direct `/etc/ufw/` file editing or external tools (Ansible, scripts). UFW's CLI prevents them.

---

### B2 — Same rule, different comments

```bash
sudo ufw allow 80/tcp comment "test2"
# 80 (no proto) already present in baseline
```

| Expected | Result |
|----------|--------|
| `✖ [ALERT]` Duplicate UFW rule detected: `80/tcp ALLOW IN Anywhere` | ✔ v0.15 |
| Comment stripped before comparison — `# test2` ignored | ✔ v0.15 |
| Redundant `80/tcp` deleted, `80` kept | ✔ v0.15 |

**Root cause fixed:** Comparison now uses comment-stripped, whitespace-normalized text. (commit `b7a285a`)

---

### B3 — Semantic duplicate: `PORT/proto` redundant when `PORT` exists

```bash
sudo ufw allow 80/tcp comment "test2"
# 80 (no proto) already present → 80/tcp is redundant
```

| Expected | Result |
|----------|--------|
| `✖ [ALERT]` Duplicate UFW rule detected: `80/tcp ALLOW IN Anywhere` | ✔ v0.15 |
| `-1` score deduction | ✔ v0.15 |
| Fix deletes the protocol-specific rule, keeps the broader one | ✔ v0.15 |

**Root cause fixed:** Two-pass detection — first pass collects all protocol-less rules, second pass checks if `PORT/proto` is a subset of an existing `PORT` rule. (commit `b7a285a`)

---

### B4 — Semantic duplicate: UDP variant

```bash
sudo ufw allow 53/udp
sudo ufw allow 53
```

| Expected | Result |
|----------|--------|
| `✖ [ALERT]` `53/udp` detected as redundant | ✔ unit test |

> Validated via unit test only (DNS port — not in services registry, no practical risk on the VM).

---

### B5 — No false positive: `PORT/tcp` + `PORT/udp` without `PORT`

```bash
sudo ufw allow 80/tcp
sudo ufw allow 80/udp
# No bare "80" rule
```

| Expected | Result |
|----------|--------|
| `✔ [OK]` No duplicate UFW rules detected | ✔ v0.15 |
| `80/tcp` and `80/udp` are complementary — not flagged | ✔ v0.15 |

> Also note: when baseline has `80` (bare), adding `80/tcp` + `80/udp` correctly flags BOTH as semantic duplicates of `80`. Verified live.

---

## Category C — Critical services exposed

### C1 — SSH exposed (baseline state)

SSH is always present in the reference state (`ufw allow 22/tcp`). This scenario documents the expected behaviour for a critical service with an unrestricted UFW ALLOW rule.

```bash
# Baseline state — SSH already exposed
sudo ufw-audit
```

| Expected | Result |
|----------|--------|
| `✖ [ALERT]` Port 22/tcp — open to internet — no source restriction in UFW | ✔ v0.15.1 |
| Risk context CRITICAL displayed | ✔ v0.15.1 |
| `-2` score deduction (NAT/local context) | ✔ v0.15.1 |
| Panorama: SSH `⚠` (OPEN_WORLD) | ✔ v0.15.1 |
| DDNS `→ 22/tcp` | ✔ v0.15.1 |
| **Remediation:** source-restrict → switches to OPEN_LOCAL (WARN not ALERT, no deduction) | ✔ v0.15.1 |

> **Note:** `openssh-server` must be installed and active (`sudo apt install openssh-server && sudo systemctl enable --now ssh`). If inactive/disabled, the service is INFO-only with no port exposure check.

---

### C3 — Redis exposed on all interfaces (service installed and active)

```bash
sudo ufw allow 6379
# Redis configured to bind 0.0.0.0 (not the default)
```

| Expected | Result |
|----------|--------|
| `✖ [ALERT]` Port 6379/tcp — open to internet (Action required) | ✔ v0.15 |
| Risk context CRITICAL displayed | ✔ v0.15 |
| `-2` score deduction (NAT context) | ✔ v0.15 |
| Panorama: Redis `⚠` | ✔ v0.15 |
| DDNS cross-check: `→ 6379/tcp` | ✔ v0.15 (`6379/udp` filtered — no UDP listener) |

**Root cause fixed (obs 1):** CRITICAL/HIGH services with `OPEN_WORLD` exposure now raise `alert()` instead of `warn()`, moving them to "Action required". (commit `e01b24b`)

---

### C3b — Redis loopback only — false positive fix (v0.14.1)

Default Redis configuration: binds to `127.0.0.1` only, but a permissive UFW rule exists.

```bash
sudo ufw allow 6379
# Redis default: bind 127.0.0.1 (loopback only)
```

| Expected | Result |
|----------|--------|
| `ℹ [INFO]` Port 6379/tcp — bound to localhost only — UFW rule has no effect on external access | ✔ v0.15 |
| No ALERT, no score deduction | ✔ v0.15 |
| Panorama: Redis `✔` (rule exists, exposure = LOOPBACK) | ✔ v0.15 |
| DDNS: `6379/tcp` NOT in exposed ports (loopback only) | ✔ v0.15 |
| DDNS: `6379/udp` NOT in exposed ports (no UDP listener) | ✔ v0.15 |

**Root cause fixed (v0.14.1):** `_classify_exposure()` was UFW-only and did not cross-check actual socket bindings. Fix: `PortsSnapshot` is now collected before CHECK 3; ports where all `ss` bindings are loopback get `Exposure.LOOPBACK` (INFO, no deduction). `_find_open_ports()` in `ddns.py` now also receives the `loopback_ports` and `active_ports` sets. (commits `2bfc85b`, `64311be`)

---

### C2 — MySQL exposed (service not installed)

```bash
sudo ufw allow 3306
```

| Expected | Result |
|----------|--------|
| No service alert (MySQL not installed) | ✔ v0.15 |
| Port 3306 open in UFW but unmatched to any installed service | ✔ v0.15 |
| DDNS: `3306/tcp` and `3306/udp` NOT in exposed ports (no active listener) | ✔ v0.15 |

> **Behaviour updated (v0.14.1):** `_find_open_ports()` now cross-checks against actual non-loopback listeners (`active_ports` set from `ss`). Orphan UFW rules (port open, no service running) are excluded from the DDNS exposed ports list. `3306/tcp` and `3306/udp` no longer appear in DDNS findings when MySQL is not installed.

---

### C4 — Nginx exposed (medium-risk service, installed and active)

```bash
sudo apt install nginx
sudo ufw allow 80
sudo ufw-audit
```

| Expected | Result |
|----------|--------|
| `⚠ [WARNING]` Port 80/tcp — open to internet — no source restriction in UFW | ✔ v0.15.1 |
| Risk context MEDIUM displayed | ✔ v0.15.1 |
| `-1` score deduction | ✔ v0.15.1 |
| Panorama: Nginx `⚠` | ✔ v0.15.1 |
| Finding appears in *Possible improvements* (not *Action required*) | ✔ v0.15.1 |

> Medium-risk services (`warn()` not `alert()`) — distinction from critical services like SSH or Redis.

---

### C5 — Samba exposed (critical service, installed and active)

```bash
sudo apt install samba
sudo ufw allow 445
sudo ufw allow 139
sudo ufw-audit
```

| Expected | Result |
|----------|--------|
| `✖ [ALERT]` Port 445/tcp — open to internet — no source restriction in UFW | ✔ v0.15.1 |
| `✖ [ALERT]` Port 139/tcp — open to internet | ✔ v0.15.1 |
| Risk context CRITICAL displayed (ransomware vector, EternalBlue) | ✔ v0.15.1 |
| `-2` deduction × 2 ports (−4 total) | ✔ v0.15.1 |
| Panorama: Samba `⚠` (OPEN_WORLD) | ✔ v0.15.1 |
| Both ports in *Action required* block | ✔ v0.15.1 |
| DDNS `→ 445/tcp`, `→ 139/tcp` | ✔ v0.15.1 |

> **Cleanup:** `sudo apt remove --purge samba && sudo ufw delete allow 445 && sudo ufw delete allow 139`

---

### C6 — Ports open in UFW, services not installed (multiple services)

For each entry below: open the port in UFW with no matching service installed. Expected behaviour: **no service-level alert**, port may appear as an unmatched open rule.

```bash
sudo ufw allow <PORT>
sudo ufw-audit
```

| Service | Port | Expected behaviour | Result |
|---------|------|--------------------|--------|
| VNC Server | 5900/tcp | No service alert — VNC not detected | ✔ v0.15.1 |
| FTP Server | 21/tcp | No service alert — FTP not detected | ✔ v0.15.1 |
| PostgreSQL | 5432/tcp | No service alert — PostgreSQL not detected | ✔ v0.15.1 |
| Mosquitto (MQTT) | 1883/tcp | `ℹ [INFO]` 1883/tcp loopback — UFW rule has no effect; 8883/tcp not listening — no message; Panorama ✔ | ✔ v0.15.1 ² |
| WireGuard | 51820/udp | `ℹ [INFO]` WireGuard installed but stopped/disabled — no port exposure check (INACTIVE early return) | ✔ v0.15.1 ¹ |
| Gitea | 3000/tcp | No service alert — Gitea not detected | ✔ v0.15.1 |
| Jellyfin | 8096/tcp | No service alert — Jellyfin not detected | ✔ v0.15.1 |
| Home Assistant | 8123/tcp | No service alert — HASS not detected | ✔ v0.15.1 |
| Cockpit | 9090/tcp | No service alert — Cockpit not detected | ✔ v0.15.1 |

> For all above: the port should appear in **UFW RULES ANALYSIS** if an active listener exists, but since the service is not installed there is no listener — no ALERT in NETWORK SERVICES ANALYSIS.
> DDNS cross-check: none of these ports should appear in DDNS exposed list (no active listener — v0.14.1 fix).

> ¹ WireGuard was already installed (but inactive) on the test VM. The "not installed" path for WireGuard remains untested — behaviour confirmed: INACTIVE service with an open UFW rule → INFO only, no ALERT, no score deduction.

> ² Mosquitto was installed and ACTIVE on the test VM (not matching the "not installed" C6 scenario). Test revealed a bug: registry ports not actively listening (8883/tcp) incorrectly triggered `Exposure.NO_RULE` → panorama ✖. Fixed in beta (commit `67743ca`): `Exposure.NOT_LISTENING` for non-listening registry ports → panorama ✔.

> **Already validated:** MySQL / MariaDB (3306) → C2

---

### C7 — CUPS exposed (low-risk service, usually pre-installed on desktop Linux)

CUPS (print server) listens on `127.0.0.1:631` by default. This test verifies behaviour when CUPS is active and a UFW rule exists.

```bash
# CUPS is often pre-installed on Linux Mint
sudo ufw allow 631
sudo ufw-audit
```

| Expected | Result |
|----------|--------|
| `ℹ [INFO]` Port 631/tcp — bound to localhost only — UFW rule has no effect | ✔ v0.15.1 |
| No ALERT, no score deduction (loopback binding) | ✔ v0.15.1 |
| Panorama: CUPS `✔` (rule exists, loopback → INFO) | ✔ v0.15.1 |

> If CUPS binds to `0.0.0.0`: `⚠ [WARNING]` Port 631/tcp — open to internet (low risk, nature=improvement).

---

## Category D — IPv6 consistency

### D1 — IPv4 rules present, no IPv6 equivalent (warning expected)

```bash
# From baseline: 22/tcp and 80 are present, no (v6) rules
sudo ufw status numbered
```

> **Note:** Some distributions (or VMs with `IPV6=no` in `/etc/default/ufw`) do not add IPv6 rules. If all rules are already paired (IPv4 + IPv6), use `sudo ufw --force reset` and re-add only IPv4 rules:

```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp   # Do NOT let UFW create (v6) rules — requires IPV6=no
sudo ufw enable
```

| Expected | Result |
|----------|--------|
| `⚠ [WARNING]` IPv6 rules missing — only IPv4 rules present | ✔ v0.15 live (IPV6=no VM) |
| `-1` score deduction | ✔ v0.15 live |
| Live test | ✔ v0.15 |

---

### D2 — IPv4 and IPv6 rules both present (no warning)

```bash
# Baseline with IPV6=yes (default): 22/tcp and 22/tcp (v6) both present
sudo ufw-audit
```

| Expected | Result |
|----------|--------|
| `✔ [OK]` IPv4 and IPv6 rules both present | ✔ v0.15 live (IPV6=yes, A1 test) |
| No deduction | ✔ v0.15 live |
| Live test | ✔ v0.15 |

---

## Category E — Loopback-only ports (v0.15)

### C8 — SSH restricted to LAN (OPEN_LOCAL path)

```bash
sudo ufw delete allow 22/tcp
sudo ufw allow from 192.168.1.0/24 to any port 22 proto tcp
sudo ufw-audit
```

| Expected | Result |
|----------|--------|
| `⚠ [WARNING]` Port 22/tcp — restricted to local network by UFW rule | ✔ v0.16 |
| No score deduction (OPEN_LOCAL ≠ OPEN_WORLD) | ✔ v0.16 |
| Panorama: SSH `✔` (LAN restriction = correct config) | ✔ v0.16 |
| DDNS: `ℹ` Port 22/tcp restricted to local network (not ALERT) | ✔ v0.16 |
| Risk context CRITICAL still displayed | ✔ v0.16 |

> **Cleanup:** `sudo ufw delete allow from 192.168.1.0/24 to any port 22 proto tcp && sudo ufw allow 22/tcp`

---



### E1 — Port listening on localhost only, no UFW rule — INFO not ALERT

```bash
# Any process bound exclusively to 127.0.0.1 without a UFW rule
# Example: netcat listening on loopback (or rely on Redis default config)
# Redis default: bind 127.0.0.1 — no UFW rule needed
sudo ufw-audit
```

| Expected | Result |
|----------|--------|
| `ℹ [INFO]` Port 6379/tcp — bound to localhost only — no UFW rule needed (covered by default deny) | ✔ v0.15.1 |
| No ALERT, no score deduction | ✔ v0.15.1 |
| Redis panorama ✔ | ✔ v0.15.1 |
| Message uses `services.exposure.loopback_no_rule` locale key (added with `Exposure.LOOPBACK_NO_RULE` fix) | ✔ v0.15.1 |

> **Note:** The original expected message referenced `ports.uncovered_local`. In practice, Redis on loopback with no UFW rule is handled by the services check path (`Exposure.LOOPBACK_NO_RULE`), not the ports check. The `ports.uncovered_local` key (`"Port {port} — bound to localhost only — no external exposure"`) applies to the ports section for processes not covered by the service registry.

---

## Additional observations

### Obs — Avahi panorama shows ✖ despite INFO message (known issue, v0.16)

Avahi binds on `0.0.0.0:5353/udp` (mDNS multicast). No UFW rule exists for 5353 → `Exposure.NO_RULE` → panorama ✖. The service check correctly emits `ℹ [INFO]` "covered by default deny policy", but the panorama symbol is set by the `NO_RULE` enum value regardless of the INFO severity.

**Root cause:** `NO_RULE` on a non-loopback, non-listening-externally port (multicast/LAN-only in practice) is treated identically to `NO_RULE` on a genuinely exposed port. A future fix could introduce `Exposure.NO_RULE_MULTICAST` or a broader mechanism to distinguish locally-scoped `NO_RULE` from truly exposed `NO_RULE`.

**Impact:** cosmetic only — no false ALERT, no score deduction.

---



### Obs — DDNS does not detect protocol-less rules (fixed)

With `80 ALLOW IN Anywhere` (no `/tcp`), the DDNS cross-check previously showed nothing for port 80.

**Root cause fixed:** `_find_open_ports()` now handles bare port rules — adds both `PORT/tcp` and `PORT/udp` to the open ports list. (commit `e01b24b`)

**Validated (v0.14.1 update):** Bare rule `80 ALLOW` with Nginx listening on `0.0.0.0:80` → DDNS correctly lists `→ 80/tcp` only (`80/udp` filtered — no UDP listener on port 80).

---

### Obs — DDNS false positives: system ports and orphan rules (v0.14.1)

```bash
sudo ufw allow 53
sudo ufw allow 3306
sudo ufw allow 6379
# Redis on 127.0.0.1 only, MySQL not installed
```

| Expected | Result |
|----------|--------|
| DDNS: `53/tcp`, `53/udp` NOT listed (system port filter) | ✔ v0.14.1 |
| DDNS: `3306/tcp`, `3306/udp` NOT listed (no active listener) | ✔ v0.14.1 |
| DDNS: `6379/tcp`, `6379/udp` NOT listed (loopback only / no UDP listener) | ✔ v0.14.1 |

**Root cause fixed (v0.14.1):** Added `_DDNS_SYSTEM_PORTS` constant (53, 67, 68, 546, 547, 5353) and `active_ports` cross-check in `_find_open_ports()`. Only ports with an actual non-loopback listener in `ss` output are included in the DDNS exposed list. (commit `64311be`)

---

### Obs — UFW allows wildcard rules after specific rules without error

```
Anywhere/tcp    ALLOW IN    Anywhere/tcp
22/tcp          ALLOW IN    Anywhere
```

UFW does not warn that `Anywhere/tcp` makes `22/tcp` redundant. ufw-audit correctly flags the wildcard.

---

## B1 note — exact duplicates via file manipulation

To test exact duplicates that UFW's CLI prevents, rules can be injected directly:

```bash
sudo cp /etc/ufw/user.rules /etc/ufw/user.rules.bak
# Manually duplicate a rule line in user.rules
sudo ufw reload
sudo ufw-audit
# Cleanup:
sudo cp /etc/ufw/user.rules.bak /etc/ufw/user.rules
sudo ufw reload
```

Not yet tested — low practical priority since UFW CLI prevents this.
