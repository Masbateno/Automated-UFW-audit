*[Lire en français](TESTING_FR.md)*

# UFW-audit — Test plan: dangerous UFW rules

Manual regression tests using deliberately dangerous UFW rules.
Each test verifies that ufw-audit correctly detects (and fixes) a specific misconfiguration.

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
| `✖ [ALERT]` Port 22/tcp — open to internet — no source restriction in UFW | pending |
| Risk context CRITICAL displayed | pending |
| `-2` score deduction (NAT/local context) | pending |
| Panorama: SSH `✖` | pending |

> **Remediation to test:** `sudo ufw delete allow 22/tcp && sudo ufw allow from 192.168.1.0/24 to any port 22 proto tcp` → switches to OPEN_LOCAL (WARN not ALERT, no deduction).

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
| `⚠ [WARNING]` Port 80/tcp — open to internet — no source restriction in UFW | pending |
| Risk context MEDIUM displayed | pending |
| `-1` score deduction | pending |
| Panorama: Nginx `⚠` | pending |
| Finding appears in *Possible improvements* (not *Action required*) | pending |

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
| `✖ [ALERT]` Port 445/tcp — open to internet — no source restriction in UFW | pending |
| `✖ [ALERT]` Port 139/tcp — open to internet | pending |
| Risk context CRITICAL displayed (ransomware vector, EternalBlue) | pending |
| Score deduction × 2 (both ports) | pending |
| Panorama: Samba `✖` | pending |
| Both ports in *Action required* block | pending |

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
| VNC Server | 5900/tcp | No service alert — VNC not detected | pending |
| FTP Server | 21/tcp | No service alert — FTP not detected | pending |
| PostgreSQL | 5432/tcp | No service alert — PostgreSQL not detected | pending |
| Mosquitto (MQTT) | 1883/tcp | No service alert — Mosquitto not detected | pending |
| WireGuard | 51820/udp | No service alert — WireGuard not detected | pending |
| Gitea | 3000/tcp | No service alert — Gitea not detected | pending |
| Jellyfin | 8096/tcp | No service alert — Jellyfin not detected | pending |
| Home Assistant | 8123/tcp | No service alert — HASS not detected | pending |
| Cockpit | 9090/tcp | No service alert — Cockpit not detected | pending |

> For all above: the port should appear in **UFW RULES ANALYSIS** if an active listener exists, but since the service is not installed there is no listener — no ALERT in NETWORK SERVICES ANALYSIS.
> DDNS cross-check: none of these ports should appear in DDNS exposed list (no active listener — v0.14.1 fix).

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
| `ℹ [INFO]` Port 631/tcp — bound to localhost only — UFW rule has no effect | pending |
| No ALERT, no score deduction (loopback binding) | pending |
| Panorama: CUPS `✔` (rule exists, loopback → INFO) | pending |

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

### E1 — Port listening on localhost only, no UFW rule — INFO not ALERT

```bash
# Any process bound exclusively to 127.0.0.1 without a UFW rule
# Example: netcat listening on loopback (or rely on Redis default config)
# Redis default: bind 127.0.0.1 — no UFW rule needed
sudo ufw-audit
```

| Expected | Result |
|----------|--------|
| `ℹ [INFO]` Port X — bound to localhost only — no external exposure | pending |
| No ALERT, no score deduction | pending |
| Message uses `ports.uncovered_local` locale key (new in v0.15) | pending |

> **New in v0.15:** Ports in `PortCategory.UNCOVERED_LOCAL` now use a distinct locale key `ports.uncovered_local` instead of `ports.uncovered` (which implies all-interfaces exposure). This prevents misleading "listening on all interfaces" messages for loopback-only services.

---

## Additional observations

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
