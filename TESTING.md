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
| Fix applied correctly | ✔ |

**Root cause fixed:** `ufw status numbered` pads lines with trailing spaces — the `$` anchor in the regex never matched. Fixed: `Anywhere$` → `Anywhere\s*$`. (commit `8ccd9b6`)

---

### A2 — TCP wildcard `Anywhere/tcp ALLOW IN Anywhere/tcp`

```bash
sudo ufw allow proto tcp from any to any
```

| Expected | Result |
|----------|--------|
| `✖ [ALERT]` Rule allowing all incoming connections without port restriction | ✔ v0.11.4 |
| `-2` score deduction | ✔ |
| Fix applied correctly | ✔ |

**Root cause fixed:** Pattern extended to `Anywhere(?:/\w+)?` on both sides to cover `/tcp`, `/udp` variants. (commit `1dd9ede`)

---

### A3 — UDP wildcard `Anywhere/udp ALLOW IN Anywhere/udp`

```bash
sudo ufw allow proto udp from any to any
```

| Expected | Result |
|----------|--------|
| `✖ [ALERT]` Rule allowing all incoming connections without port restriction | ✔ v0.11.4 |
| `-2` score deduction | ✔ |
| Fix applied correctly | ✔ |

---

### A4 — All three wildcards simultaneously

```bash
sudo ufw allow from any
sudo ufw allow proto tcp from any to any
sudo ufw allow proto udp from any to any
```

| Expected | Result |
|----------|--------|
| 3 distinct `✖ [ALERT]` findings | ✔ v0.11.4 |
| Score: 1/10, Risk level: CRITICAL | ✔ |
| 3 fixes proposed and applied in reverse index order (avoids renumbering) | ✔ |

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
| `✖ [ALERT]` Duplicate UFW rule detected: `80/tcp ALLOW IN Anywhere` | ✔ v0.11.4 |
| Comment stripped before comparison — `# test2` ignored | ✔ |
| Redundant `80/tcp` deleted, `80` kept | ✔ |

**Root cause fixed:** Comparison now uses comment-stripped, whitespace-normalized text. (commit `b7a285a`)

---

### B3 — Semantic duplicate: `PORT/proto` redundant when `PORT` exists

```bash
sudo ufw allow 80/tcp comment "test2"
# 80 (no proto) already present → 80/tcp is redundant
```

| Expected | Result |
|----------|--------|
| `✖ [ALERT]` Duplicate UFW rule detected: `80/tcp ALLOW IN Anywhere` | ✔ v0.11.4 |
| `-1` score deduction | ✔ |
| Fix deletes the protocol-specific rule, keeps the broader one | ✔ |

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
| `✔ [OK]` No duplicate UFW rules detected | ✔ v0.11.4 |
| `80/tcp` and `80/udp` are complementary — not flagged | ✔ |

> Also note: when baseline has `80` (bare), adding `80/tcp` + `80/udp` correctly flags BOTH as semantic duplicates of `80`. Verified live.

---

## Category C — Critical services exposed

### C3 — Redis exposed on all interfaces (service installed and active)

```bash
sudo ufw allow 6379
# Redis configured to bind 0.0.0.0 (not the default)
```

| Expected | Result |
|----------|--------|
| `✖ [ALERT]` Port 6379/tcp — open to internet (Action required) | ✔ v0.11.4 |
| Risk context CRITICAL displayed | ✔ |
| `-2` score deduction (NAT context) | ✔ |
| Panorama: Redis `✖` → `⚠` | ✔ |
| DDNS cross-check: `→ 6379/tcp` | ✔ v0.14.1 (bare rule `6379/udp` filtered — no UDP listener) |

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
| `ℹ [INFO]` Port 6379/tcp — bound to localhost only — UFW rule has no effect on external access | ✔ v0.14.1 |
| No ALERT, no score deduction | ✔ |
| Panorama: Redis `✔` (rule exists, exposure = LOOPBACK) | ✔ |
| DDNS: `6379/tcp` NOT in exposed ports (loopback only) | ✔ |
| DDNS: `6379/udp` NOT in exposed ports (no UDP listener) | ✔ |

**Root cause fixed (v0.14.1):** `_classify_exposure()` was UFW-only and did not cross-check actual socket bindings. Fix: `PortsSnapshot` is now collected before CHECK 3; ports where all `ss` bindings are loopback get `Exposure.LOOPBACK` (INFO, no deduction). `_find_open_ports()` in `ddns.py` now also receives the `loopback_ports` and `active_ports` sets. (commits `2bfc85b`, `64311be`)

---

### C2 — MySQL exposed (service not installed)

```bash
sudo ufw allow 3306
```

| Expected | Result |
|----------|--------|
| No service alert (MySQL not installed) | ✔ v0.11.4 |
| Port 3306 open in UFW but unmatched to any installed service | confirmed |
| DDNS: `3306/tcp` and `3306/udp` NOT in exposed ports (no active listener) | ✔ v0.14.1 |

> **Behaviour updated (v0.14.1):** `_find_open_ports()` now cross-checks against actual non-loopback listeners (`active_ports` set from `ss`). Orphan UFW rules (port open, no service running) are excluded from the DDNS exposed ports list. `3306/tcp` and `3306/udp` no longer appear in DDNS findings when MySQL is not installed.

---

## Category D — IPv6 consistency

Not yet tested live. Covered by unit tests in `test_check_rules.py`:
- IPv4 rules with no IPv6 equivalent → `⚠ [WARNING]` (validated)
- IPv4 + IPv6 rules present → `✔ [OK]` (validated)

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
