*[Lire en français](README_DEV_FR.md)*

# ufw-audit — Developer documentation

This document is for people who want to contribute to the project, add a service, add a language, or understand the internal architecture.

---

## Table of contents

1. [Architecture](#architecture)
2. [Project structure](#project-structure)
3. [Running the tests](#running-the-tests)
4. [Adding a service](#adding-a-service)
5. [Adding a language](#adding-a-language)
6. [Code conventions](#code-conventions)
7. [Execution flow](#execution-flow)
8. [Scoring system](#scoring-system)
9. [Internationalisation](#internationalisation)

---

## Architecture

The project is built around one central principle: **separate data collection from business logic**.

Each check module follows the same two-step pattern:

```
SystemSnapshot.from_system()   →   raw data from the system (subprocess calls)
check_xxx(snapshot, t)         →   pure logic, testable without system calls
```

This separation allows the entire business logic to be tested by instantiating snapshots directly in tests, with no mocks and no real system calls.

### Core modules

| Module | Role |
|---|---|
| `__main__.py` | Orchestrator — initialises, calls checks, displays results |
| `cli.py` | Argument parsing — returns an `AuditConfig` dataclass |
| `config.py` | User configuration — `~/.config/ufw-audit/config.conf` |
| `i18n.py` | Internationalisation — `t("key.sub_key")` with dot notation |
| `output.py` | Terminal display — `print_ok/warn/alert/info/section/banner` functions |
| `registry.py` | Service registry — loads `services.json`, exposes `ServiceRegistry` |
| `report.py` | Report file — writes the detailed report with immediate flush |
| `scoring.py` | Score engine — `ScoreEngine`, `CheckResult`, `Finding`, `Deduction` |

### Check modules (`checks/`)

| Module | What it checks |
|---|---|
| `firewall.py` | UFW status, default policy, IPv6 consistency |
| `services.py` | Installed network services, systemd state, UFW exposure |
| `ports.py` | Listening ports via `ss`, classification, deduplication |
| `logs.py` | UFW logs — blocked attempts, bruteforce, top IPs/ports |
| `ddns.py` | Active DDNS clients, configured domain, crossed with open UFW ports |
| `docker.py` | iptables bypass, ports exposed by containers |

---

## Project structure

```
ufw_audit/
├── __init__.py
├── __main__.py          # Orchestrator
├── cli.py               # AuditConfig + parse_args()
├── config.py            # UserConfig — user configuration
├── i18n.py              # t(key) with dot notation
├── output.py            # Terminal display
├── registry.py          # ServiceRegistry.load()
├── report.py            # AuditReport + NullReport
├── scoring.py           # ScoreEngine, CheckResult, Finding, Deduction
├── checks/
│   ├── __init__.py
│   ├── firewall.py      # FirewallStatus + check_firewall()
│   ├── services.py      # ServiceSnapshot + check_services()
│   ├── ports.py         # PortsSnapshot + check_ports()
│   ├── logs.py          # LogsSnapshot + check_logs()
│   ├── ddns.py          # DdnsSnapshot + check_ddns()
│   └── docker.py        # DockerSnapshot + check_docker()
├── data/
│   └── services.json    # Declarative registry of the 22 services
└── locales/
    ├── en.json          # English translation keys
    └── fr.json          # French translation keys

tests/
├── test_cli.py
├── test_config.py
├── test_ddns.py
├── test_docker.py
├── test_firewall.py
├── test_i18n.py
├── test_logs.py
├── test_output.py
├── test_ports.py
├── test_registry.py
├── test_report.py
├── test_scoring.py
└── test_services.py

install.sh               # Transparent installer with manifest
README.md                # User documentation
README_DEV.md            # This file
CHANGELOG.md             # Version history
```

---

## Running the tests

### Prerequisites

```bash
python3 --version   # 3.8+ required
```

No PyPI dependencies — stdlib only.

### Run all tests

```bash
cd ~/Desktop/ufw_audit/python/
python3 -m pytest tests/ -v
```

### Run a specific module

```bash
python3 -m pytest tests/test_scoring.py -v
python3 -m pytest tests/test_logs.py -v
```

### Run without pytest (stdlib only)

Each test file can be run directly:

```bash
python3 -m unittest tests/test_firewall.py
```

### Expected result

```
421 tests, 0 failures
```

Tests make no system calls — all snapshots are built directly in the test files. They can be run without `sudo` and without UFW installed.

---

## Adding a service

Everything happens in `ufw_audit/data/services.json`. No Python code changes are needed for services with standard detection.

### Service entry structure

```json
{
  "id": "my_service",
  "label": "My Service",
  "packages": ["my-service"],
  "services": ["my-service"],
  "ports": ["1234/tcp"],
  "risk": "medium",
  "config_key": "fixed",
  "detection": {
    "binary": [],
    "snap": [],
    "config_files": []
  }
}
```

### Required fields

| Field | Type | Description |
|---|---|---|
| `id` | string | Unique identifier, snake_case |
| `label` | string | Name displayed on screen |
| `packages` | array | dpkg package names to detect |
| `services` | array | systemd service names |
| `ports` | array | Default ports — format `"number/proto"` |
| `risk` | string | `"critical"`, `"high"`, `"medium"`, `"low"` |
| `config_key` | string | `"fixed"` or `"auto"` |
| `detection` | object | Alternative detection methods |

### Risk levels

| Value | Meaning | Effect |
|---|---|---|
| `critical` | Highly sensitive service | Risk context displayed, deductions doubled in public context |
| `high` | Sensitive service | Risk context displayed, deductions doubled in public context |
| `medium` | Standard service | No risk context |
| `low` | Internal service | No risk context |

### Detection via binary or snap

For services without a standard dpkg package:

```json
"detection": {
  "binary": ["/usr/local/bin/my-service"],
  "snap": ["my-service-snap"],
  "config_files": []
}
```

### Auto-detected port from config file

If the service can listen on a configurable port, use `"config_key": "auto"` and provide the configuration file:

```json
"config_key": "auto",
"detection": {
  "config_files": ["/etc/my-service/my-service.conf"]
}
```

The `services.py` module will attempt to extract the port from common patterns (`port = 1234`, `listen = 1234`, etc.).

### Adding risk context (critical/high services only)

For `critical` or `high` services, add the keys to both locale files.

The key is built from the label: lowercase, spaces → `_`, `/` → `_`, `(` and `)` removed.

Example for `"label": "My Service (daemon)"` → key `my_service_daemon`:

In `locales/en.json`:
```json
"service_risk": {
  "my_service_daemon": {
    "level": "HIGH",
    "exposure": "Description of the exposure vector",
    "threat": "Description of the potential threat"
  }
}
```

In `locales/fr.json`:
```json
"service_risk": {
  "my_service_daemon": {
    "level": "ÉLEVÉ",
    "exposure": "Description du vecteur d'exposition",
    "threat": "Description de la menace potentielle"
  }
}
```

### Verify key parity

After any change to the locales:

```bash
cd ~/Desktop/ufw_audit/python/
python3 check_keys.py
```

Expected output:
```
EN keys: 183
FR keys: 183
Missing in FR: none
```

---

## Adding a language

### 1. Create the locale file

```bash
cp ufw_audit/locales/en.json ufw_audit/locales/de.json
```

### 2. Translate all values

The file contains 183 keys organised into sections. Translate all values while keeping `{variable}` placeholders intact.

Example:
```json
"ports.listening_count": "{count} listening port(s) detected on this system"
```
becomes:
```json
"ports.listening_count": "{count} lauschende(r) Port(s) auf diesem System erkannt"
```

### 3. Add the CLI flag

In `ufw_audit/cli.py`, add the option in `parse_args()`:

```python
elif arg in ("--german", "--deutsch"):
    config.lang = "de"
```

### 4. Verify parity

```bash
python3 -c "
import json
def keys(d, p=''):
    k = set()
    for a,v in d.items():
        f = f'{p}.{a}' if p else a
        k |= keys(v,f) if isinstance(v,dict) else {f}
    return k
en = keys(json.load(open('ufw_audit/locales/en.json')))
de = keys(json.load(open('ufw_audit/locales/de.json')))
missing = en - de
print(f'Missing: {missing if missing else \"none\"}')
"
```

---

## Code conventions

### Snapshot / check pattern

Each check module strictly follows this pattern:

```python
@dataclass
class XxxSnapshot:
    # Raw data collected from the system
    field_a: str
    field_b: int

    @classmethod
    def from_system(cls) -> "XxxSnapshot":
        # Subprocess calls here — ONLY here
        data = _run("command", "arg")
        return cls(field_a=data, field_b=0)


def check_xxx(snapshot: XxxSnapshot, t=None) -> CheckResult:
    # Pure logic — NEVER any subprocess calls here
    _t = t if t is not None else _identity_t
    result = CheckResult()
    # ...
    return result
```

**Absolute rule:** `check_xxx()` never calls subprocess. All data collection is in `from_system()`.

### CheckResult

```python
result = CheckResult()

result.ok(message=_t("key"))                          # ✔ finding
result.warn(message=_t("key"), nature="improvement")  # ⚠ finding
result.alert(message=_t("key"), nature="action",      # ✖ finding
             cmd="sudo ufw ...")
result.info(message=_t("key"))                        # ℹ finding

result.add_deduction(
    reason=_t("key"),
    points=2,
    context="local",   # or "public"
)
```

### Finding natures

| Nature | Meaning | Summary block |
|---|---|---|
| `"action"` | Correction required | *Action required* |
| `"improvement"` | Possible improvement | *Possible improvements* |
| `"structural"` | Normal but notable configuration | *Normal configuration* |
| `None` | Purely informational | Not shown in summary |

### Translation function

Always pass `t` as a parameter with an identity fallback:

```python
def check_xxx(snapshot, t=None) -> CheckResult:
    _t = t if t is not None else _identity_t
```

This allows testing without initialising i18n:

```python
result = check_firewall(make_status())          # raw keys in messages
result = check_firewall(make_status(), t=my_t)  # custom translation
```

### Subprocess

Always via the `_run()` helper local to each module:

```python
def _run(*args: str) -> str:
    try:
        proc = subprocess.run(
            list(args), capture_output=True, text=True, timeout=10,
        )
        return proc.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return ""
```

Never let a subprocess exception propagate.

### Tests

Each check module has a corresponding test file. Tests:

- Make no system calls
- Build snapshots directly
- Test pure logic in `check_xxx()`
- Test parsing helpers separately

Typical structure:

```python
def make_snapshot(**overrides) -> XxxSnapshot:
    defaults = dict(field_a="default", field_b=0)
    defaults.update(overrides)
    return XxxSnapshot(**defaults)

def test_nominal_case():
    snap = make_snapshot(field_a="value")
    result = check_xxx(snap)
    assert "ok" in [f.level.value for f in result.findings]
```

---

## Execution flow

```
main()
  │
  ├── parse_args()              → AuditConfig
  ├── i18n.init(lang)           → load locales
  ├── ServiceRegistry.load()    → load services.json
  ├── UserConfig.load()         → load user config
  ├── AuditReport.open() / .null()
  ├── ScoreEngine()
  │
  ├── CHECK 1 — Firewall
  │     FirewallStatus.from_system()
  │     check_firewall(status, t)
  │     engine.apply(result)
  │
  ├── CHECK 2 — UFW rules
  │     _check_rules(ufw_verbose, ufw_numbered, t)
  │     engine.apply(result)
  │
  ├── CHECK 3 — Network services
  │     ServiceSnapshot.collect(registry)
  │     for each service:
  │       check_services([snap], t)
  │       engine.apply(result)
  │
  ├── CHECK 4 — Listening ports
  │     PortsSnapshot.from_system()
  │     check_ports(snapshot, audited_ports, t)
  │     engine.apply(result)
  │
  ├── CHECK 5 — UFW logs
  │     LogsSnapshot.from_system(log_days)
  │     check_logs(snapshot, audited_ports, t)
  │     engine.apply(result)
  │
  ├── CHECK 6 — DDNS
  │     DdnsSnapshot.from_system()
  │     check_ddns(snapshot, ufw_rules, t)
  │     engine.apply(result)
  │
  ├── CHECK 7 — Docker
  │     DockerSnapshot.from_system()
  │     check_docker(snapshot, t)
  │     engine.apply(result)
  │
  ├── engine.finalize()         → compute final score
  ├── _print_summary(engine)    → display summary
  └── report.close()
```

---

## Scoring system

### Score calculation

The score starts at 10/10. Each `Deduction` subtracts points.

```python
engine = ScoreEngine()
engine.apply(check_result)   # apply findings and deductions
engine.cap(maximum=3)        # cap score if firewall is inactive
engine.finalize()            # compute score and risk level

score = engine.score         # int 0–10
level = engine.level         # RiskLevel.LOW / MEDIUM / HIGH
```

### Network context

The `"public"` context (machine with a direct internet-facing IP) doubles penalties for exposed critical services.

```python
result.add_deduction(reason="...", points=2, context="public")
```

### Risk levels

| Score | Level |
|---|---|
| 8–10 | LOW |
| 5–7 | MEDIUM |
| 0–4 | HIGH |

---

## Internationalisation

### Accessing translations

```python
from ufw_audit.i18n import t

# Simple key
t("firewall.active")
# → "UFW firewall is active"

# Key with variable
t("ports.listening_count", count=17)
# → "17 listening port(s) detected on this system"
```

### Missing key

If a key does not exist, `t()` returns `"[missing.key]"` — never an exception. This makes incremental development easier.

### Data file location

In production (installed), locale files and `services.json` are read from `$UFW_AUDIT_SHARE` (set by the entry point to `/usr/local/share/ufw-audit/`).

In development (run from source), they are read from the `locales/` and `data/` directories relative to the Python module.

```python
# i18n.py
_share = os.environ.get("UFW_AUDIT_SHARE", "")
if _share:
    _LOCALES_DIR = Path(_share) / "locales"
else:
    _LOCALES_DIR = Path(__file__).parent / "locales"
```

---

## Environment variables

| Variable | Effect |
|---|---|
| `UFW_AUDIT_SHARE` | Shared data directory (locales, services.json) — set by the installer |
| `SUDO_USER` | Real user under sudo — used for config path and report |
| `NO_COLOR` | Disables ANSI colours (standard) |
