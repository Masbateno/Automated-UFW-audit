*[Read in English](README.md)*

# ufw-audit — Documentation développeur

Ce document s'adresse aux personnes qui souhaitent contribuer au projet, ajouter un service, ajouter une langue, ou comprendre l'architecture interne.

---

## Table des matières

1. [Architecture](#architecture)
2. [Structure du projet](#structure-du-projet)
3. [Lancer les tests](#lancer-les-tests)
4. [Ajouter un service](#ajouter-un-service)
5. [Ajouter une langue](#ajouter-une-langue)
6. [Conventions de code](#conventions-de-code)
7. [Flux d'exécution](#flux-dexécution)
8. [Système de scoring](#système-de-scoring)
9. [Internationalisation](#internationalisation)

---

## Architecture

Le projet est structuré autour d'un principe central : **séparer la collecte de données de la logique métier**.

Chaque module de vérification suit le même pattern en deux étapes :

```
SystemSnapshot.from_system()   →   données brutes du système (subprocess)
check_xxx(snapshot, t)         →   logique pure, testable sans appels système
```

Cette séparation permet de tester toute la logique métier en instanciant directement des snapshots dans les tests, sans mock ni appels système réels.

### Modules principaux

| Module | Rôle |
|---|---|
| `__main__.py` | Orchestrateur — initialise, appelle les checks, affiche les résultats |
| `cli.py` | Parsing des arguments — retourne un `AuditConfig` dataclass |
| `config.py` | Configuration utilisateur — `~/.config/ufw-audit/config.conf` |
| `i18n.py` | Internationalisation — `t("clé.sous_clé")` avec notation pointée |
| `output.py` | Affichage terminal — fonctions `print_ok/warn/alert/info/section/banner` |
| `registry.py` | Registre des services — charge `services.json`, expose `ServiceRegistry` |
| `report.py` | Fichier rapport — écrit le rapport détaillé avec flush immédiat |
| `scoring.py` | Moteur de score — `ScoreEngine`, `CheckResult`, `Finding`, `Deduction` |

### Modules de vérification (`checks/`)

| Module | Ce qu'il vérifie |
|---|---|
| `firewall.py` | Statut UFW, politique par défaut, cohérence IPv6 |
| `services.py` | Services réseau installés, état systemd, exposition UFW |
| `ports.py` | Ports en écoute via `ss`, classification, déduplication |
| `logs.py` | Logs UFW — tentatives bloquées, bruteforce, top IPs/ports |
| `ddns.py` | Clients DDNS actifs, domaine configuré, ports ouverts croisés |
| `docker.py` | Contournement iptables, ports exposés par les containers |

---

## Structure du projet

```
ufw_audit/
├── __init__.py
├── __main__.py          # Orchestrateur
├── cli.py               # AuditConfig + parse_args()
├── config.py            # UserConfig — config utilisateur
├── i18n.py              # t(key) avec notation pointée
├── output.py            # Affichage terminal
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
│   └── services.json    # Registre déclaratif des 22 services
└── locales/
    ├── en.json          # Clés de traduction anglais
    └── fr.json          # Clés de traduction français

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

install.sh               # Installateur transparent avec manifeste
README.md                # Documentation utilisateur
README_DEV.md            # Ce fichier
CHANGELOG.md             # Historique des versions
```

---

## Lancer les tests

### Prérequis

```bash
python3 --version   # 3.8+ requis
```

Aucune dépendance PyPI — stdlib uniquement.

### Lancer tous les tests

```bash
cd ~/Desktop/ufw_audit/python/
python3 -m pytest tests/ -v
```

### Lancer un module spécifique

```bash
python3 -m pytest tests/test_scoring.py -v
python3 -m pytest tests/test_logs.py -v
```

### Lancer sans pytest (stdlib uniquement)

Chaque fichier de test peut être lancé directement :

```bash
python3 -m unittest tests/test_firewall.py
```

### Résultats attendus

```
421 tests, 0 failures
```

Les tests n'effectuent aucun appel système — tous les snapshots sont construits directement dans les tests. Ils peuvent être lancés sans `sudo` et sans UFW installé.

---

## Ajouter un service

Tout se passe dans `ufw_audit/data/services.json`. Aucune modification de code Python n'est nécessaire pour les services avec détection standard.

### Structure d'une entrée service

```json
{
  "id": "mon_service",
  "label": "Mon Service",
  "packages": ["mon-service"],
  "services": ["mon-service"],
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

### Champs obligatoires

| Champ | Type | Description |
|---|---|---|
| `id` | string | Identifiant unique, snake_case |
| `label` | string | Nom affiché à l'écran |
| `packages` | array | Noms de paquets dpkg à détecter |
| `services` | array | Noms de services systemd |
| `ports` | array | Ports par défaut — format `"numéro/proto"` |
| `risk` | string | `"critical"`, `"high"`, `"medium"`, `"low"` |
| `config_key` | string | `"fixed"` ou `"auto"` |
| `detection` | object | Méthodes de détection alternatives |

### Niveaux de risque

| Valeur | Signification | Effet |
|---|---|---|
| `critical` | Service très sensible | Contexte de risque affiché, déductions doublées en contexte public |
| `high` | Service sensible | Contexte de risque affiché, déductions doublées en contexte public |
| `medium` | Service standard | Pas de contexte de risque |
| `low` | Service interne | Pas de contexte de risque |

### Détection par binaire ou snap

Pour les services sans paquet dpkg standard :

```json
"detection": {
  "binary": ["/usr/local/bin/mon-service"],
  "snap": ["mon-service-snap"],
  "config_files": []
}
```

### Port auto-détecté depuis la config

Si le service peut écouter sur un port configurable, utiliser `"config_key": "auto"` et fournir le fichier de configuration :

```json
"config_key": "auto",
"detection": {
  "config_files": ["/etc/mon-service/mon-service.conf"]
}
```

Le module `services.py` tentera d'extraire le port depuis les patterns courants (`port = 1234`, `listen = 1234`, etc.).

### Ajouter le contexte de risque (services critical/high uniquement)

Pour les services `critical` ou `high`, ajouter les clés dans les deux fichiers de locale.

La clé est construite depuis le label : minuscules, espaces → `_`, `/` → `_`, `(` et `)` supprimés.

Exemple pour `"label": "Mon Service (daemon)"` → clé `mon_service_daemon` :

Dans `locales/en.json` :
```json
"service_risk": {
  "mon_service_daemon": {
    "level": "HIGH",
    "exposure": "Description of the exposure vector",
    "threat": "Description of the potential threat"
  }
}
```

Dans `locales/fr.json` :
```json
"service_risk": {
  "mon_service_daemon": {
    "level": "ÉLEVÉ",
    "exposure": "Description du vecteur d'exposition",
    "threat": "Description de la menace potentielle"
  }
}
```

### Vérifier la parité des clés

Après toute modification des locales :

```bash
cd ~/Desktop/ufw_audit/python/
python3 check_keys.py
```

Résultat attendu :
```
EN keys: 183
FR keys: 183
Missing in FR: none
```

---

## Ajouter une langue

### 1. Créer le fichier de locale

```bash
cp ufw_audit/locales/en.json ufw_audit/locales/de.json
```

### 2. Traduire toutes les valeurs

Le fichier contient 183 clés organisées en sections. Traduire toutes les valeurs en conservant les placeholders `{variable}` intacts.

Exemple :
```json
"ports.listening_count": "{count} listening port(s) detected on this system"
```
devient :
```json
"ports.listening_count": "{count} lauschende(r) Port(s) auf diesem System erkannt"
```

### 3. Ajouter le flag CLI

Dans `ufw_audit/cli.py`, ajouter l'option dans `parse_args()` :

```python
elif arg in ("--german", "--deutsch"):
    config.lang = "de"
```

### 4. Vérifier la parité

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

## Conventions de code

### Pattern snapshot / check

Chaque module de vérification suit strictement ce pattern :

```python
@dataclass
class XxxSnapshot:
    # Données brutes collectées du système
    field_a: str
    field_b: int

    @classmethod
    def from_system(cls) -> "XxxSnapshot":
        # Appels subprocess ici — UNIQUEMENT ici
        data = _run("command", "arg")
        return cls(field_a=data, field_b=0)


def check_xxx(snapshot: XxxSnapshot, t=None) -> CheckResult:
    # Logique pure — JAMAIS d'appels subprocess ici
    _t = t if t is not None else _identity_t
    result = CheckResult()
    # ...
    return result
```

**Règle absolue :** `check_xxx()` ne fait jamais appel à subprocess. Toute la collecte est dans `from_system()`.

### CheckResult

```python
result = CheckResult()

result.ok(message=_t("clé"))                          # ✔ finding
result.warn(message=_t("clé"), nature="improvement")  # ⚠ finding
result.alert(message=_t("clé"), nature="action",      # ✖ finding
             cmd="sudo ufw ...")
result.info(message=_t("clé"))                        # ℹ finding

result.add_deduction(
    reason=_t("clé"),
    points=2,
    context="local",   # ou "public"
)
```

### Natures des findings

| Nature | Signification | Bloc résumé |
|---|---|---|
| `"action"` | Correction requise | *Action requise* |
| `"improvement"` | Amélioration possible | *Améliorations possibles* |
| `"structural"` | Configuration normale mais notable | *Configuration normale* |
| `None` | Informatif pur | Non affiché dans le résumé |

### Fonction de traduction

Toujours passer `t` en paramètre avec fallback identity :

```python
def check_xxx(snapshot, t=None) -> CheckResult:
    _t = t if t is not None else _identity_t
```

Cela permet de tester sans initialiser i18n :

```python
result = check_firewall(make_status())          # clés brutes dans les messages
result = check_firewall(make_status(), t=my_t)  # traduction personnalisée
```

### Subprocess

Toujours via le helper `_run()` local à chaque module :

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

Ne jamais laisser une exception subprocess remonter.

### Tests

Chaque module de vérification a son fichier de test correspondant. Les tests :

- Ne font aucun appel système
- Construisent les snapshots directement
- Testent la logique pure dans `check_xxx()`
- Testent les helpers de parsing séparément

Structure type :

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

## Flux d'exécution

```
main()
  │
  ├── parse_args()              → AuditConfig
  ├── i18n.init(lang)           → charge les locales
  ├── ServiceRegistry.load()    → charge services.json
  ├── UserConfig.load()         → charge config utilisateur
  ├── AuditReport.open() / .null()
  ├── ScoreEngine()
  │
  ├── CHECK 1 — Firewall
  │     FirewallStatus.from_system()
  │     check_firewall(status, t)
  │     engine.apply(result)
  │
  ├── CHECK 2 — Règles UFW
  │     _check_rules(ufw_verbose, ufw_numbered, t)
  │     engine.apply(result)
  │
  ├── CHECK 3 — Services réseau
  │     ServiceSnapshot.collect(registry)
  │     pour chaque service :
  │       check_services([snap], t)
  │       engine.apply(result)
  │
  ├── CHECK 4 — Ports en écoute
  │     PortsSnapshot.from_system()
  │     check_ports(snapshot, audited_ports, t)
  │     engine.apply(result)
  │
  ├── CHECK 5 — Logs UFW
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
  ├── engine.finalize()         → calcule score final
  ├── _print_summary(engine)    → affiche résumé
  └── report.close()
```

---

## Système de scoring

### Calcul du score

Le score démarre à 10/10. Chaque `Deduction` soustrait des points.

```python
engine = ScoreEngine()
engine.apply(check_result)   # applique findings et déductions
engine.cap(maximum=3)        # plafonne si pare-feu inactif
engine.finalize()            # calcule score et niveau de risque

score = engine.score         # int 0–10
level = engine.level         # RiskLevel.LOW / MEDIUM / HIGH
```

### Contexte réseau

Le contexte `"public"` (machine avec IP directement accessible sur internet) double les pénalités pour les services critiques exposés.

```python
result.add_deduction(reason="...", points=2, context="public")
```

### Niveaux de risque

| Score | Niveau |
|---|---|
| 8–10 | FAIBLE |
| 5–7 | MOYEN |
| 0–4 | ÉLEVÉ |

---

## Internationalisation

### Accès aux traductions

```python
from ufw_audit.i18n import t

# Clé simple
t("firewall.active")
# → "Le pare-feu UFW est actif"

# Clé avec variable
t("ports.listening_count", count=17)
# → "17 port(s) en écoute détecté(s) sur ce système"
```

### Clé manquante

Si une clé n'existe pas, `t()` retourne `"[clé.manquante]"` — jamais une exception. Cela facilite le développement incrémental.

### Localisation des fichiers de données

En production (installé), les fichiers de locale et `services.json` sont lus depuis `$UFW_AUDIT_SHARE` (défini par le point d'entrée à `/usr/local/share/ufw-audit/`).

En développement (lancé depuis les sources), ils sont lus depuis le répertoire `locales/` et `data/` relatifs au module Python.

```python
# i18n.py
_share = os.environ.get("UFW_AUDIT_SHARE", "")
if _share:
    _LOCALES_DIR = Path(_share) / "locales"
else:
    _LOCALES_DIR = Path(__file__).parent / "locales"
```

---

## Variables d'environnement

| Variable | Effet |
|---|---|
| `UFW_AUDIT_SHARE` | Répertoire des données partagées (locales, services.json) — défini par l'installateur |
| `SUDO_USER` | Utilisateur réel sous sudo — utilisé pour le chemin de config et le rapport |
| `NO_COLOR` | Désactive les couleurs ANSI (standard) |

