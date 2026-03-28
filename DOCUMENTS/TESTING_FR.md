*[Read in English](TESTING.md)*

# UFW-audit — Plan de test : règles UFW dangereuses

Tests de régression manuel utilisant délibérément des règles UFW dangereuses.
Chaque test vérifie qu'ufw-audit détecte (et corrige) une mauvaise configuration spécifique.

**VM de test :** Linux Mint 22.3 — `so6minttest`
**État de référence** (baseline propre après chaque test) :

```bash
sudo ufw --force reset
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp
sudo ufw allow 80
sudo ufw enable
```

---

## Catégorie A — Wildcards open-any

Règles ouvrant tous les ports à toutes les sources — sévérité majeure.

### A1 — Wildcard complet `Anywhere ALLOW IN Anywhere`

```bash
sudo ufw allow from any
```

| Attendu | Résultat |
|----------|----------|
| `✖ [ALERTE]` Règle autorisant toutes connexions entrantes sans restriction port | ✔ v0.11.4 |
| Déduction score `-2` | ✔ |
| Correction proposée : `sudo ufw --force delete N` | ✔ |
| Correction appliquée correctement | ✔ |
| **Règle IPv6 aussi détectée et corrigée** (`Anywhere (v6) ALLOW IN Anywhere (v6)`) | ✔ v0.15 |

**Cause racine corrigée (v0.11.4) :** `ufw status numbered` remplit lignes avec espaces trailing — l'ancre `$` dans regex ne correspondait jamais. Corrigé : `Anywhere$` → `Anywhere\s*$`. (commit `8ccd9b6`)

**Cause racine corrigée (v0.15) :** Règles wildcard IPv6 (`Anywhere (v6) ALLOW IN Anywhere (v6)`) échappaient à la détection — `open_any_pattern` ne prenait pas en compte le suffixe `(v6)`. Corrigé : motif étendu avec `(?:\s+\(v6\))?` des deux côtés. Règles IPv4 et IPv6 sont maintenant signalées et corrigées indépendamment.

---

### A2 — Wildcard TCP `Anywhere/tcp ALLOW IN Anywhere/tcp`

```bash
sudo ufw allow proto tcp from any to any
```

| Attendu | Résultat |
|----------|----------|
| `✖ [ALERTE]` Règle autorisant toutes connexions entrantes sans restriction port | ✔ v0.11.4 |
| Déduction score `-2` | ✔ |
| Correction appliquée correctement | ✔ |
| **Variante IPv6 aussi détectée** (`Anywhere/tcp (v6) ALLOW IN Anywhere/tcp (v6)`) | ✔ v0.15 |

**Cause racine corrigée (v0.11.4) :** Motif étendu à `Anywhere(?:/\w+)?` des deux côtés pour couvrir variantes `/tcp`, `/udp`. (commit `1dd9ede`)

**v0.15 :** Même correction IPv6 que A1 s'applique ici.

---

### A3 — Wildcard UDP `Anywhere/udp ALLOW IN Anywhere/udp`

```bash
sudo ufw allow proto udp from any to any
```

| Attendu | Résultat |
|----------|----------|
| `✖ [ALERTE]` Règle autorisant toutes connexions entrantes sans restriction port | ✔ v0.11.4 |
| Déduction score `-2` | ✔ |
| Correction appliquée correctement | ✔ |
| **Variante IPv6 aussi détectée** | ✔ v0.15 |

---

### A4 — Les trois wildcards simultanément

```bash
sudo ufw allow from any
sudo ufw allow proto tcp from any to any
sudo ufw allow proto udp from any to any
```

| Attendu | Résultat |
|----------|----------|
| 3 résultats `✖ [ALERTE]` distincts (IPv4 uniquement) | ✔ v0.11.4 |
| **6 résultats `✖ [ALERTE]` distincts (IPv4 + IPv6)** | ✔ v0.15 |
| Score : 0/10 (plafonné), Niveau risque : CRITIQUE | ✔ |
| 6 corrections proposées et appliquées en ordre index inverse | ✔ v0.15 |

---

### A5 — Faux positif : règle source restreinte

```bash
sudo ufw allow from 192.168.1.0/24
```

| Attendu | Résultat |
|----------|----------|
| `✔ [OK]` Aucune règle 'allow from any' sans restriction de port détectée | ✔ v0.15 |
| Règle source-restreinte NON signalée comme open-any | ✔ |

> `ufw status numbered` montre `Anywhere ALLOW IN 192.168.1.0/24` — destination est `Anywhere` mais source est restreinte. Le motif requiert correctement que LES DEUX côtés soient `Anywhere` pour déclencher.

---

## Catégorie B — Règles dupliquées

### B1 — Duplication exacte

```bash
sudo ufw allow 80/tcp
sudo ufw allow 80/tcp   # UFW dit: "Skipping adding existing rule"
```

| Attendu | Résultat |
|----------|----------|
| UFW nativement prévient vrais doublons exacts | ✔ confirmé |
| Non testable via CLI — requirerait manipulation directe fichiers | noté |

> **Note :** Doublons exacts peuvent seulement résulter édition directe `/etc/ufw/` ou outils externes (Ansible, scripts). CLI UFW les prévient.

---

### B2 — Même règle, commentaires différents

```bash
sudo ufw allow 80/tcp comment "test2"
# 80 (pas proto) déjà présent dans baseline
```

| Attendu | Résultat |
|----------|----------|
| `✖ [ALERTE]` Règle UFW dupliquée détectée : `80/tcp ALLOW IN Anywhere` | ✔ v0.11.4 |
| Commentaire supprimé avant comparaison — `# test2` ignoré | ✔ |
| `80/tcp` redondant supprimé, `80` gardé | ✔ |

**Cause racine corrigée :** Comparaison utilise maintenant texte stripé-commentaires, normalisé-espaces. (commit `b7a285a`)

---

### B3 — Duplication sémantique : `PORT/proto` redondant quand `PORT` existe

```bash
sudo ufw allow 80/tcp comment "test2"
# 80 (pas proto) déjà présent → 80/tcp est redondant
```

| Attendu | Résultat |
|----------|----------|
| `✖ [ALERTE]` Règle UFW dupliquée détectée : `80/tcp ALLOW IN Anywhere` | ✔ v0.11.4 |
| Déduction score `-1` | ✔ |
| Correction supprime la règle protocol-spécifique, garde la plus large | ✔ |

**Cause racine corrigée :** Détection deux-passes — première passe collecte toutes règles sans-protocole, deuxième passe vérifie si `PORT/proto` est subset d'existant `PORT`. (commit `b7a285a`)

---

### B4 — Duplication sémantique : variante UDP

```bash
sudo ufw allow 53/udp
sudo ufw allow 53
```

| Attendu | Résultat |
|----------|----------|
| `✖ [ALERTE]` `53/udp` détecté comme redondant | ✔ unit test |

> Validé via unit test uniquement (port DNS — pas dans registry services, pas risque pratique sur VM).

---

### B5 — Pas faux positif : `PORT/tcp` + `PORT/udp` sans `PORT`

```bash
sudo ufw allow 80/tcp
sudo ufw allow 80/udp
# Pas règle nulle "80"
```

| Attendu | Résultat |
|----------|----------|
| `✔ [OK]` Pas règles UFW dupliquées détectées | ✔ v0.11.4 |
| `80/tcp` et `80/udp` sont complémentaires — pas signalés | ✔ |

> Aussi noter : quand baseline a `80` (nu), ajouter `80/tcp` + `80/udp` correctement signale TOUTES DEUX comme doublons sémantiques de `80`. Vérifié en direct.

---

## Catégorie C — Services critiques exposés

### C1 — SSH exposé (état de la baseline)

SSH est toujours présent dans l'état de référence (`ufw allow 22/tcp`). Ce scénario documente le comportement attendu pour un service critique avec une règle UFW ALLOW non restreinte.

```bash
# État de la baseline — SSH déjà exposé
sudo ufw-audit
```

| Attendu | Résultat |
|---------|----------|
| `✖ [ALERTE]` Port 22/tcp — ouvert à internet — aucune restriction source dans UFW | pending |
| Contexte risque CRITIQUE affiché | pending |
| Déduction score `-2` (contexte NAT/local) | pending |
| Panorama : SSH `✖` | pending |

> **Remédiation à tester :** `sudo ufw delete allow 22/tcp && sudo ufw allow from 192.168.1.0/24 to any port 22 proto tcp` → passe en OPEN_LOCAL (AVERTISSEMENT et non ALERTE, sans déduction).

---

### C3 — Redis exposé sur toutes les interfaces (service installé et actif)

```bash
sudo ufw allow 6379
# Redis configuré pour écouter sur 0.0.0.0 (pas la configuration par défaut)
```

| Attendu | Résultat |
|----------|----------|
| `✖ [ALERTE]` Port 6379/tcp — ouvert à internet (Action requise) | ✔ v0.11.4 |
| Contexte risque CRITIQUE affiché | ✔ |
| Déduction score `-2` (contexte NAT) | ✔ |
| Panorama : Redis `✖` → `⚠` | ✔ |
| Vérification croisée DDNS : `→ 6379/tcp` | ✔ v0.14.1 (`6379/udp` filtré — pas de listener UDP) |

**Cause racine corrigée (obs 1) :** Services CRITIQUE/ÉLEVÉS avec exposition `OPEN_WORLD` lèvent maintenant `alert()` au lieu `warn()`, les déplaçant à « Action requise ». (commit `e01b24b`)

---

### C3b — Redis loopback uniquement — correction faux positif (v0.14.1)

Configuration Redis par défaut : écoute sur `127.0.0.1` uniquement, mais une règle UFW permissive existe.

```bash
sudo ufw allow 6379
# Redis par défaut : bind 127.0.0.1 (loopback uniquement)
```

| Attendu | Résultat |
|----------|----------|
| `ℹ [INFO]` Port 6379/tcp — lié uniquement sur localhost — la règle UFW n'a aucun effet sur l'accès externe | ✔ v0.14.1 |
| Pas d'ALERTE, pas de déduction de score | ✔ |
| Panorama : Redis `✔` (règle existe, exposition = LOOPBACK) | ✔ |
| DDNS : `6379/tcp` absent de la liste exposée (loopback uniquement) | ✔ |
| DDNS : `6379/udp` absent de la liste exposée (pas de listener UDP) | ✔ |

**Cause racine corrigée (v0.14.1) :** `_classify_exposure()` se basait uniquement sur UFW et ne vérifiait pas les bindings réels des sockets. Correction : `PortsSnapshot` est collecté avant le CHECK 3 ; les ports dont tous les bindings `ss` sont en loopback reçoivent `Exposure.LOOPBACK` (INFO, sans déduction). `_find_open_ports()` dans `ddns.py` reçoit également les ensembles `loopback_ports` et `active_ports`. (commits `2bfc85b`, `64311be`)

---

### C2 — MySQL exposé (service non installé)

```bash
sudo ufw allow 3306
```

| Attendu | Résultat |
|----------|----------|
| Pas d'alerte service (MySQL non installé) | ✔ v0.11.4 |
| Port 3306 ouvert dans UFW mais non-correspondant à aucun service installé | confirmé |
| DDNS : `3306/tcp` et `3306/udp` absents de la liste exposée (aucun listener actif) | ✔ v0.14.1 |

> **Comportement mis à jour (v0.14.1) :** `_find_open_ports()` effectue maintenant une vérification croisée avec les listeners non-loopback réels (ensemble `active_ports` depuis `ss`). Les règles UFW orphelines (port ouvert, aucun service actif) sont exclues de la liste d'exposition DDNS. `3306/tcp` et `3306/udp` n'apparaissent plus dans les résultats DDNS quand MySQL n'est pas installé.

---

### C4 — Nginx exposé (service à risque moyen, installé et actif)

```bash
sudo apt install nginx
sudo ufw allow 80
sudo ufw-audit
```

| Attendu | Résultat |
|---------|----------|
| `⚠ [AVERTISSEMENT]` Port 80/tcp — ouvert à internet — aucune restriction source dans UFW | pending |
| Contexte risque MOYEN affiché | pending |
| Déduction score `-1` | pending |
| Panorama : Nginx `⚠` | pending |
| Résultat dans *Améliorations possibles* (et non *Action requise*) | pending |

> Les services à risque moyen utilisent `warn()` et non `alert()` — distinction par rapport aux services critiques comme SSH ou Redis.

---

### C5 — Samba exposé (service critique, installé et actif)

```bash
sudo apt install samba
sudo ufw allow 445
sudo ufw allow 139
sudo ufw-audit
```

| Attendu | Résultat |
|---------|----------|
| `✖ [ALERTE]` Port 445/tcp — ouvert à internet — aucune restriction source dans UFW | pending |
| `✖ [ALERTE]` Port 139/tcp — ouvert à internet | pending |
| Contexte risque CRITIQUE affiché (vecteur ransomware, EternalBlue) | pending |
| Déduction score × 2 (deux ports) | pending |
| Panorama : Samba `✖` | pending |
| Les deux ports dans le bloc *Action requise* | pending |

> **Nettoyage :** `sudo apt remove --purge samba && sudo ufw delete allow 445 && sudo ufw delete allow 139`

---

### C6 — Ports ouverts dans UFW, services non installés (services multiples)

Pour chaque entrée ci-dessous : ouvrir le port dans UFW sans service correspondant installé. Comportement attendu : **aucune alerte service**, le port peut apparaître comme règle UFW orpheline.

```bash
sudo ufw allow <PORT>
sudo ufw-audit
```

| Service | Port | Comportement attendu | Résultat |
|---------|------|---------------------|----------|
| Serveur VNC | 5900/tcp | Pas d'alerte service — VNC non détecté | pending |
| Serveur FTP | 21/tcp | Pas d'alerte service — FTP non détecté | pending |
| PostgreSQL | 5432/tcp | Pas d'alerte service — PostgreSQL non détecté | pending |
| Mosquitto (MQTT) | 1883/tcp | Pas d'alerte service — Mosquitto non détecté | pending |
| WireGuard | 51820/udp | Pas d'alerte service — WireGuard non détecté | pending |
| Gitea | 3000/tcp | Pas d'alerte service — Gitea non détecté | pending |
| Jellyfin | 8096/tcp | Pas d'alerte service — Jellyfin non détecté | pending |
| Home Assistant | 8123/tcp | Pas d'alerte service — HASS non détecté | pending |
| Cockpit | 9090/tcp | Pas d'alerte service — Cockpit non détecté | pending |

> Pour tous les cas ci-dessus : le port n'a pas de listener actif — aucune ALERTE dans ANALYSE DES SERVICES RÉSEAU.
> Vérification croisée DDNS : aucun de ces ports ne doit apparaître dans la liste exposée DDNS (aucun listener actif — correction v0.14.1).

> **Déjà validé :** MySQL / MariaDB (3306) → C2

---

### C7 — CUPS exposé (service à faible risque, souvent pré-installé sur desktop Linux)

CUPS (serveur d'impression) écoute sur `127.0.0.1:631` par défaut. Ce test vérifie le comportement quand CUPS est actif et une règle UFW existe.

```bash
# CUPS est souvent pré-installé sur Linux Mint
sudo ufw allow 631
sudo ufw-audit
```

| Attendu | Résultat |
|---------|----------|
| `ℹ [INFO]` Port 631/tcp — lié uniquement sur localhost — la règle UFW n'a aucun effet | pending |
| Pas d'ALERTE, pas de déduction de score (binding loopback) | pending |
| Panorama : CUPS `✔` (règle existe, loopback → INFO) | pending |

> Si CUPS écoute sur `0.0.0.0` : `⚠ [AVERTISSEMENT]` Port 631/tcp — ouvert à internet (risque faible, nature=improvement).

---

## Catégorie D — Cohérence IPv6

### D1 — Règles IPv4 présentes, aucun équivalent IPv6 (avertissement attendu)

```bash
# Depuis la baseline : 22/tcp et 80 sont présents, aucune règle (v6)
sudo ufw status numbered
```

> **Note :** Certaines distributions (ou VMs avec `IPV6=no` dans `/etc/default/ufw`) n'ajoutent pas de règles IPv6. Si toutes les règles sont déjà couplées (IPv4 + IPv6), utiliser `sudo ufw --force reset` et re-ajouter uniquement les règles IPv4.

| Attendu | Résultat |
|----------|----------|
| `⚠ [AVERTISSEMENT]` Règles IPv6 manquantes — seules des règles IPv4 présentes | ✔ unit test |
| Déduction score `-1` | ✔ unit test |
| Test direct | pending |

---

### D2 — Règles IPv4 et IPv6 toutes deux présentes (pas d'avertissement)

| Attendu | Résultat |
|----------|----------|
| `✔ [OK]` Règles IPv4 et IPv6 toutes deux présentes | ✔ unit test |
| Aucune déduction | ✔ unit test |
| Test direct | pending |

---

## Observations supplémentaires

### Obs — DDNS ne détecte pas règles sans-protocole (corrigé)

Avec `80 ALLOW IN Anywhere` (pas `/tcp`), la vérification croisée DDNS n'affichait précédemment rien pour le port 80.

**Cause racine corrigée :** `_find_open_ports()` gère maintenant les règles ports nus — ajoute `PORT/tcp` et `PORT/udp` à la liste des ports ouverts. (commit `e01b24b`)

**Validé (mise à jour v0.14.1) :** Règle nue `80 ALLOW` avec Nginx écoutant sur `0.0.0.0:80` → DDNS liste correctement `→ 80/tcp` uniquement (`80/udp` filtré — aucun listener UDP sur le port 80).

---

### Obs — Faux positifs DDNS : ports système et règles orphelines (v0.14.1)

```bash
sudo ufw allow 53
sudo ufw allow 3306
sudo ufw allow 6379
# Redis sur 127.0.0.1 uniquement, MySQL non installé
```

| Attendu | Résultat |
|----------|----------|
| DDNS : `53/tcp`, `53/udp` absents (filtre ports système) | ✔ v0.14.1 |
| DDNS : `3306/tcp`, `3306/udp` absents (aucun listener actif) | ✔ v0.14.1 |
| DDNS : `6379/tcp`, `6379/udp` absents (loopback uniquement / pas de listener UDP) | ✔ v0.14.1 |

**Cause racine corrigée (v0.14.1) :** Ajout de la constante `_DDNS_SYSTEM_PORTS` (53, 67, 68, 546, 547, 5353) et vérification croisée `active_ports` dans `_find_open_ports()`. Seuls les ports avec un listener non-loopback réel dans la sortie `ss` sont inclus dans la liste d'exposition DDNS. (commit `64311be`)

---

### Obs — UFW permet règles wildcard après règles spécifiques sans erreur

```
Anywhere/tcp    ALLOW IN    Anywhere/tcp
22/tcp          ALLOW IN    Anywhere
```

UFW n'avertit pas que `Anywhere/tcp` rend `22/tcp` redondant. ufw-audit correctement signale le wildcard.

---

## Note B1 — doublons exacts via manipulation fichiers

Pour tester doublons exacts que CLI UFW prévient, règles peuvent être injectées directement :

```bash
sudo cp /etc/ufw/user.rules /etc/ufw/user.rules.bak
# Manuellement dupliquer ligne règle dans user.rules
sudo ufw reload
sudo ufw-audit
# Nettoyage :
sudo cp /etc/ufw/user.rules.bak /etc/ufw/user.rules
sudo ufw reload
```

Pas encore testé — priorité pratique basse car CLI UFW le prévient.

---

## Catégorie E — Ports loopback uniquement (v0.15)

### E1 — Port écoutant sur localhost uniquement, sans règle UFW — INFO pas ALERTE

```bash
# Tout processus lié exclusivement à 127.0.0.1 sans règle UFW
# Redis par défaut : bind 127.0.0.1 — aucune règle UFW nécessaire
sudo ufw-audit
```

| Attendu | Résultat |
|----------|----------|
| `ℹ [INFO]` Port X — lié uniquement à localhost — pas d'exposition externe | pending |
| Pas d'ALERTE, pas de déduction de score | pending |
| Message utilise la clé locale `ports.uncovered_local` (nouveau en v0.15) | pending |

> **Nouveau en v0.15 :** Les ports dans `PortCategory.UNCOVERED_LOCAL` utilisent maintenant une clé locale distincte `ports.uncovered_local` au lieu de `ports.uncovered` (qui implique une exposition sur toutes les interfaces). Cela évite des messages trompeurs « listening on all interfaces » pour les services loopback uniquement.
