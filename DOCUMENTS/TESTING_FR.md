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

**Cause racine corrigée :** `ufw status numbered` remplit lignes avec espaces trailing — l'ancre `$` dans regex ne correspondait jamais. Corrigé : `Anywhere$` → `Anywhere\s*$`. (commit `8ccd9b6`)

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

**Cause racine corrigée :** Motif étendu à `Anywhere(?:/\w+)?` des deux côtés pour couvrir variantes `/tcp`, `/udp`. (commit `1dd9ede`)

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

---

### A4 — Les trois wildcards simultanément

```bash
sudo ufw allow from any
sudo ufw allow proto tcp from any to any
sudo ufw allow proto udp from any to any
```

| Attendu | Résultat |
|----------|----------|
| 3 résultats `✖ [ALERTE]` distincts | ✔ v0.11.4 |
| Score : 1/10, Niveau risque : CRITIQUE | ✔ |
| 3 corrections proposées et appliquées en ordre index inverse (avertit renomination) | ✔ |

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

## Catégorie D — Cohérence IPv6

Pas encore testé en direct. Couvert par unit tests dans `test_check_rules.py` :
- Règles IPv4 sans équivalent IPv6 → `⚠ [AVERTISSEMENT]` (validé)
- Règles IPv4 + IPv6 présentes → `✔ [OK]` (validé)

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
