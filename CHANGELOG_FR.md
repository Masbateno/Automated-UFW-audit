*[Read in English](CHANGELOG.md)* · *[Journal complet](DOCUMENTS/CHANGELOG_FULL_FR.md)*

# ufw-audit — Journal des modifications

| Version | Date | Résumé |
|---------|------|--------|
| [v1.2.0](#v120) | 2026-03-30 | Passage qualité : 12 corrections défensives sur 8 modules — aucun changement de comportement |
| [v1.1.1](#v111) | 2026-03-30 | Hotfix : Avahi (mDNS) affiche ✖ dans le panorama alors qu'il est couvert par la politique deny par défaut |
| [v1.1.0](#v110) | 2026-03-30 | Boîte de synthèse repensée (retour à la ligne + commandes de correction + disclaimer) ; détection vsftpd/Transmission corrigée ; passage qualité interne |
| [v1.0.4](#v104) | 2026-03-29 | Hotfix : ports éphémères encore affichés dans LISTENING PORTS OVERVIEW (couche affichage) |
| [v1.0.3](#v103) | 2026-03-29 | Hotfix : des centaines de messages de ports UDP éphémères inondaient la sortie (Samba/bureau actif) |
| [v1.0.1](#v101) | 2026-03-29 | Hotfix : SSH sur port non-standard non détecté ; ports TCP élevés classés à tort comme éphémères |
| [v1.0](#v10) | 2026-03-29 | Packaging PyPI, `--install-completion`, Python 3.9+, install.sh déprécié |
| [v0.22.1](#v0221) | 2026-03-29 | Hotfix : pare-feu détecté inactif sur les locales non-anglaises |
| [v0.22](#v022) | 2026-03-29 | 5 modules refactorisés, alignement des cadres corrigé, `CheckResult` nettoyé |
| [v0.21](#v021) | 2026-03-28 | 619/619 tests — corrections faux positifs CGNAT/IPv6, carnet d'adresses email |
| [v0.20](#v020) | 2026-03-28 | 548/548 — 17 tests mode dégradé (`ss`/règles/logs absents) |
| [v0.19](#v019) | 2026-03-28 | CI GitHub Actions — matrice Python 3.8/3.10/3.12 |
| [v0.18](#v018) | 2026-03-28 | 531/531 — 26 nouveaux tests pour `fixes.py` |
| [v0.17](#v017) | 2026-03-28 | 505/505 — 15 échecs préexistants corrigés ; deux corrections de code |
| [v0.16](#v016) | 2026-03-28 | Faux positifs panorama : `NOT_LISTENING` + `LOOPBACK_NO_RULE` corrigés |
| [v0.15.1](#v0151) | 2026-03-27 | Install script : rollback transactionnel ; interface fix plus propre |
| [v0.15](#v015) | 2026-03-27 | Audit sécurité (8 corrections), refactoring DRY, wildcards IPv6 détectés |
| [v0.14.1](#v0141) | 2026-03-26 | Faux positifs : Redis loopback, ports système DDNS, bannière VERSION |
| [v0.14](#v014) | 2026-03-25 | `__main__.py` 1820→481 lignes — 5 nouveaux modules extraits |
| [v0.13](#v013) | 2026-03-24 | Planificateur multi-cron, TUI `--manage-cron`, 40+ tests cron |
| [v0.12](#v012) | 2026-03-24 | Rapports email HTML, conversion markdown→HTML sans dépendance |
| [v0.11.4](#v0114) | 2026-03-23 | Regex open-any corrigé, services critiques→Action requise, `TESTING.md` |
| [v0.11.3](#v0113) | 2026-03-23 | `--install-cron`, `--manage-logs`, panorama services, bannière auto-fix |
| [v0.11.2](#v0112) | 2026-03-22 | Bannière redessinée (ASCII art Doom), messages d'exposition réécrits |
| [v0.11.1](#v0111) | 2026-03-22 | Patch sécurité : 20 vulnérabilités corrigées |
| [v0.11](#v011) | 2026-03-22 | Tests terrain (Mint/Debian/Kali), `--quiet`, détection virtualisation |
| [v0.10](#v010) | — | Géolocalisation GeoIP2, options courtes CLI, note de périmètre du score |
| [v0.9](#v09) | — | Réécriture complète Python, 421 tests, 22 services, bilingue EN/FR |

---

## v1.2.0

**2026-03-30**

- Correction : `i18n.current_lang()` retourne désormais la locale réellement chargée, et non celle demandée (utile lors du fallback depuis une langue non supportée)
- Correction : `manage_logs.py` — les trois chemins de suppression (`single`, `multi`, `all`) protègent `unlink()` avec `try/except OSError`
- Correction : `i18n.init()` lève un `ValueError` explicite sur les fichiers JSON de locale malformés (était un `JSONDecodeError` brut)
- Correction : `_paths.resolve_share_dir()` protège `Path.resolve()` avec `try/except OSError`
- Correction : `registry.py` — `config_key` validé contre `VALID_CONFIG_KEYS` ou `isidentifier()` ; format des ports validé (`nombre/tcp|udp`) ; `config_key="fixed"` requiert au moins un port
- Correction : `report_markdown.py` — détection des tables avec `line.strip().startswith("|")` (gère les tables indentées) ; lignes de cadres ASCII dans `_audit_log_to_html` matchées par regex ligne entière
- Correction : `report_markdown.py` — `send_html_email()` vérifie la présence de `sendmail` (et non `mail`) puisque c'est bien `sendmail` qui est appelé
- Correction : `output.py` — label et port du panorama tronqués à la largeur de colonne pour éviter les débordements de mise en page
- Correction : `scoring.py` — `Deduction.context` validé contre `{"local", "public", "structural"}` ; le cap injecte une `Deduction` synthétique dans le breakdown lors du `finalize()` pour que la raison du cap apparaisse dans la synthèse du score
- Correction : `sysinfo.py` — regex IPv4 privée centralisée (`_PRIVATE_IPV4_RE`) et appliquée uniformément ; détection `172.x` corrigée à la plage RFC 1918 uniquement (`172.16–31`) ; strings `kernel` et `user` sanitizés
- 639/639 tests unitaires

---

## v1.1.1

**2026-03-30**

- Hotfix : les services avec `Exposure.NO_RULE` (ex. Avahi/mDNS 5353/udp) affichaient ✖ dans la colonne UFW du panorama — un port sans règle explicite est couvert par la politique deny par défaut d'UFW et doit afficher ✔

---

## v1.1.0

**2026-03-30**

- Fonctionnalité : messages de la boîte de synthèse avec retour à la ligne — les longs findings ne sont plus tronqués
- Fonctionnalité : commandes de correction (`→ cmd`) affichées sous chaque finding dans la boîte de synthèse
- Fonctionnalité : disclaimer rouge affiché sous le bloc « Possible improvements »
- Correction : directive vsftpd `listen_port=X` non détectée par l'auto-détection de port
- Correction : `rpc-port` de Transmission dans `settings.json` non détecté (config JSON)
- Interne : paramètre timeout dans `_run()` ; regex validation domaine durcie ; `ipaddress` pour la détection IP publique Docker ; lecture log depuis la fin du fichier ; code mort supprimé ; typage amélioré
- 639/639 tests unitaires (+5)

---

## v1.0.4

**2026-03-29**

- Correction : les ports UDP éphémères inondaient toujours la section LISTENING PORTS OVERVIEW — `display_ports_overview()` affichait le raw `ss` sans filtrage. La couche affichage applique désormais le même filtre éphémère que la couche analyse.

---

## v1.0.3

**2026-03-29**

- Correction : chaque port UDP éphémère générait un message INFO — sur un bureau actif (Samba, navigateur, etc.) cela produisait des centaines de lignes inutiles. Les ports éphémères sont désormais silencieusement ignorés.

---

## v1.0.1

**2026-03-29**

- Correction : SSH sur un port non-standard (ex. `Port 49732` dans sshd_config) était toujours signalé sur le port 22 — la détection automatique lit désormais `/etc/ssh/sshd_config` correctement
- Correction : les ports TCP supérieurs à 32767 étaient classés comme éphémères à tort — seuls les ports UDP élevés sont éphémères ; les sockets TCP LISTEN sont toujours des sockets serveur
- 634/634 tests unitaires (15 nouveaux)

---

## v1.0

**2026-03-29**

- Packaging PyPI — `pipx install ufw-audit` devient la méthode d'installation recommandée
- `--install-completion` — installe l'autocomplétion bash + lien symbolique `/usr/local/bin/` pour le PATH sudo
- Correction : clé `services.exposure.not_listening` affichée brute dans la sortie
- `install.sh` déprécié ; Python 3.9 minimum ; matrice CI mise à jour (3.9/3.10/3.12)

---

## v0.22.1

**2026-03-29**

- Hotfix : UFW détecté comme inactif sur les systèmes en locale non-anglaise
- Cause : `LANGUAGE` surpasse `LC_ALL=C` dans gettext — maintenant vidé dans tous les appels subprocess

---

## v0.22

**2026-03-29**

- 5 modules refactorisés (`__main__`, `firewall`, `services`, `scoring`, `output`) — aucune nouvelle fonctionnalité
- Alignement des cadres corrigé sur toutes les interfaces (Unicode large + constante overhead incorrecte)
- `meta: dict` supprimé de `CheckResult` → `open_ports: List[str]` typé
- `FirewallStatus` met en cache la sortie subprocess — pas de double appel `ufw status`

---

## v0.21

**2026-03-28** — 619/619 tests

- 78 nouveaux tests + 3 corrections de bugs — passe qualité pré-v1.0
- Faux positif corrigé : CGNAT (`100.64/10`) et IPv6 privé classés `OPEN_WORLD` incorrectement
- Faux positif corrigé : lignes de config commentées matchées par le regex de détection de port
- `--manage-cron` : carnet d'adresses email (ajout/suppression/tout effacer)
- `--fix` / `--manage-logs` / `--install-cron` / `--manage-cron` désormais mutuellement exclusifs

---

## v0.20

**2026-03-28** — 548/548 tests

- 17 nouveaux tests en mode dégradé : `ss` absent, règles UFW vides, log manquant, dégradation combinée
- Pas de crash ni de fausses déductions quand les outils système sont indisponibles

---

## v0.19

**2026-03-28**

- CI GitHub Actions : pytest sur chaque push/PR
- Matrice Python 3.8 / 3.10 / 3.12 sur ubuntu-latest

---

## v0.18

**2026-03-28** — 531/531 tests

- 26 nouveaux tests pour `fixes.py` — `run_fixes()` entièrement couvert
- Classification des items, subprocess succès/échec/timeout, modes interactif et auto (`--yes`)

---

## v0.17

**2026-03-28** — 505/505 tests

- 15 échecs préexistants corrigés dans 6 fichiers — aucun changement fonctionnel à l'audit
- Correction : extraction de domaine DuckDNS (`?domains=` paramètre query)
- Correction : garde plage DOW dans `cron_to_human` (`1-5` ne prend plus le chemin weekday)

---

## v0.16

**2026-03-28**

- `Exposure.NOT_LISTENING` — port du registre sans listener actif → panorama ✔, aucun message (était ✖)
- `Exposure.LOOPBACK_NO_RULE` — port loopback sans règle UFW → panorama ✔, message INFO (était ✖)
- Suite de régression complète validée (C6 × 9 services, C8, E1) — zéro entrée `pending`

---

## v0.15.1

**2026-03-27**

- Install script : trap + rollback en cas d'échec partiel — installation partielle impossible
- Correction : règle open-any sans index `[N]` ne génère plus de commande de fix invalide
- Interface fix : la sortie subprocess UFW ne fuit plus dans le terminal

---

## v0.15

**2026-03-27**

- Audit sécurité complet — 8 corrections (permissions cron, traversée de chemins, injection HTML, bornes log)
- DRY : `checks/_run.py` + `_paths.py` partagés, code dupliqué supprimé dans 7 fichiers
- Correction : wildcards IPv6 (`Anywhere (v6)`) désormais détectés et supprimés par `--fix`
- 6 corrections dans le script d'installation

---

## v0.14.1

**2026-03-26**

- Faux positif corrigé : services liés au loopback (Redis sur `127.0.0.1`) n'alertent plus
- Faux positifs DDNS éliminés : ports système et règles orphelines filtrés
- `--remove-cron` réellement supprimé ; bannière VERSION corrigée

---

## v0.14

**2026-03-25**

- `__main__.py` réduit de ~1820 à ~481 lignes
- 5 nouveaux modules extraits : `display.py`, `fixes.py`, `manage_logs.py`, `panorama.py`, `sysinfo.py`
- `check_rules()` déplacé vers `checks/firewall.py`

---

## v0.13

**2026-03-24**

- Planificateur multi-cron : plusieurs jobs nommés (`/etc/cron.d/ufw-audit-{nom}`)
- Wizard de planification en 4 étapes (tous les jours / jours semaine / jours mois / expression custom)
- TUI `--manage-cron` : lister, modifier, supprimer les jobs
- Module `cron.py` isolé + 40+ tests unitaires

---

## v0.12

**2026-03-24**

- Rapports email incluent désormais une version HTML (MIME multipart) en plus du texte brut
- Convertisseur markdown→HTML sans dépendance (stdlib Python pure)
- Le script nightly cron génère et envoie des emails HTML automatiquement

---

## v0.11.4

**2026-03-23**

- Regex open-any corrigé : espaces trailing, variantes `/tcp`/`/udp`, doublons sémantiques détectés
- Services critiques/élevés exposés sur internet → *Action requise* (était *Améliorations possibles*)
- `TESTING.md` ajouté — premier plan de test de régression manuel formel

---

## v0.11.3

**2026-03-23**

- `--install-cron` : planifier des audits automatiques avec notification email optionnelle
- `--manage-logs` : interface interactive pour parcourir et supprimer les rapports sauvegardés
- Panorama des services : tableau compact des 22 services après chaque audit
- Auto-fix (`-y`) affiche une bannière d'avertissement + résumé des commandes exécutées

---

## v0.11.2

**2026-03-22**

- Bannière entièrement redessinée : "UFW-AUDIT" en ASCII art Doom, largeur 80 chars
- Messages d'exposition des ports réécrits pour être entièrement auto-explicatifs
- Tableau des ports déplacé en mode verbose (`-v`) uniquement

---

## v0.11.1

**2026-03-22**

- Patch sécurité : 20 vulnérabilités corrigées en 3 passes
- Injection shell, injection ANSI, traversée de chemins, attaques symlink, ReDoS, JSON bomb
- Permissions fichiers durcies : rapports `0o600`, répertoire config `0o700`

---

## v0.11

**2026-03-22**

- Tests terrain sur Mint 22.3, Debian 13, Kali Rolling — tous les bugs trouvés corrigés
- Mode `--quiet` avec codes de retour 0–3 pour scripting et cron
- Détection de virtualisation : libvirt/KVM, VirtualBox, VMware, LXD, paquets Snap réseau

---

## v0.10

- Géolocalisation GeoIP2 optionnelle (pays + opérateur), whois supprimé
- Options courtes CLI (`-v`, `-d`, `-f`, `-q`, `-n`)
- Note de périmètre du score ajoutée à la sortie

---

## v0.9

- Réécriture complète en Python (depuis bash)
- 421 tests unitaires
- Installateur transparent avec manifeste et rollback
- 22 services avec contexte de risque à deux axes (exposition + menace)
- Interface bilingue EN/FR
- Autocomplétion bash
