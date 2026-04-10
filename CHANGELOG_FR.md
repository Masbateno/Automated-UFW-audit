*[Read in English](CHANGELOG.md)* · *[Journal complet](DOCUMENTS/CHANGELOG_FULL_FR.md)*

# ufw-audit — Journal des modifications

| Version | Date | Résumé |
|---------|------|--------|
| [v1.12.0](#v1120) | 2026-04-10 | Refonte `--help` + 6 nouvelles options courtes + autocomplétion + 4 correctifs Debian VM ; 1703/1703 tests |
| [v1.11.0](#v1110) | 2026-04-07 | `--explain` A2 (+13 clés, 20→33) ; audit comptes utilisateurs (CHECK 17) ; audit politique de mots de passe (CHECK 18) ; passage qualité ; 1675/1675 tests |
| [v1.10.0](#v1100) | 2026-04-07 | Suggestion `--explain` dans le résumé ; audit modules noyau (CHECK 14) ; audit tâches cron (CHECK 15) ; audit état des services (CHECK 16) ; passage qualité (source + 9 fichiers de tests) ; 1541/1541 tests |
| [v1.9.0](#v190) | 2026-04-06 | Audit mises à jour système (CHECK 13) ; `--explain KEY` + refs CIS ; webhooks ; scores par domaine ; `--diff` ; 1332/1332 tests |
| [v1.8.0](#v180) | 2026-04-06 | Audit sécurité SSH (CHECK 11) ; fichiers sensibles & sudoers (CHECK 12) ; correctif i18n ; détail INFO en verbose ; 1104/1104 tests |
| [v1.7.0](#v170) | 2026-04-04 | Profils d'audit ; `Deduction.key` ; multi-email cron ; suppression multiple cron ; `--reset-baseline` ; filtre ports éphémères ; 966/966 tests |
| [v1.6.0](#v160) | 2026-04-04 | Vérification durcissement ; cohérence IPv6 ; rapport comparatif ; API plugin ; 926/926 tests |
| [v1.5.0](#v150) | 2026-04-04 | Analyse pile pare-feu ; Contexte réseau ; bannière enrichie ; passage qualité (12 modules renforcés) ; 766/766 tests |
| [v1.4.2](#v142) | 2026-04-04 | Hotfix : ports NetBIOS 137/138 encore signalés non couverts malgré une règle UFW existante |
| [v1.4.1](#v141) | 2026-04-04 | Hotfix : `--install-completion` absent des suggestions de complétion bash |
| [v1.4.0](#v140) | 2026-04-04 | Conscience de la politique deny par défaut ; `__main__.py` découpé en 4 modules ; passage hardening (11 correctifs) ; 676/676 tests |
| [v1.3.0](#v130) | 2026-03-31 | i18n complète (toutes les raisons de déduction traduites) ; mode `--offline` ; détection réseau IPv6 ; chaîne de fallback 3 providers |
| [v1.2.1](#v121) | 2026-03-31 | Nettoyage packaging : `install.sh` supprimé ; corrections `pyproject.toml` (LICENSE, classifier, URLs) |
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

## v1.12.0

**2026-04-10**

### Refonte `--help`

- 7 sections nommées : AUDIT / OUTPUT / FIXES / INTEGRATIONS / CONFIGURATION / MAINTENANCE / STANDALONE
- Section STANDALONE regroupe les commandes sans sudo (`--explain`, `--install-completion`, `--version`, `--help`)
- Section EXIT CODES clarifiée pour l'usage en scripts

### Nouvelles options courtes

| Court | Long | Usage |
|-------|------|-------|
| `-J`  | `--json-full` | Export JSON complet |
| `-C`  | `--manage-cron` | Gestion des tâches cron |
| `-e`  | `--explain CLÉ` | Expliquer une clé de résultat |
| `-D`  | `--diff` | Mode différentiel |
| `-w`  | `--webhook URL` | URL webhook |
| `-p`  | `--profile NOM` | Profil d'audit |

### Correctif autocomplétion

7 options absentes de la complétion bash : `--lang=`, `--profile=`, `--reset-baseline`, `--explain=`, `--diff`, `--webhook=`, `--webhook-format=`

Complétions intelligentes ajoutées : `--profile=` → server/workstation/container ; `--lang=` → en/fr ; `--webhook-format=` → auto/generic/slack

### Correctifs Debian VM

**Correctif #1 — Contexte de risque pour tous les services installés**
- Entrées `service_risk` ajoutées dans `en.json` + `fr.json` pour 11 services medium/faible : Apache, Nginx, Transmission, qBittorrent, Avahi, CUPS, Jellyfin, Plex, Gitea, Syncthing, Ollama
- `runner.py` + `display.py` : bloc contexte de risque affiché pour tous les services actifs

**Correctif #2 — GeoIP wget**
- Préfixe `sudo mkdir -p /usr/share/GeoIP &&` ajouté à la commande wget (`en.json`, `fr.json`, fallback `display.py`) — répertoire absent par défaut sur Debian

**Correctif #3 — `unattended-upgrades` selon le profil**
- `check_updates()` accepte le paramètre `profile_name`
- Profil `workstation` : risque composé (unattended absent + mises à jour de sécurité en attente) dégradé en INFO, pas de déduction −1 pt supplémentaire

**Correctif #4 — Comptes expirés avec dates**
- `expired_accounts` passe de `List[str]` à `Dict[str, str]` (utilisateur → date ISO d'expiration)
- Comptes système (UID < 1000) exclus de la vérification d'expiration
- Message du résultat inclut la date par compte : `alice (2023-06-15), bob (2022-01-01)`

### Tests

- 8 nouveaux tests dans `test_cli.py`
- 16 nouveaux tests : `TestWorkstationProfile` (5) dans `test_updates.py` ; assertions de dates + fixtures dict dans `test_user_accounts.py`
- **Total : 1703/1703**

---

## v1.11.0

**2026-04-07**

### `--explain` Phase A2 (20 → 33 clés)

- `EXPLAIN_KEYS` étendu de 20 à 33 clés ; groupées par catégorie dans le code
- Nouvelles clés SSH : `max_auth_tries`, `allow_tcp_forwarding`, `x11_forwarding`, `permit_user_env`, `ignore_rhosts_disabled`, `host_based_auth`, `strict_modes_disabled`, `client_strict_host_no`, `weak_ciphers`, `weak_macs`, `weak_kex`
- Nouvelle clé Hardening : `fail2ban_missing`
- Nouvelles clés Kernel modules : `risky_fs`, `risky_net`
- Nouvelles clés Cron / Services : `pipe_to_shell`, `enabled_inactive`
- Locales (`en.json`, `fr.json`) : titre / pourquoi / comment / ref CIS ajoutés pour les 13 nouvelles clés
- Test : `test_has_thirty_three_keys`, 13 nouvelles assertions de présence

### Audit comptes utilisateurs (CHECK 17)

- Nouveau module `checks/user_accounts.py` — `UserAccountsSnapshot` + `check_user_accounts()`
- Comptes avec UID 0 autre que root → ALERT, −3 pts (fixe) ; commande `passwd -l` sûre
- Mot de passe vide sur un compte avec shell de connexion → ALERT, −2 pts (fixe) ; lit `/etc/shadow` (root requis)
- Comptes avec date d'expiration passée → INFO, pas de déduction
- `/etc/shadow` illisible (non-root) → INFO, pas de déduction ; détection UID 0 fonctionne toujours
- Comptes `nologin`/`/bin/false` exclus de la vérification des mots de passe vides
- Déduplication `dict.fromkeys` sur toutes les listes ; snapshot jamais muté
- Domaine : `user_accounts` → `file_perms`
- Nouveau fichier de tests : `test_user_accounts.py` — 51 tests

### Audit politique de mots de passe (CHECK 18)

- Nouveau module `checks/password_policy.py` — `PasswordPolicySnapshot` + `check_password_policy()`
- Absence de module PAM qualité (`pam_pwquality` / `pam_cracklib`) → WARN, −1 pt
- `minlen < 8` explicite (quand le module EST configuré) → WARN, −1 pt
- `PASS_MAX_DAYS ≥ 365` → INFO seulement ; pas de déduction (NIST SP 800-63B ne l'impose plus)
- Structure `elif` : `no_quality_module` et `weak_minlen` mutuellement exclusifs
- `pwquality.conf` a priorité sur l'option `minlen=` inline PAM
- Domaine : `password_policy` → `hardening`
- Nouveau fichier de tests : `test_password_policy.py` — 51 tests

### Passage qualité

- `test_user_accounts.py` : `test_no_shadow_info_absent_when_readable`, 3 tests d'immutabilité du snapshot, `test_no_t_does_not_crash`
- `test_password_policy.py` : `test_minlen_7_flagged`, `test_login_defs_unreadable_no_crash`, `test_pass_min_days_ignored`, `test_no_t_does_not_crash`, `test_pam_cracklib_ok_finding`

---

## v1.10.0

**2026-04-07**

### Suggestion `--explain` dans le résumé (Phase A1)

- Chaque finding actionnable affiche désormais `? ufw-audit --explain <clé>` si la clé est dans `EXPLAIN_KEYS`
- Utilise `normalize_key()` — `file_perms.shadow.world_writable` → `file_perms.world_writable`
- Nouveau fichier de tests : `test_display_explain_hint.py` — 25 tests

### Audit des modules noyau (CHECK 14)

- Nouveau module `checks/kernel_modules.py` — `KernelModulesSnapshot` + `check_kernel_modules()`
- Modules FS risqués : cramfs, freevxfs, jffs2, hfs, hfsplus, squashfs, udf, usb_storage → WARN, −1 pt (flat)
- Modules réseau risqués : dccp, sctp, rds, tipc → WARN, −1 pt (flat)
- Max −2 pts ; cmd : `sudo modprobe -r <modules>` (sécurisé via `shlex.quote`)
- `lsmod` indisponible → INFO, aucune déduction
- Nouveau fichier de tests : `test_kernel_modules.py` — 48 tests

### Audit des tâches cron (CHECK 15)

- Nouveau module `checks/cron_audit.py` — `CronAuditSnapshot` + `check_cron_audit()`
- `curl/wget … | sh/bash/zsh/…` dans tout fichier cron système → WARN, −2 pts (flat) ; regex couvre `/bin/sh`, `zsh`, `/usr/bin/bash -s`
- Script `.sh` accessible en écriture référencé dans cron → WARN, −1 pt ; cmd : `sudo chmod o-w <scripts>` (sécurisé)
- `/etc/cron.d` parsé en format crontab (chemins extraits) ; `cron.daily/hourly/weekly/monthly` examinés directement
- Crontabs d'utilisateurs inattendus dans `/var/spool/cron/crontabs/` → INFO, aucune déduction
- Max −3 pts
- Nouveau fichier de tests : `test_cron_audit.py` — 47 tests

### Audit de l'état des services (CHECK 16)

- Nouveau module `checks/services_state.py` — `ServicesStateSnapshot` + `check_services_state()`
- Requête `systemctl` en deux étapes : `list-unit-files` (état activé) + `list-units --all` (état actif) — ne signale que les services activés+inactifs
- Services surveillés : ufw, fail2ban, apparmor, auditd, clamav-daemon, clamav-freshclam, ssh, sshd, crowdsec, ossec
- Activé au boot mais inactif/en échec → WARN par service, −1 pt (plafonné à −3)
- `systemctl` indisponible → INFO, aucune déduction
- Nouveau fichier de tests : `test_services_state.py` — 35 tests

### Passage qualité

- `firewall.py` : `key=` ajouté à tous les findings de `_check_duplicates`, `_check_open_any`, `_check_ipv6_coverage`
- `test_check_rules.py` (19→29) : assertions par clé, classes `TestOpenAny`/`TestDuplicates`/`TestIPv6Coverage`/`TestCombined`
- `test_cli.py` (25→63) : tous les flags/défauts/combinaisons couverts ; classes `TestWebhook` et `TestExplain`
- `test_compare.py` (47→54) : `SimpleNamespace` pour les objets de données, `_make_delta` au niveau module, `skipif` Windows
- `test_cron.py` (52→62) : `TestOrdinal` paramétrisé, jours de la semaine FR, `_parse_dom("")`
- `test_ddns.py` (37→42) : hostname entre guillemets, valeur vide, regex de repli, règle malformée
- `test_degraded.py` (17→20) : vrai `LogEntry`, combinaisons pare-feu inactif + ports/règles vides

### Scores par domaine

- `kernel_modules`, `cron_audit`, `services_state` mappés au domaine `hardening`

---

## v1.9.0

**2026-04-06**

### Audit mises à jour système (CHECK 13)

- Nouveau module `checks/updates.py` — `UpdatesSnapshot` + `check_updates()`
- Détecte les paquets de sécurité en attente via `apt-get -s upgrade` + correspondance suite `-security`
- Détecte les mises à jour régulières en attente (informatif)
- Détecte l'installation et la configuration de `unattended-upgrades` (apt-conf + timer systemd)
- Scoring : sécurité en attente → −2 pts (fixe, indépendant du nombre) ; `unattended-upgrades` absent + sécurité en attente → −1 pt supplémentaire (risque composé)
- Déduplication des noms de paquets ; gestion défensive de listes `None`

### `--explain KEY`

- Nouveau module `explain.py` — `normalize_key()` + `run_explain()`
- Affiche une explication structurée par constat : titre, POURQUOI C'EST UN RISQUE, COMMENT CORRIGER, référence CIS Ubuntu 22.04
- 20 clés explicables sur tous les domaines (SSH ×11, file_perms ×4, updates ×2, hardening ×2)
- `--explain list` — liste toutes les clés avec leurs titres traduits
- Normalisation des clés : supprime les segments intermédiaires `file_perms.*` (regex gère l'imbrication profonde)
- Références CIS stockées dans la section locale `explain_cis` (EN + FR)
- Ne nécessite pas les droits root

### Webhooks (`--webhook`)

- Nouveau module `webhook.py` — `build_generic_payload()`, `build_slack_payload()`, `send_webhook()`
- Payload générique : Grafana / récepteurs HTTP personnalisés ; inclut `domain_scores`
- Payload Slack : auto-détecté par URL, colorisé (rouge/orange/vert)
- `--webhook-format=auto|generic|slack` — forcer le format
- Non-fatal : les erreurs s'affichent sur stderr, le code de sortie n'est pas affecté
- `--offline` supprime l'appel webhook ; stdlib uniquement (`urllib.request`)
- Persistance : `get/set_webhook_url()`, `get/set_webhook_format()` dans `UserConfig`

### Scores par domaine

- Nouveau module `domain_scores.py` — `compute_domain_scores()` + `render_domain_scores()`
- Cinq domaines : SSH, Fichiers & Accès, Mises à jour, Durcissement, Pare-feu & Services
- Chaque domaine scoré indépendamment : `max(0, min(10, 10 − déductions_domaine))`
- Affiché en terminal après le résumé d'audit (barre █/░)
- Inclus dans `--json`, `--json-full` et le payload webhook générique

### Mode `--diff`

- Lance l'audit silencieusement, affiche uniquement le delta comparatif (changements depuis le dernier audit)
- Compatible avec `--verbose`

### Tests

- `test_updates.py` — 34 tests
- `test_explain.py` — ~94 tests : normalize_key, EXPLAIN_KEYS, run_explain, parsing CLI
- `test_domain_scores.py` — ~48 tests : attribution déductions, plancher/plafond, rendu, CIS, structure JSON/webhook
- `test_webhook.py` — ~54 tests : détection URL, formats, payloads, mocking HTTP, persistance config, parsing CLI
- 1332/1332 (+228)

---

## v1.8.0

**2026-04-06**

### Audit sécurité SSH (CHECK 11)

- Nouveau module `checks/ssh.py` — analyse complète `sshd_config` (15 directives + crypto faible), audit des clés privées, `authorized_keys`, `~/.ssh/config`, `known_hosts`
- Cible le répertoire home de `SUDO_USER` ; suggestions d'installation adaptées à la distro
- 93 nouveaux tests dans `tests/test_ssh.py`

### Fichiers sensibles & sudoers (CHECK 12)

- Nouveau module `checks/file_perms.py` — fichiers sensibles accessibles en écriture globale / trop permissifs, permissions clés hôtes SSH, détection `NOPASSWD:ALL` sudoers
- 45 nouveaux tests dans `tests/test_file_perms.py`

### i18n / affichage

- Clé `output.recommendation_label` ajoutée (EN/FR) — corrige le français codé en dur dans toutes les locales
- Les constats INFO affichent maintenant le texte `detail` en mode verbose (`-v`)

### Tests

- 1104/1104 (+138)

---

## v1.7.0

**2026-04-04**

### Profils d'audit

- Profils nommés (`server`, `workstation`, `container`) livrés sous forme de fichiers `.conf` dans `ufw_audit/data/profiles/`
- Option `--profile=NAME` — sélectionne un profil ; persiste entre les exécutions dans `~/.config/ufw-audit/config.conf`
- Format de fichier INI : `[profile]` nom/extends/description ; `[overrides]` clé=niveau ; `[skip_sections]` noms de section
- Héritage via `extends` avec garde de profondeur (`_MAX_EXTENDS_DEPTH = 8`) — empêche les cycles
- Niveaux d'override : `info | warn | alert | skip`
- Profils personnalisés : déposer un fichier `.conf` dans `~/.config/ufw-audit/profiles/` — priorité sur les profils intégrés
- `apply_profile()` est post-vérification — les fonctions de vérification existantes et futures n'ont pas besoin d'être modifiées

### Clés de déduction (`Deduction.key`)

- `Deduction.key: str = ""` ajouté au dataclass `Deduction` — clé i18n stable liant chaque déduction à son constat
- Paramètre `add_deduction(key=)` ajouté dans `CheckResult`
- Toutes les déductions scorées dans `hardening.py` et `ipv6.py` portent un `key=` correspondant
- `_remove_deductions_for_key()` simplifié en `d.key != key` — déterministe, sans heuristique sur les chaînes traduites
- `_find_profile_file()` mis en cache via `@lru_cache(maxsize=32)` — les chaînes `extends` profondes ne lisquent le disque qu'une fois
- Les clés d'override dans les fichiers de profil sont normalisées (`strip().lower()`) — tolère les majuscules

### `--install-cron` — emails de notification multiples

- `prompt_emails()` remplace `prompt_email()` — demande "Ajouter une autre adresse ? [o/N]" après chaque sélection
- Les adresses déjà sélectionnées sont marquées ✔ pour éviter les doublons
- Toutes les adresses choisies sont stockées en CSV dans le fichier cron et le script
- Le script bash boucle sur les destinataires : `IFS="," read -ra _ADDRS` — chaque adresse reçoit son propre email

### `--manage-cron` — suppression multiple

- `d:1,3` — supprime les crons 1 et 3 (liste)
- `d:1-3` — supprime les crons 1 à 3 (plage)
- `d:all` — supprime tous les crons installés (message de confirmation dédié)
- La suppression unitaire (`d:N`) est inchangée ; le message de confirmation s'adapte à la sélection

### Rapport comparatif — filtre des ports éphémères

- `build_baseline()` exclut désormais les ports éphémères (≥ 32768) — supprime les faux positifs « nouveau port » d'Avahi, libvirt, VPN et autres sockets UDP transitoires
- `--reset-baseline` — supprime `~/.config/ufw-audit/last_baseline.json` et quitte proprement (utile lors d'un changement de profil ou d'une modification majeure du système)

### Note de migration

Si vous mettez à jour depuis v1.6.0, exécutez `sudo ufw-audit --reset-baseline` une fois pour supprimer l'ancienne baseline (qui peut contenir des ports éphémères). Le prochain audit créera automatiquement une baseline propre.

---

## v1.6.0

**2026-04-04** — 928/928 tests

### Nouvelles sections

- **DURCISSEMENT** (`checks/hardening.py`) — unattended-upgrades, rp_filter, acceptation des redirections ICMP, fail2ban, AppArmor, log_martians, broadcast ICMP
- **COHÉRENCE IPv6** (`checks/ipv6.py`) — croise l'activation noyau IPv6 avec le paramètre UFW IPv6 et les listeners IPv6 actifs

### Rapport comparatif

- `compare.py` — dataclasses `AuditBaseline` + `AuditDelta` ; `build_baseline()`, `save_baseline()`, `load_baseline()`, `compute_delta()`, `display_delta()`
- Baseline sauvegardée dans `~/.config/ufw-audit/last_baseline.json` après chaque audit
- Affiche le delta de score, d'alertes/avertissements, les ports nouveaux/fermés, les services démarrés/arrêtés

### API plugin

- `plugin_checks.py` — fonctions de vérification tierces découvertes via le groupe d'entry-points `ufw_audit.checks`
- Isolation des plugins : les erreurs d'import passent le plugin avec un avertissement au lieu de crasher l'audit
- Désinfection ANSI des noms de check plugin (`_sanitize_check_name()`)

### Sortie JSON

- Objets `hardening_snapshot` et `ipv6_snapshot` ajoutés à la sortie `--json-full`

---

## v1.5.0

**2026-04-04** — 766/766 tests

### Nouvelles sections

- **ANALYSE DE LA PILE PARE-FEU** (`checks/firewall_stack.py`) — détecte les règles iptables ACCEPT brutes contournant UFW dans la chaîne INPUT ; règles ACCEPT dans FORWARD (supprimées si Docker/WireGuard/libvirt sont détectés) ; tables nftables parallèles à UFW (tables de compatibilité iptables-nft exclues) ; ip_forward activé sans démon de routage (Docker, WireGuard ou libvirt/KVM)
- **CONTEXTE RÉSEAU** (`checks/network_context.py`) — tableau des interfaces (nom, type, ACTIF/INACTIF, adresse IPv4) ; nombre de connexions TCP établies + top IP distantes ; WARN si connexion établie vers un hôte externe sur un port sensible (MySQL, PostgreSQL, Redis, MongoDB, CouchDB)

### Bannière enrichie

- Version du noyau, version iptables + backend (`nf_tables` / `legacy`), version nftables affichées au démarrage
- `"non installé"` affiché si iptables ou nftables est absent

### Sortie JSON (`--json-full`)

- Objet `"firewall_stack"` : `input_bypasses`, `forward_bypasses`, `nftables_active`, `ip_forward`, flags démons de routage
- Objet `"network_context"` : liste `interfaces`, `connections_count`, `top_remote_ips`

### Tests

- `tests/test_firewall_stack.py` — 38 tests (nouveau fichier)
- `tests/test_network_context.py` — 51 tests (nouveau fichier)
- `tests/test_report.py` — fixture mise à jour pour `iptables_version` / `nftables_version`

### Passage qualité (12 modules — aucun changement de comportement sur un audit propre)

- **`report_markdown.py`** — Correction XSS : `_safe_url()` rejette les URLs non-`http(s)` ; cohérence des horodatages via `created_at` ; normalisation des colonnes de tableau ; extension `.md`
- **`registry.py`** — Validation de la plage de ports (1–65535) ; garde contre les mots-clés Python dans `config_key` ; typage de `__iter__`
- **`cli.py`** — `--lang=CODE` généralise `--french` ; conflit `--quiet`+`--json` ; conflit `--json`+`--fix` ; `--log-days` plafonné à 3650 ; import `field` inutilisé supprimé
- **`config.py`** — Écriture atomique (`.tmp` + `replace()`) pour `UserConfig` et `EmailStore` ; validation email (regex stricte) ; `set()` rejette les clés invalides
- **`cron.py`** — Regex email renforcé ; chemin de script cron supporte les espaces ; `_validate_custom_cron()` vérifie les plages minute (0–59) et heure (0–23)
- **`fixes.py`** — Les corrections manuelles sont désormais affichées après les auto-fixes ; regex de suppression UFW ancrée ; garde contre les opérateurs shell ; clé locale `done_summary`
- **`i18n.py`** — Fallback par clé vers l'anglais si la clé FR est absente ; validation du type racine JSON ; garde de profondeur de clé (max 10) ; `_load_locale()` extrait ; log reflète la langue réellement chargée
- **`manage_logs.py`** — La suppression `"all"` demande une confirmation `[y/N]`
- **`panorama.py`** — `PanoramaRow TypedDict` ; gardes défensives `state`/`exposures` ; normalisation lowercase de `risk`
- **`completion.py`** — Garde `src.exists()` avant la copie ; messages distincts selon la cause d'échec
- **`_paths.py`** — `.strip()` sur la variable d'environnement ; `resolve(strict=True)`
- **`pyproject.toml`** — README avec `content-type = "text/markdown"` explicite ; classifier Python 3.11 ajouté

---

## v1.4.2

**2026-04-04**

- Correctif : ports NetBIOS 137/138 encore signalés comme non couverts même lorsqu'une règle UFW explicite existe — la vérification de couverture UFW était évaluée après la branche NetBIOS au lieu d'avant

---

## v1.4.1

**2026-04-04**

- Correctif : `--install-completion` était absent des suggestions de complétion bash

---

## v1.4.0

**2026-04-04**

- Fonctionnalité : système de plugins `services.d` — déposer des fichiers JSON dans `~/.config/ufw-audit/services.d/` pour définir des services personnalisés chargés aux côtés des définitions intégrées
- Fonctionnalité : conscience de la politique deny par défaut — `check_ports()` accepte `default_incoming_policy` ; les ports publics non couverts sont rétrogradés en INFO si la politique UFW est `deny` ou `reject`
- Refactorisation : `__main__.py` découpé en 4 modules — `completion.py` (`--install-completion`), `runner.py` (pipeline des 8 vérifications), `json_output.py` (sérialisation JSON) ; `__main__.py` est désormais un pur orchestrateur (~160 lignes)
- Refactorisation : `run_checks()` retourne un `ChecksResult` NamedTuple typé au lieu d'un `tuple` nu
- Correctif : `__main__.py` — `CLIError` retourne maintenant `EXIT_ERROR (3)` au lieu de `1` (conflit avec `EXIT_WARNINGS`) ; `try/finally` garantit la restauration de `sys.stdout` et la fermeture de `_devnull` même en cas d'exception
- Correctif : `firewall.py` — booléen `found_duplicate` remplace l'heuristique fragile `startswith[:20]` pour la détection de règles dupliquées
- Correctif : `logs.py` — correction de la borne d'année pour les timestamps syslog (un log de décembre analysé en janvier n'est plus daté dans le futur) ; suppression de l'exclusion `is_symlink()` pour les bases GeoIP2 `.mmdb` (liens symboliques valides sur Debian/Ubuntu via `update-alternatives`)
- Correctif : `_run.py` — `_is_safe_config_path()` centralisée (était dupliquée dans `ddns.py` et `services.py`)
- Correctif : `cron.py` — `read_text(encoding="utf-8")` ; borne de plage `min(end, start+999)` contre les abus mémoire ; regex NOTIFY_EMAIL accepte guillemets simples et doubles
- Correctif : `json_output.py` — timestamp UTC (`timezone.utc`) ; paramètres typés (`SystemInfo`, `list[ServiceSnapshot]`) ; champ `schema_version: "1"` ajouté
- Correctif : `completion.py` — garde contre l'absence de `/etc/bash_completion.d/` ; refus d'écraser un vrai binaire à la destination du lien symbolique
- 676/676 tests unitaires (+24 depuis v1.3.0)

---

## v1.3.0

**2026-03-31**

- Fonctionnalité : toutes les chaînes `Deduction.reason` passent désormais par `t()` — breakdown du score entièrement traduit EN et FR (zéro chaîne codée en dur)
- Fonctionnalité : flag `--offline` / `-o` — désactive tous les appels HTTP externes (pas de résolution d'IP publique) ; utile sur les machines isolées ou derrière un pare-feu sortant strict
- Fonctionnalité : `get_public_ip()` essaie 3 providers dans l'ordre (`api.ipify.org` → `ifconfig.me/ip` → `icanhazip.com`) avant de retourner `""`
- Fonctionnalité : `detect_network_context()` détecte désormais les adresses IPv6 publiques (`inet6` sur les interfaces, en excluant `::1`, `fe80::`, ULA `fc`/`fd`)
- 652/652 tests unitaires (11 nouveaux dans `tests/test_sysinfo.py`)

---

## v1.2.1

**2026-03-31**

- Suppression : `install.sh` définitivement supprimé — déprécié depuis v1.0, `pipx install ufw-audit` est la méthode canonique
- Correction : `pyproject.toml` — `license-files = ["LICENSE"]` (était `[]`) ; ajout du classifier `Python :: 3 :: Only` ; remplacement de l'URL `Repository` dupliquée par `Issues`

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
