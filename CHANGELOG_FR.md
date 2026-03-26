*[Read in English](CHANGELOG.md)*

# UFW-audit — Journal des modifications

Toutes les modifications notables du projet sont documentées ici.

---

## [v0.15] — en cours (beta)

### Durcissement sécurité — audit complet du code

Revue de sécurité et de qualité complète sur l'ensemble des modules. Aucune vulnérabilité de haute sévérité trouvée. Cinq problèmes de sévérité moyenne et trois de faible sévérité corrigés.

#### Corrections

- **`fixes.py` (M1)** — `subprocess.run()` appelé sans `timeout` ; ajout de `timeout=30` et de `subprocess.TimeoutExpired` dans les exceptions attrapées. Empêche un blocage indéfini si une commande UFW se fige.
- **`i18n.py` (M2)** — La validation du chemin `UFW_AUDIT_SHARE` utilisait `is_symlink()` uniquement sur le composant final, manquant les liens symboliques intermédiaires. Remplacé par `Path.resolve()` qui suit toute la chaîne de liens symboliques.
- **`registry.py` (M3)** — Même vulnérabilité de chaîne de liens symboliques que `i18n.py`. Même correctif : `Path.resolve()`.
- **`manage_logs.py` (M4)** — `prompt_path()` retournait le chemin brut fourni par l'utilisateur sans normalisation. Ajout de `.resolve()` pour développer et canonicaliser le chemin, neutralisant les séquences de traversée `..`.
- **`cron.py` (M5)** — Les fichiers cron dans `/etc/cron.d/` étaient créés avec `0o644` (lisibles par tous), exposant l'adresse email de notification à tous les utilisateurs du système. Changé en `0o640` (lecture réservée à root et au groupe).
- **`cron.py` (L1)** — Les variables écrites dans le script bash généré (`NOTIFY_EMAIL`, `LOG_DIR`, préfixe `PYTHONPATH`, chemin du binaire) étaient intégrées avec des guillemets doubles. Remplacé par `shlex.quote()` pour un échappement shell correct de toutes les valeurs.
- **`display.py` (L2)** — Les nombres magiques `48` et `44` (largeurs de troncature des messages dans le récapitulatif) extraits vers des constantes de module `_SUMMARY_MSG_LEN` et `_SUMMARY_REASON_LEN`.
- **`report_markdown.py` (L3)** — `except Exception` nu dans la fonction d'envoi d'email remplacé par des types spécifiques : `(OSError, subprocess.TimeoutExpired, ValueError)`.

---

## [v0.14.1] — 2026-03-26

### Corrections de bugs (corrections post-sortie)

- **Faux positif ALERT — services liés au loopback** : un service écoutant exclusivement sur `127.0.0.1` (ex. Redis sur `6379/tcp`) était incorrectement signalé comme *"exposé sur internet"* lorsqu'une règle UFW ouverte existait pour ce port. `PortsSnapshot` est désormais collecté avant le CHECK 3 ; les ports dont tous les bindings `ss` sont sur loopback reçoivent `Exposure.LOOPBACK` (INFO, sans déduction) au lieu de `OPEN_WORLD`.
- **Faux positifs DDNS** : les ports système (`53`, DHCP, mDNS) et les ports exclusivement loopback apparaissaient dans la liste d'exposition DDNS. Ajout du filtre `_DDNS_SYSTEM_PORTS` et vérification croisée avec les listeners non-loopback réels — les règles UFW orphelines (aucun service actif) et les règles bare (sans `/proto`) ne génèrent plus d'entrées fantômes.
- **`--remove-cron` non supprimé à la sortie** : le flag était marqué déprécié *"sera supprimé en v0.14"* mais n'avait jamais été retiré. Supprimé de `cli.py`, `__main__.py`, `cron.py`, `locales/en.json`, `locales/fr.json` et `ufw-audit.bash-completion`.
- **Bannière VERSION** : la bannière affichait encore `v0.13.0b` après la sortie de la v0.14. Corrigé.

---

## [v0.14] — 2026-03-25

### Refactoring — Modularisation de `__main__.py`

`__main__.py` réduit de ~1820 à ~481 lignes. Toute la logique métier et le code d'affichage extraits dans des modules dédiés. Le fichier est désormais un orchestrateur pur.

#### Nouveaux modules

| Module | Contenu |
|---|---|
| `panorama.py` | `build_panorama_rows()` — construction du tableau panorama des services |
| `sysinfo.py` | `collect_system_info()`, `detect_network_context()`, `get_user_home()` |
| `manage_logs.py` | `run_manage_logs()`, `get_or_prompt_log_dir()`, `prompt_path()` |
| `fixes.py` | `run_fixes()` — interface du mode fix (interactif et auto-fix) |
| `display.py` | `display_result()`, `display_risk_context()`, `check_single_service_display()`, `display_log_results()`, `print_audit_summary()`, `build_risk_context_entries()` |

#### Déplacé

- `check_rules()` — déplacé de `__main__.py` vers `ufw_audit/checks/firewall.py` (aux côtés de `check_firewall()`)

#### Code mort supprimé

- Variable globale `_QUIET` — remplacée par le paramètre explicite `quiet` dans `display_result()`
- Fonction helper `_out()` — définie mais jamais appelée

#### Installeur

- `install.sh` mis à jour : `display.py`, `fixes.py`, `manage_logs.py`, `panorama.py`, `sysinfo.py` ajoutés à la liste de copie des modules

### Documentation

- `AUTOMATION_EN.md` renommé en `AUTOMATION.md` (l'anglais est la langue par défaut)
- `AUTOMATION.md` (français) renommé en `AUTOMATION_FR.md`
- Liens de basculement de langue ajoutés dans `CHANGELOG`, `TESTING` et `AUTOMATION`

---

## [v0.13] — 2026-03-24

### Nouvelles fonctionnalités — Planificateur multi-cron

- **Assistant de planification** — `--install-cron` lance désormais un wizard guidé en 4 étapes :
  1. **Nom** — libellé libre pour le cron (slug généré automatiquement, suggestion fournie)
  2. **Type de planification** — choix parmi : tous les jours / certains jours de la semaine / certains jours du mois / expression cron personnalisée
  3. **Heure** — saisie `HH:MM` (ignorée pour les expressions personnalisées) ; défaut `03:00`
  4. **Email** — adresse de notification optionnelle (inchangé depuis v0.12)
  - Aperçu du planning en langage naturel avant confirmation (ex : *tous les lundi, mercredi, vendredi à 02:30*)
  - Le mode expression personnalisée accepte toute expression cron valide en 5 champs
- **Crons nommés** — chaque tâche est identifiée par un nom ; les fichiers sont créés sous `/etc/cron.d/ufw-audit-{nom}` et `/usr/local/bin/ufw-audit-{nom}` ; les fichiers cron incluent des métadonnées en commentaires (`# name:`, `# email:`) pour une identification fiable
- **`--manage-cron`** — nouveau TUI de gestion interactif (même schéma que `--manage-logs`) :
  - Liste tous les crons installés avec nom, planning en langage naturel et email
  - Entrer un numéro pour modifier le planning d'un cron existant (relance le wizard de planification)
  - `d:N` pour supprimer un cron et son script associé
- **`--remove-cron` mis à jour** — liste maintenant tous les crons installés et exige une sélection explicite par numéro avant suppression ; plus de suppression implicite
- **Compatibilité legacy** — les crons créés par v0.12 (`/etc/cron.d/ufw-audit`) sont détectés et gérables via `--manage-cron` et `--remove-cron`

### Internals

- `ufw_audit/cron.py` ajouté — logique cron isolée : dataclass `CronEntry`, `list_installed_crons()`, `parse_cron_file()`, `build_schedule_expr()`, `cron_to_human()` (EN/FR), `make_slug()`, `suggest_name()`
- `_run_install_cron()` refactorisé — le wizard remplace la simple saisie heure/email ; les chemins sont maintenant dynamiques selon le slug
- `_run_manage_cron()` et `_edit_cron_schedule()` ajoutés dans `__main__.py`
- `_run_remove_cron()` mis à jour — utilise `list_installed_crons()` au lieu d'un chemin codé en dur
- Flag `manage_cron` ajouté à `AuditConfig` / `cli.py`
- Nouvelles clés de localisation : `install_cron.prompt_name`, `install_cron.prompt_schedule`, `install_cron.schedule_*`, `install_cron.preview`, `manage_cron.*`, `remove_cron.none_found`, `remove_cron.prompt`, `remove_cron.invalid`
- `install.sh` mis à jour : `cron.py` et `report_markdown.py` (absents depuis v0.12) ajoutés à la liste de copie des modules ; VERSION mise à jour à `0.13`

### Corrections de bugs

- `__file__` est `None` sur `ufw_audit.__init__` sous Python 3.12+ lorsque `__init__.py` est vide — `_run_install_cron()` utilise maintenant `Path(__file__)` depuis `__main__.py` pour résoudre `PYTHONPATH`, qui est toujours défini

### Tests

- `tests/test_cron.py` ajouté — 40+ tests unitaires couvrant `build_schedule_expr()`, `cron_to_human()` (EN/FR, tous les types de planification), `make_slug()`, `suggest_name()`, `parse_cron_file()` (métadonnées v0.13, legacy, cas limites), et les helpers internes

---

## [v0.12.0] — 2026-03-24

### Nouvelles fonctionnalités — Rapports par email

- **Génération de rapports Markdown** — nouvelle classe `MarkdownReport` produisant des rapports natifs Markdown optimisés pour la livraison par email (remplace les boîtes ASCII par des en-têtes Markdown propres)
- **Conversion HTML sans dépendances** — convertisseur pur Python markdown → HTML (aucune bibliothèque externe) ; produit du HTML valide et stylisé adapté aux clients de messagerie
- **Email MIME multipart** — les emails envoyés par le script cron incluent maintenant les versions texte brut (compatible spam filter) et HTML (rendu visuel) ; utilise la commande système `mail`
- **Rendu HTML pour email** — les rapports d'audit texte brut hérités convertis en HTML lisible pour les notifications cron ; bordures UTF-8 supprimées, résultats stylisés avec horodatages et couleurs
- **Intégration du script nightly** — `--install-cron` génère un script bash qui convertit les journaux d'audit en HTML et envoie des emails multipart ; pas de changements visibles dans l'UX cron

### Internals

- `ufw_audit/report_markdown.py` ajouté — module de 750+ lignes avec `MarkdownReport`, `markdown_to_html()`, `send_html_email()`, `send_audit_log_as_html_email()` helpers
- `_run_install_cron()` mis à jour — le script nightly utilise maintenant un heredoc Python pour appeler la conversion email Markdown
- `write_services_panorama()` ajoutée à `MarkdownReport` — prête pour l'intégration future de la table services dans les rapports email

### Tests

- L'API `MarkdownReport` et la conversion HTML validées avec tables Markdown, en-têtes et échantillons d'audit texte brut
- Génération de script bash vérifiée

---

## [v0.11.4] — 2026-03-23

### Corrections de bugs — Détection des règles UFW

- **Espaces de fin « open-any »** — `ufw status numbered` remplit les lignes de règles avec des espaces de fin ; l'ancre `$` dans la regex « open-any » ne correspondait jamais à `Anywhere ALLOW IN Anywhere`. Corrigé : `Anywhere$` → `Anywhere\s*$`
- **Variantes `/tcp` et `/udp` « open-any »** — `Anywhere/tcp ALLOW IN Anywhere/tcp` et `Anywhere/udp ALLOW IN Anywhere/udp` (tous les ports, restreints par protocole) n'étaient pas détectés. Motif étendu : `Anywhere(?:/\w+)?` des deux côtés couvre maintenant les trois formes de wildcards
- **Détection sémantique des doublons** — les règles `PORT/proto` (p. ex. `80/tcp`) sont maintenant signalées comme redondantes quand une règle sans protocole pour le même port (`80`) existe déjà avec la même action et source. Détection en deux passes : première passe collecte toutes les règles sans proto ; deuxième passe confronte chaque règle spécifique au protocole à cet ensemble
- **Suppression des commentaires dans la vérification des doublons** — la comparaison de règles supprime maintenant les commentaires en ligne (`# label`) et normalise les espaces avant la comparaison ; `80/tcp # test2` et `80/tcp` sont traités comme la même règle
- **Affichage du chemin de config des doublons** — un `print()` égaré dans `_print_summary()` affichait le chemin de config une deuxième fois à la fin du résumé, avec un chemin reconstitué à partir de `_get_user_home()` différent du chemin effectif affiché au démarrage. Supprimé

### Corrections de bugs — Exposition des services et DDNS

- **Services critiques/élevés → Alerte au lieu d'Avertissement** — les services avec `risk: critical` ou `risk: high` exposés à internet (`OPEN_WORLD`) lèvent maintenant `alert()` avec `nature="action"`, les plaçant dans le bloc *Action requise* du résumé. Auparavant tous les services exposés utilisaient `warn()` indépendamment du niveau de risque, enfouissant les résultats critiques comme Redis ou SSH dans *Améliorations possibles*
- **Vérification croisée DDNS rate les règles sans protocole** — `_find_open_ports()` correspondait uniquement au format `PORT/proto` (p. ex. `80/tcp`) ; les règles de port nu comme `80 ALLOW IN Anywhere` (couvrant tcp et udp) n'étaient pas détectées. Ajoute maintenant `PORT/tcp` et `PORT/udp` quand une règle de port nu est trouvée

### Tests

- `tests/test_check_rules.py` ajouté — couvre la détection « open-any » (régression espaces de fin, variantes `/tcp`, `/udp`), détection des doublons (exacte, espaces de fin supprimés, TCP/UDP sémantique), cohérence IPv6, et protection contre les faux positifs pour les règles complémentaires `PORT/tcp` + `PORT/udp`
- `TESTING.md` ajouté — planification des tests de régression manuels avec résultats de VM en direct pour les catégories A (wildcards), B (doublons), C (exposition services), D (IPv6), plus observations documentées et comportement connu

---

## [v0.11.3] — 2026-03-23

### Nouvelles fonctionnalités

- **Invite d'emplacement des logs** — le premier exécution de `-d` demande où stocker les rapports ; le chemin est enregistré dans `config.conf` et réutilisé automatiquement aux exécutions suivantes
- **`--manage-logs`** — interface interactive autonome : liste les rapports enregistrés (nom, taille, date), supprime par index ou tout d'un coup
- **`--install-cron`** — configuration cron interactive : demande l'heure d'exécution et l'email de notification optionnel ; génère le script wrapper `/usr/local/bin/ufw-audit-nightly` et l'entry `/etc/cron.d/ufw-audit` ; notification envoyée via système `mail` uniquement quand l'audit détecte avertissements/alertes (code sortie > 0)
- **Panorama des services** — nouvelle section après l'audit services montrant les 22 services connus dans une table compacte (SERVICE / STATUT / PORT(S) / UFW), indépendamment du statut d'installation ; services non installés affichés atténués
- **En-tête ASCII art dans fichiers `.log`** — les fichiers rapport s'ouvrent maintenant avec une boîte de 62 caractères contenant « UFW-AU » en ASCII Doom + ligne version/host/user, remplaçant l'en-tête texte brut

### Améliorations UX

- **`-y / --yes` auditable** — le mode auto-fix affiche maintenant un bandeau `⚠ MODE AUTO-FIX` avant appliquer les corrections, et imprime un résumé de chaque commande appliquée à la fin
- **`AUTOMATION.md`** ajouté — documentation complète pour configuration cron, email, et gestion des logs

### Internals

- `ServiceSnapshot.collect_all()` ajouté — variante de `collect()` incluant les services non installés (utilisé par le panorama)
- `print_services_panorama()` ajouté à `output.py`
- `_get_or_prompt_log_dir()`, `_run_manage_logs()`, `_run_install_cron()`, `_build_panorama_rows()` ajoutées à `__main__.py`
- Flags `manage_logs` et `install_cron` ajoutés à `AuditConfig` / `cli.py`
- Nouvelles clés locale : `log_dir`, `manage_logs`, `install_cron`, `sections.services_panorama`, `services.panorama.*`, `fixes.auto_mode_banner`, `fixes.auto_summary_title`

---

## [v0.11.2] — 2026-03-22

### Améliorations output & UX

- **Bandeau redessiné** — « UFW-AUDIT » en ASCII art bloc complet (style figlet Doom) sur toute la largeur 80-char du bandeau ; tiret rendu `═══` au point vertical médian ; mascotte supprimée ; nouvelle ligne étage (`╠═╣ / UFW-AUDIT vX.X  │  sous-titre / ╠═╣`) insérée entre l'art et infos système
- **Verdict du log** — remplacé le brut de blocs par une ligne verdict coloriée : `[OK] Activité normale` ou `[ATTENTION] Activité suspecte`
- **Top IPs / ports** — promu de `print_dim` à `print_info` (`ℹ [INFO]`) pour poids visuel cohérent
- **Dump port (ss)** — conditionné au mode verbeux (`-v`) ; non-verbeux affiche un hint `Utilisez -v pour afficher la table ports complète` à la place
- **Messages exposition port** — complètement auto-explicatifs : `ouvert à internet — aucune restriction source dans UFW`, `restreint au réseau local par règle UFW`, `explicitement bloqué par une règle UFW`, `couvert par politique deny défaut (aucune règle UFW explicite requise)`
- **Docs installation** — ajout étape `chmod +x install.sh` à README et README_FR

### Corrections fichier rapport

- Supprimé en-tête section log dupliqué (écrit deux fois : du flux principal et de `_display_log_results`)
- Titre section `LISTENING PORTS` utilise maintenant la locale active au lieu de hardcoded English
- Résultats virtualisation ont maintenant leur propre en-tête section `=== ANALYSE DE VIRTUALISATION ===` (étaient ajoutés dans la section Docker)
- Supprimé en-tête dupliqué `PORTS EN ÉCOUTE (VUE GÉNÉRALE)` (l'en-tête dump ss était redondant avec l'en-tête section deux lignes au-dessus)
- Ligne séparatrice ajoutée entre la ligne décompte ports et le dump ss dans le rapport

### Corrections locale

- Français : `"jours de logs disponibles"` → `"jour(s) de logs disponibles"` (grammaire pour count=1)
- Anglais : `"days of logs available"` → `"day(s) of logs available"` (cohérence)

---

## [v0.11.1] — 2026-03-22

### Hardening sécurité — 20 corrections sur 3 passes

Release de patch adressant les vulnérabilités de sécurité trouvées lors de la revue de code interne. Pas de changements fonctionnels — toutes les fonctionnalités v0.11 restent identiques.

#### Critique / Élevé

- **Injection shell** — `subprocess.run(cmd, shell=True)` en mode fix remplacé par `shlex.split()` + forme liste ; nom interface virtualisation cité avec `shlex.quote()`
- **Overwrite daemon.json** — commande fix Docker remplacée par une en pur Python fusionnant les clés existantes au lieu de blindly overwriting le fichier avec `tee`
- **Injection ANSI** — nouveau `output.sanitize()` supprime séquences d'escape ANSI et caractères non-printables de toutes données externes (noms conteneurs, hostnames, domaines) avant affichage terminal
- **Traversée de chemins / attaques symlink** — `_is_safe_config_path()` ajouté à `ddns.py` et `services.py` ; toutes lectures fichier config gardées par `path.is_absolute() and not path.is_symlink()`
- **Attaque symlink GeoIP2** — `_geo_via_geoip2()` et `geoip2_status()` sautent fichiers database symlinkés
- **Injection `SUDO_USER`** — validé contre `^[a-zA-Z0-9_.-]{1,256}$` avant `pwd.getpwnam()`

#### Moyen

- **ReDoS** — `\S+` dans `_extract_field()` borné à `\S{1,256}`
- **JSON bomb / DoS** — `registry.py` et `i18n.py` plafonnent lectures fichiers JSON à 1 MB et 512 KB respectivement avant `json.loads()`
- **DoS mémoire** — `/var/log/ufw.log` lu plafonnée à 100 MB ; `/etc/os-release` ligne plafonnée à 512 octets
- **Injection `UFW_AUDIT_SHARE`** — validé : doit être absolu, non-symlink, répertoire existant avant utilisation dans `registry.py` et `i18n.py`
- **Validation réponse HTTP** — réponse ipify.org limitée à 64 octets et validée contre regex IPv4
- **Injection domaine** — domaine DDNS extrait validé contre regex domaine ; nettoyé avec `output.sanitize(max_len=253)` avant affichage
- **Injection port / protocole** — `services.py` valide numéro port (1–65535) et protocole (`tcp`/`udp`) depuis registry avant utilisation
- **TOCTOU** — existence check daemon.json remplacée par `try/except FileNotFoundError` atomique

#### Bas

- **Permissions fichiers** — fichiers rapport créés avec `0o600` via `os.open()` ; répertoire config user créé avec `0o700` ; fichier config écrit avec `0o600`
- **Returncode subprocess** — mode fix vérifie `proc.returncode` et reporte succès/échec explicitement
- **Clauses exception larges** — `except Exception` remplacé par types d'exception spécifiques partout
- **Fuite FD** — `/dev/null` mode quiet descripteur fichier enregistré avec `atexit` pour fermeture propre
- **Injection hostname / nom OS** — nettoyé avec `output.sanitize(max_len=64)` avant affichage terminal
- **Import non utilisé** — `import io` supprimé du chemin mode quiet

---

## [v0.11] — 2026-03-22

### Consolidation CLI & tests sur le terrain

- Testé sur 3 distributions : Linux Mint 22.3, Debian 13 (trixie), Kali Linux Rolling
- Versions Python couverts : 3.12, 3.13
- Tous les bugs trouvés lors des tests terrain corrigés (voir ci-dessous)

### Corrections de bugs

- **`_command_exists()` returncode** — `subprocess.run` ne lève pas sur commande manquante ; returncode n'était pas vérifié, causant les paquets supprimés (état dpkg `rc`) à être détectés comme installés. Corrigé dans `firewall.py` et `docker.py`.
- **Adresse wildcard `*`** — certaines versions `ss` utilisent `*` au lieu de `0.0.0.0` pour « tous les interfaces » ; ajouté à regex `_ALL_INTERFACES` et parser `_split_addr_port()` dans `ports.py`.
- **Port qlipper 6666/udp** — outil sync presse-papiers KDE ; ajouté à `_SYSTEM_PORTS` pour supprimer faux positif.
- **Mode verbose affichage double** — lignes exposition port imprimées deux fois avec `-v` ; bloc redondant supprimé dans `__main__.py`.
- **Breakdown score `-0`** — quand firewall inactif, plafond affiché `-0` au lieu d'une note claire ; remplacé par `⚠ Score plafonné à 3 (firewall inactif)`.
- **Dédupplication port** — ports NetBIOS 137/138 et autres ports multi-adresses rapportés une fois par adresse liée au lieu d'une fois par port ; ajouté `reported_warn_ports` et `reported_alert_ports` sets dans `ports.py`.
- **Port UPnP/SSDP 1900/udp** — découverte multicast locale ; ajouté à `_SYSTEM_PORTS`.
- **Ports DHCPv6 546/547/udp** — ajoutés à `_SYSTEM_PORTS`.
- **Duplication avertissement IPv6** — apparaissait dans les sections `FIREWALL STATUS` et `UFW RULES ANALYSIS` ; supprimé de `firewall.py`, gardé uniquement dans `_check_rules()`.

### Mode non-interactif (`--quiet`)

- Nouveau flag `-q` / `--quiet` — supprime tout output terminal via redirection stdout vers `/dev/null`
- Codes sortie significatifs pour scripts et automation cron :
  - `0` — audit propre, pas d'alertes ou avertissements
  - `1` — avertissements détectés
  - `2` — alertes détectées, action requise
  - `3` — erreur technique
- `--quiet` incompatible avec `--fix` (validé au parse time)
- Codes sortie documentés dans `--help` et README

### `check_virtualization()`

- Nouveau module `ufw_audit/checks/virtualization.py` — même motif que `check_docker()`
- Détecte : libvirt/KVM (`virsh`, `virbr*`), VirtualBox (`vboxmanage`, `vboxnet*`), VMware (`vmware`, `vmnet*`), LXD/LXC (`lxd`/`lxc`, `lxdbr*`)
- Détecte aussi paquets Snap avec connexions réseau actives
- Avertissement affiché sans pénalité score — informatif, pas une mauvaise configuration
- Validé sur Linux Mint 22.3 avec libvirt/KVM actif + `virbr0`

### Complétition Bash

- Complétition `install.sh` ajoutée — `./install.sh --<TAB>` complète `--dry-run`, `--uninstall`, `--help`

---

## [v0.10] — 2026-03-22

### Géolocalisation IP — whois retiré, GeoIP2 optionnel

- **`whois` complètement retiré** — non fiable sur registres, lent sur gros fichiers logs, bloquant sur 100+ IPs
- **Intégration GeoIP2 optionnelle** — utilise `python3-geoip2` + base de données MaxMind GeoLite2 si disponible ; repli silencieux sur IP brut si non installé
- **Cache mémoire `_GEO_CACHE`** — chaque IP résolue une seule fois par session peu importe combien de fois elle apparaît dans les logs
- **`geoip2_status()`** — détecte disponibilité bibliothèque et présence base données indépendamment ; trois états : `available`, `unavailable`, `no_database`
- **Message info one-time** dans section analyse log :
  - GeoIP2 absent : `GeoIP2 non disponible — installez avec : sudo apt install python3-geoip2 geoip-database`
  - GeoIP2 installé mais pas de base données : `GeoIP2 installé mais pas de base GeoLite2 trouvée — installez avec : sudo apt install geoip-database`
  - GeoIP2 disponible : aucun message affiché

### Améliorations CLI

- **Flags courts** — tous les options fréquemment utilisés ont maintenant une forme courte :
  - `-f` / `--fix`
  - `-y` / `--yes`
  - `-r` / `--reconfigure`
  - `-n` / `--no-color`
  - `-V` / `--version` (existait déjà, maintenant documenté)
- **`-h` / `--help` et `-V` / `--version` sans sudo** — vérification root déplacée après parse arguments ; options informationnelles ne requirent jamais privilèges élevés
- **Aide réécrite** — format tabulaire propre avec flags court+long, examples usage, et lien documentation

### Complétition Bash

- **Complétition `install.sh` ajoutée** — `./install.sh --<TAB>` complète maintenant `--dry-run`, `--uninstall`, `--help`
- Fichier complétition mis à jour dans `/etc/bash_completion.d/ufw-audit`

### Disclaimer portée score

- **Note deux lignes affichée après chaque résumé audit** — rappelle à l'utilisateur que le score couvre uniquement l'exposition firewall, non mises à jour système, sécurité application, ou autres vecteurs attaque
- Bilingue EN/FR via clés locale `summary.scope_line1` et `summary.scope_line2`

### Format version

- Chaînes version changées de style `0.9.0` à `0.9` / `0.10` — plus simple, cohérent avec conventions project

---

## [v0.9.0] — 2026-03-20

Réécriture complète en Python — toutes les fonctionnalités conservées et étendues, architecture entièrement refactorisée.

### Réécriture complète en Python

- **Langage** — réécrit de Bash en Python 3.8+ (stdlib uniquement, zéro dépendances PyPI)
- **Architecture** — chaque module check divisé en deux couches strictes :
  - `XxxSnapshot.from_system()` — collecte données système via subprocess
  - `check_xxx(snapshot, t)` — logique pure, totalement testable unitairement sans appels système
- **421 tests unitaires** sur 13 fichiers de test — zéro échecs ; tous les tests exécutés sans sudo et sans UFW installé
- **Structure package** — `ufw_audit/` avec sous-package `checks/`, `locales/`, `data/`
- **Point d'entrée** — `/usr/local/bin/ufw-audit` installé par `install.sh`

### Installeur

- **`install.sh`** — installeur transparent avec output explicite pour chaque action
- Détecte Python 3.8+, copie fichiers aux emplacements Linux standard (`/usr/local/`)
- Écrit manifeste install exhaustif à `/usr/local/share/ufw-audit/install.manifest`
- **`--uninstall`** — lit le manifeste, supprime exactement ce qui a été installé, supprime répertoires uniquement s'ils sont vides, offre suppression configuration utilisateur séparément
- **`--dry-run`** — affiche toutes les actions sans effectuer aucunes changements

### Nouveaux modules

| Module | Rôle |
|---|---|
| `cli.py` | `AuditConfig` dataclass + `parse_args()` |
| `config.py` | `UserConfig` — `~/.config/ufw-audit/config.conf` (remplace `~/.ufw_audit.conf`) |
| `i18n.py` | `t("key.sub_key")` avec notation pointée, var env `UFW_AUDIT_SHARE` pour layout installé |
| `output.py` | Toutes fonctions affichage terminal — bandeau, sections, résultats, boîte résumé |
| `registry.py` | `ServiceRegistry.load()` depuis `services.json` — définitions déclaratives services |
| `report.py` | `AuditReport` + `NullReport` — flush immédiat à chaque write, pas buffering |
| `scoring.py` | `ScoreEngine`, `CheckResult`, `Finding`, `Deduction`, `RiskLevel` |
| `checks/firewall.py` | `FirewallStatus` + `check_firewall()` |
| `checks/services.py` | `ServiceSnapshot` + `check_services()` + enum `Exposure` |
| `checks/ports.py` | `PortsSnapshot` + `check_ports()` + enum `PortCategory` |
| `checks/logs.py` | `LogsSnapshot` + `check_logs()` + `get_ip_geo()` + détection bruteforce |
| `checks/ddns.py` | `DdnsSnapshot` + `check_ddns()` + extraction domaine par type client |
| `checks/docker.py` | `DockerSnapshot` + `check_docker()` + `ExposedPort` |

### Registry services déclaratif (`services.json`)

- 22 services définis déclarativement — aucune logique service hardcodée en Python
- Chaque service porte : id, label, packages, services systemd, ports défaut, niveau risque, config_key, hints détection (binary, snap, fichiers config)
- Ajouter nouveau service require éditer `services.json` uniquement — pas de changements Python

### Internationalisation

- 183 clés traduction dans `en.json` et `fr.json` — parité complète vérifiée
- Nouvelle section `service_risk` — 12 services critique/élevés avec trois clés chacun : `level`, `exposure`, `threat`
- Variable env `UFW_AUDIT_SHARE` — locales et `services.json` lus depuis répertoire share installé en production, depuis source tree en développement

### Corrections de bugs (post première exécution)

| # | Problème | Correction |
|---|---|---|
| 1 | Bandeau mal aligné — largeur badge hardcodée | `_build_logo()` — largeur badge dynamique du contenu |
| 2 | Pas de ligne vide avant boîtes section | `print()` ajouté au start de `print_section()` |
| 3 | Boîte résumé `⚠  :` — deux-points sur valeur vide | Séparateur conditionnel dans `print_summary_box()` |
| 4 | WireGuard affiché « état inconnu » | Service template `wg-quick@` aucune instance → `INACTIVE_DISABLED` |
| 5 | Port DNS rapporté deux fois | Set `reported_system_ports` — déduplique par `(port, proto)` |
| 6 | Liste ports en écoute absente du terminal | `ss_output` maintenant imprimé au terminal dans section ports overview |
| 7 | Chemin config affiche `/root/` sous sudo | `_get_user_home()` via `SUDO_USER` + `pwd.getpwnam()` |
| 8 | `ModuleNotFoundError: ufw_audit` | Point d'entrée utilise parent de `LIB_DIR` dans `sys.path`, pas `LIB_DIR` lui-même |

### Documentation

- **`README.md`** — documentation utilisateur complète pour v0.9.0 (Anglais) : fonctionnalités, table services, prérequis, installation, usage, référence options, emplacements fichiers
- **`README_DEV.md`** — documentation développeur (Anglais) : architecture, structure project, exécution tests, ajouter un service, ajouter une langue, conventions code, flux exécution, système scoring, internationalisation

---

## [v0.8.0] — 2026-03-20

### Géolocalisation IP dans analyse log UFW

- **`get_ip_geo()`** — nouvelle fonction résolvant pays et opérateur pour toute adresse IP via `whois`
- Plages privées/loopback (`10.x`, `192.168.x`, `172.16-31.x`, `127.x`) retournées « réseau local » sans requête réseau
- Résultats cachés dans `GEO_CACHE[]` — chaque IP consultée uniquement une fois par exécution
- Géolocalisation affichée en terminal sur top source IP et coups bruteforce
- Géolocalisation affichée dans rapport détaillé (`-d`) sur table top-10 IP complet et table bruteforce
- Si `whois` non installé : message informatif unique affiché, audit continue normalement sans données géo

---

## [v0.7] — 2026-03-20

Release majeur — refonte classification risque, analyse log UFW, détection DDNS/exposition externe, nouveaux services, et multiples corrections de bugs.

### Refonte classification risque

- **Nouveaux niveaux risque** — 7 services reclassifiés sur deux-axis framework (surface exposition + menace potentielle) :
  - Serveur SSH, Serveur VNC, MySQL/MariaDB, PostgreSQL, Redis → `critical` (était `high`)
  - Cockpit, Home Assistant → `high` (était `medium`)
- **`get_risk_context()`** — nouvelle fonction retournant expositions et menace strings par service (FR + EN) ; couvre tous services `high` et `critical`
- **`log_risk_context()`** — affiche bloc contexte risque en terminal et log pour services `high`/`critical` actifs (sauté pour `inactive_disabled`)
- **`finalize_log()`** — nouvelle section `[RISK CONTEXT]` dans rapport détaillé listant tous services détectés `high`/`critical` avec contexte deux-axis complet ; services inactifs/désactivés exclus

### Analyse log UFW — `audit_ufw_logs()`

- Nouvelle section dédiée parsant `/var/log/ufw.log`
- Supporte formats syslog (`Mar 19 10:23:14`) et systemd ISO (`2026-03-19T18:20:08`)
- Filtrage rapide single-pass `awk` par date — pas de subprocess `date` par ligne
- Période configurable via `--log-days=N` (défaut : 7)
- Résumé terminal : tentatives bloquées totales, top source IP, top port ciblé, détection bruteforce, tentatives sur ports services installés
- Rapport détaillé : tables top-10 complets pour IPs et ports
- Détection bruteforce : >10 tentatives depuis même IP sur même port en 60 secondes

### Détection DDNS / exposition externe — `audit_ddns()`

- Nouvelle section détectant clients DDNS actifs : ddclient, inadyn, DUC No-IP, script DuckDNS
- Extrait domaine configuré depuis fichier config client
- Croise DDNS actif avec règles UFW `ALLOW` sans restriction pour identifier ports internet-exposés
- Identifie services élevés/critiques parmi ports exposés
- Score : −1 global si DDNS actif + ports ouverts (pas par port)
- Conseil Fail2ban affiché quand exposition détectée
- Section rapport détaillé incluse

### Nouveaux services (4)

- **Nextcloud** — `high` ; détection snap + apt ; contexte risque deux-axis
- **Gitea / Forgejo** — `medium` ; détection binary + systemd + apt ; port auto-détecté depuis `app.ini`
- **Mosquitto (MQTT)** — `high` ; ports `fixed` 1883/8883 ; contexte risque deux-axis
- **Syncthing** — `medium` ; port auto-détecté depuis `config.xml`

### Améliorations détection

- **`is_package_installed()`** — étendu au-delà dpkg : paquets snap (`snap list`) et installations binaires (gitea, forgejo)
- **`get_service_state()`** — détection état service snap via `snap services`
- **`AUDITED_PORTS[]`** — ports traités par `audit_services()` maintenant exclus de `check_listening_ports_analysis()` — élimine rapportage port dupliqué

### Améliorations `--fix`

- **Trier commandes ufw delete en ordre nombre règle décroissant** — prévient échecs renomation quand suppression multiples règles séquentiellement
- **`eval "$CMD" < /dev/null`** — prévient blocage sur prompts interactifs

### Scoring

- **`IMPLICIT_POLICY_SVCS[]`** — tracer services `high`/`critical` sans règle UFW explicite ; affiché comme note contextuelle sous phrase résumé (pas pénalité score)
- **Mosquitto** correctement ajouté à note politique implicite quand actif sans règle explicite

### Corrections de bugs

- Version UFW `N/A` dans en-tête rapport — `grep -oE` maintenant appliqué à output `ufw version` complet, pas juste `head -1`
- `grep -c` remplacé par `wc -l` dans analyse log — prévient erreurs arithmétique `0\n0` sur certaines versions grep
- Compatibilité `mawk` — filtrage date `awk` réécrit utilisant `substr()` au lieu `match()` avec groupes capture
- WireGuard `inactive_disabled` plus affiché en contexte risque (terminal ou rapport)

### README

- Table services mise à jour avec colonne `Basis` expliquant classification risque
- Note ajoutée distinguant services validés de services implémentés-mais-non-testés
- Appel action testeurs bêta avec lien issue GitHub

---

## [v0.6.1] — 2026-03-19

Release patch — correction bug pour prompt port interactif.

### Correction de bug

- **`resolve_ports()` — `ask` config_key maintenant enregistre port après première demande** — services avec `config_key=ask` (Nginx, Apache, VNC, qBittorrent, Home Assistant) demandaient port à chaque exécution au lieu d'enregistrer réponse. Correction convertit `ask` en clé stable dérivée du label service (p. ex. `nginx_web_server_port`) et l'enregistre à `~/.ufw_audit.conf` comme toute clé nommée. Exécutions suivantes lisent valeur enregistrée sans demander. `--reconfigure` correctly efface ces clés dynamiques.

---

## [v0.6] — 2026-03-19

Release majeur — analyse Docker, nouveaux services, export JSON, mode `--fix`, améliorations scoring contextuel, et corrections faux positifs.

### Nouveau : mode `--fix`

- **`run_fixes()`** — section fix interactive affichée après résumé quand `--fix` passé
- Chaque item `action` avec commande automatable obtient prompt `[y/N]`
- Items sans fix automatisé sûr (p. ex. firewall désactivé) affichés `[manuel]` sans exécution
- `--fix --yes` applique tous les fixes sans confirmation
- `eval "$CMD" < /dev/null` prévient blocage sur prompts interactifs (p. ex. `ufw delete`)
- `sudo ufw --force delete` utilisé pour suppression règle pourempêcher confirmation UFW

### Nouveau : analyse Docker

- **`audit_docker()`** — section dédiée après services réseau :
  - Détecte si Docker installé et actif
  - Vérifie `daemon.json` pour `"iptables": false` — OK si présent, ALERTE si absent (risque bypass UFW)
  - Liste ports conteneurs exécutés via `docker ps` et vérifie couverture DENY UFW explicite
  - Ports conteneurs sans DENY affichés `improvement` (pas score extra — déjà compté par section port)
  - Supprime appel `log_section` dupliqué qui générait spurieuse blue frame à l'intérieur section Docker

### Nouveau : export JSON

- **`export_json()`** — deux modes :
  - `--json` : résumé (score, risque, contexte, items catégorisés, breakdown score)
  - `--json-full` : ajoute ports en écoute et règles UFW
- Output toujours sur stdout ; fichier `.json` écrit à côté `.log` quand `-d` actif
- Pretty-printed via `python3 -m json.tool` quand disponible

### Nouveaux services (5)

- **WireGuard VPN** — détection service template `wg-quick@` ; port `fixed` 51820/udp ; message contextuel (exposition VPN intentionnelle)
- **Redis** — port `fixed` 6379/tcp ; avertit si lié en dehors localhost ; INFO si correctement sur 127.0.0.1
- **Jellyfin** — port `fixed` 8096/tcp
- **Plex Media Server** — port `fixed` 32400/tcp
- **Home Assistant** — port `ask` 8123/tcp ; rappel authentification deux-facteurs quand internet-facing

### Nouveau : `--no-color`

- **`setup_colors()`** — remplace définitions ANSI variables statiques ; appelée après parse arguments
- Toutes variables couleur définies à chaînes vides quand `--no-color` passé
- Détecté en première-pass boucle arguments donc couleurs jamais émises même dans messages erreur précoces

### Améliorations scoring

- **Firewall inactif → score plafonnée à 3** — flag `FW_INACTIVE` défini dans `check_firewall_status()`, plafond appliqué dans `show_summary()` après todas les appels `score_deduct()` complètent ; annoté dans breakdown score avec marqueur `⚠`
- **Politique incoming ouverte → −3** (était −2) — `--no-score` + manuel `score_deduct 3` pour override pénalité ALERTE défaut
- **IPv6 sans règles** — WARN et −1 uniquement quand règles UFW existent ; silencieux OK sur installs frais sans règles configurées

### Améliorations résumé

- **Note politique implicite** — affichée après phrase interprétation quand score propre mais services `high`/`critical` dépendent politique `deny` défaut plutôt que règles explicites ; liste services affectés ; supprimée quand actions en attente
- **Annotation plafond score** — `⚠ score plafonnée à 3 — firewall désactivé` affichée dans breakdown score comme entrée distincte (jaune `⚠`, pas préfixe `-X`)

### Corrections faux positifs

- **`AUDITED_PORTS[]`** — ports traités par `audit_services()` enregistrés et sautés dans `check_listening_ports_analysis()`, éliminant rapportage port dupliqué (p. ex. Redis 6379, Samba 445/139)
- **`get_service_state()`** — gère services template systemd (`wg-quick@*`) ; replie sur check binaire `wg` pour WireGuard quand aucune unité chargée
- Redis, Jellyfin, Plex changés de `auto`/`ask` à `fixed` — élimine prompts port interactifs pour services avec ports standard

### Hardening sécurité

- **`chmod 600`** appliqué à `~/.ufw_audit.conf` à création (`config_load`) et toute write (`config_set`)

### Nouveaux flags CLI

- `--fix` — proposer fixes après audit
- `--yes` — appliquer tous les fixes sans confirmation (requiert `--fix`)
- `--no-color` — désactiver output couleur ANSI
- `--json` — exporter résumé en JSON
- `--json-full` — exporter audit complet en JSON

---

## [v0.5] — 2026-03-13

Release majeur — refonte moteur audit, système scoring contextuel, et résumé redessiné.

### Moteur audit — nouveaux checks

- **`check_ufw_duplicates()`** — détecte règles UFW dupliquées (même port, action, et source)
- **`check_ufw_allow_any()`** — détecte règles `allow from any` sans restriction port (risque critique)
- **`check_ipv6_consistency()`** — vérifie cohérence entre état IPv6 système et règles UFW correspondantes
- **`check_listening_ports_analysis()`** — analyse port en écoute unifiée (remplace deux sections séparées) :
  - ports liés à `0.0.0.0` sans règle UFW → ALERTE
  - NetBIOS 137/138 (Samba) lié à `0.0.0.0` sans règle → AVERTISSEMENT avec message contextuel (risque bas derrière NAT)
  - ports liés à IP locale spécifique → INFO
  - ports éphémères (>32767) → silencieusement sautés
  - ports système connus (DNS 53, DHCP 67/68, mDNS 5353, CUPS 631) → info uniquement, pas impact score

### Scoring contextuel

- **`detect_network_context()`** — détecte si machine directement internet-exposée (IP publique sur interface locale) ou derrière NAT
- **`score_deduct()`** — remplace manipulation score directe dans `log()` :
  - contexte public : pénalités doublées (WARN −2, ALERTE −4), plafonnée à −4
  - contexte local : WARN −1, ALERTE −2
  - règles dupliquées : −1 peu importe contexte
- **`log()`** — deux nouveaux paramètres optionnels :
  - `--no-score` : désactive déduction score pour services correctement configurés (p. ex. Samba restreint à IP spécifique)
  - `--nature=action|improvement|structural` : catégorise chaque WARN/ALERTE pour résumé

### Résumé redessiné

- **3 blocs distincts** dans résumé :
  - `Action requise` — items nécessitant attention immédiate
  - `Améliorations possibles` — étapes hardening optionnels
  - `Configuration normale` — avertissements attendus pour ce type système (Samba local, NetBIOS, etc.)
- **Phrase interprétation** générée automatiquement basée sur composition items :
  - pas problèmes → *« Votre configuration est saine. »*
  - structural uniquement → *« Les avertissements reflètent configuration normale pour ce type système. »*
  - mixte → *« La plupart de votre configuration est normale. Adressez items marqués Action requise. »*
  - action uniquement → *« Des corrections sont nécessaires. »*
- **Contexte réseau** affiché dans résumé (🏠 réseau local / ⚡ IP publique)
- **Breakdown score** : chaque déduction listée avec raison tronquée et annotation contexte IP publique si applicable

### Corrections faux positifs

- `analyze_port_exposure()` — réécrit `ufw status numbered` parsing (extrait colonne `From` via `awk $NF` au lieu regex `from [0-9]` qui échouait contre format actuel)
- IP spécifique (p. ex. `192.168.1.10:137`) n'est plus traité exposé sur `0.0.0.0`
- Dédupplication port : un port seul peut plus générer multiples entrées log pour même exposition
- Ports éphémères et système ne produisent plus spurieux entrées WARN/ALERTE

### Internationalisation

- 25 nouvelles clés `t()` ajoutées (FR + EN) :
  - sections : `sec_ports_analysis`, `sec_rules`
  - résumé catégorisé : `sum_cat_action`, `sum_cat_improvement`, `sum_cat_structural`
  - interprétation : `sum_interp_clean`, `sum_interp_structural`, `sum_interp_mixed`, `sum_interp_action`
  - contexte réseau : `ctx_label`, `ctx_public`, `ctx_local`
  - ports : `uncov_alert`, `uncov_info`, `uncov_none`, `uncov_fix`, `uncov_sysport`, `uncov_ephemeral`
  - NetBIOS : `ports_netbios_warn`, `ports_netbios_fix`
  - scoring : `score_breakdown`, `score_pub_penalty`
  - règles : `dup_found`, `any_found`, `ipv6_*`

### Technique

- `build_listen_map()` — pré-agrège tous output `ss` en single pass ; worst-case wins (`exposed` overrides `local`, jamais l'inverse)
- `log()` refactorisée pour parser tous arguments positionnels de position 4 onwards (support multi-flag)
- `AUDIT_ITEMS[]` — global array enregistrant chaque WARN/ALERTE comme `level|nature|message`
- `SCORE_BREAKDOWN[]` — global array de déductions score pour affichage dans rapport `-d`
- Nouvelles variables globales : `PUBLIC_IP`, `HAS_PUBLIC_IP`, `NETWORK_CONTEXT`, `AUDIT_ITEMS`, `SCORE_BREAKDOWN`

---

## [v0.4] — 2026-03-04

Release majeur — moteur audit conscient services, internationalisation, et overhaul visuel.

### Nouvelles fonctionnalités

- **Système internationalisation** — fonction `t()` centralise toutes chaînes visibles utilisateur ;
  flag `--french` bascule interface entière en français at runtime
- **Bandeau ASCII** — en-tête art bloc coloriée avec boîte infos système (distro, host, version UFW,
  utilisateur, date)
- **Registry services** — 13 services réseau connus tracés : SSH, VNC, Samba, FTP,
  Apache, Nginx, MySQL/MariaDB, PostgreSQL, Transmission, qBittorrent, Avahi, CUPS,
  Cockpit
- **Moteur audit per-service** — `audit_services()` détecte paquets installés,
  vérifie état systemd, résout ports, et classifie exposition UFW comme
  `open_world` / `open_local` / `deny` / `no_rule`
- **Explications contextuelles et recommandations** — `get_risk_explanation()` et
  `get_recommendation()` retournent guidance bilingue tailorée per service et per
  situation exposition
- **Pipeline résolution port** — `resolve_ports()` essaie order : config sauvegardée →
  auto-détection depuis fichiers config → prompt interactif ; ports custom
  persistés à `~/.ufw_audit.conf`
- **Configuration port persistante** — `config_load/get/set/delete_key()` gèrent
  fichier config per-utilisateur ; flag `--reconfigure` force re-asking tous custom ports
- **Détection distribution** — `detect_distro()` avertit si système n'est pas
  basé Debian/Ubuntu
- **Formatage terminal riche** — `log_section()`, `log_service_header()`,
  `log_detail()`, `log_recommendation()`, et `banner_row()` (padding ANSI-aware)

### Changements et améliorations

- `log()` refactorisée : maintenant émet icône (`✔ ⚠ ✖ ℹ`) à côté préfixe ; préfixe
  est localisé en mode français (`[ATTENTION]`, `[ALERTE]`, `[ERREUR]`)
- Variables couleur ANSI basculées en syntaxe `$'...'` — fixe littéral `\e[32m` being
  imprimé au lieu codes couleur actuels
- `check_firewall_status()` remplace `check_firewall()` — maintenant lit politique
  incoming défaut et rapporte explicitement
- `init_logfile()` absorbe `init_log_header()` — en-tête log maintenant inclut distro,
  kernel, version UFW, utilisateur, chemin config port, et langage actif
- `get_recommendation()` remplace `generate_recommendation()` — recommandations sont
  maintenant per-service et per-situation plutôt que keyword-matched
- User home réel résolu via `$SUDO_USER` donc `~/.ufw_audit.conf` écrit à home
  utilisateur invoquant, pas root's
- Aide mise à jour avec options `--french` et `--reconfigure`
- Tous commentaires code traduits vers anglais

---

## [v0.3] — 2026-02-22

- Release totalement stable avec raffinement vérification root :
  - Aide (`-h`) et version (`-V`) peuvent maintenant être affichées sans sudo
  - Privilèges root requis uniquement quand effectuant audit réel
- Option `-V/--version` ajoutée pour afficher version script
- Système logging amélioré :
  - Recommandations automatiquement ajoutées pour entrées WARN et ALERTE en mode détaillé
  - En-tête log maintenant inclut champ « Audit initié par »
  - Section finale log avec résumé et actions recommandées
- Vérification dépendances améliorée :
  - Distingue dépendances obligatoires (`ufw`) et optionnels (`ss` / `netstat`)
  - Fourni instructions install claires pour dépendances manquantes
- Analyse port en écoute maintenant :
  - Utilise `ss` ou `netstat` sûrement selon disponibilité
  - Logs verbeux et détaillés séparés
  - Compte ports en écoute et highlight exposition publique
- Flag `AUDIT_REQUESTED` introduit pour tracker quand audit réellement effectué
- Fonction helper `is_detailed()` ajoutée pour simplifier vérifications log détaillé
- Fonction `finalize_log()` ajoutée pour proprement appendre résumé audit et recommandations
- Modularité et lisibilité améliorées sans changer aucun scoring ou feature existant
- Maintient compatibilité backward entière avec comportement v0.2

---

## [v0.2.1] — 2026-02-20

- Hardening sécurité interne et améliorations código défensif
- Localisation locale ajoutée (LC_ALL=C.UTF-8) pour parsing commande cohérent
- Gestion privilèges root améliorée (aide accessible sans sudo)
- Parser arguments rétravaillé avec détection strict options inconnues
- Système logging sécurisé pour prévenir writes quand logfile undefined
- Fallback sûr ajouté pour détection port en écoute (ss → netstat)
- Usage eval non-sûr remplacé dans résolution chemin logfile
- Gestion statut UFW améliorée pour éviter faux positifs quand output commande vide
- Sorties inattendues prévenues par remplacement hard exit dans firewall check avec retour contrôlé
- Vérifications conditionnelles renforcées pour variables vides et fichiers manquants
- Résilience exécution globale améliorée sans altérer logique scoring
- Compatibilité backward complète maintenue avec comportement v0.2
- Pas de suppressions feature

---

## [v0.2] — 2026-02-19

- Hardening et améliorations stabilité majeur interne
- Gestion interruption sûre ajoutée (trap Ctrl+C)
- Système vérification dépendances introduit avant exécution
- Résilience erreur améliorée avec set -o pipefail et comportement sortie contrôlé
- Mécanisme logging sécurisé pour prévenir writes logfile undefined
- Mécanisme fallback ajouté pour détection socket réseau (ss → netstat)
- Sécurité commande interne et gestion variable améliorées
- Robustesse exécution rehaussée sans altérer logique scoring
- Compatibilité backward complète maintenue avec comportement v0.1.1
- Sélection log minimal vs détaillé ajoutée (-d pour détaillé, minimal par défaut)
- Output terminal verbeux (-v) maintenant séparé du niveau détail log
- Option -h (aide) accessible sans privilèges root
- Pas de changements fonctionnels ou suppressions feature

---

## [v0.1.1] — 2026-02-17

- Vérification privilège root ajoutée au démarrage
- Script renommé à `ufw_audit.sh` pour cohérence
- Logging amélioré : chaque message enregistré au log
- Analyse sensibilisée ports et règles UFW
- Infos système ajoutées au log (hostname, version UFW, kernel)
- Messages claires et standardisées pour alertes, avertissements, et notes
- Corrections mineures pour compatabilité et lisibilité

---

## [v0.1] — 2026-02-15

- Première release stable du script
- Audit UFW basique
- Décompte statuts OK, ATTENTION, et ERREUR
- Log complet des règles et ports en écoute
- Options : `-v/--verbose` et `-h/--help`
- Détection règles « Anywhere » et ports sensibles
- Résumé sécurité avec score et niveau risque
