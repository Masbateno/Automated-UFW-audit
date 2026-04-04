*[Read in English](CHANGELOG_FULL.md)* · *[TL;DR](../CHANGELOG_FR.md)*

# UFW-audit — Journal des modifications

Toutes les modifications notables du projet sont documentées ici.

---

## [v1.4.1] — 2026-04-04

### Correctifs

- **Complétion bash — `--install-completion` absent** (`ufw_audit/data/ufw-audit.bash-completion`) — Le flag n'était pas listé dans `long_opts`, donc appuyer sur Tab après `--install-c` ne produisait aucune suggestion. Ajouté à la liste des options longues.

---

## [v1.4.0] — 2026-04-04

### TL;DR
- Système de plugins `services.d` : déposer des fichiers JSON dans `~/.config/ufw-audit/services.d/` pour ajouter des définitions de services personnalisées
- Conscience de la politique deny par défaut : ports publics non couverts rétrogradés en INFO si la politique UFW est `deny`/`reject`
- `__main__.py` découpé en 4 modules ; désormais un pur orchestrateur (~160 lignes)
- Passage hardening : 11 correctifs sur 7 modules
- 676/676 tests unitaires (+24)

### Nouvelles fonctionnalités

- **Système de plugins `services.d`** (`registry.py`, `_paths.py`) — Les utilisateurs peuvent déposer des fichiers JSON dans `~/.config/ufw-audit/services.d/` (ou `/root/.config/ufw-audit/services.d/` lors d'une exécution via `sudo`) pour définir des services personnalisés chargés aux côtés de `services.json` intégré. Chaque fichier plugin suit le même schéma qu'une entrée de service built-in. Si un plugin définit un `id` déjà présent dans le registre, il remplace le built-in. Les fichiers invalides (JSON malformé, champ requis manquant, format de port invalide, tentative de traversée de répertoire) sont ignorés silencieusement. Le futur packaging `.deb` migrera le répertoire vers `/etc/ufw-audit/services.d/` pour les définitions système.

- **Conscience de la politique deny par défaut** (`checks/ports.py`, `locales/en.json`, `locales/fr.json`) — `check_ports()` accepte maintenant un paramètre `default_incoming_policy` (transmis depuis `FirewallStatus.incoming_policy`, déjà parsé — zéro appel subprocess supplémentaire). Lorsque la politique UFW par défaut est `deny` ou `reject`, les ports sans règle explicite sont déjà bloqués au niveau du pare-feu ; le finding est rétrogradé d'ALERT/WARN en INFO avec un message dédié (`ports.uncovered_default_deny`). Une politique `unknown` déclenche toujours ALERT.

### Refactorisations

- **`__main__.py` découpé en 4 modules** — Le monolithe d'origine est désormais un pur orchestrateur (~160 lignes). Extraits :
  - `ufw_audit/completion.py` — `install_completion() -> int` : gère `--install-completion` (script bash completion + lien symbolique sudo PATH)
  - `ufw_audit/runner.py` — `init_report()` + `run_checks() -> ChecksResult` : exécute les 8 vérifications en séquence, possède tous les imports de checks et les appels d'affichage
  - `ufw_audit/json_output.py` — `build_json_data() -> dict` : sérialisation JSON des résultats d'audit
- **`run_checks()` → NamedTuple `ChecksResult`** (`runner.py`) — Le type de retour passe d'un `tuple` opaque à `ChecksResult(snapshots, ports_snapshot)`. `fw_status` supprimé du retour (était immédiatement ignoré côté appelant).

### Correctifs

- **`__main__.py` — code de retour `CLIError`** — Retournait `1`, soit `EXIT_WARNINGS`. Changé en `EXIT_ERROR (3)` pour correspondre à la constante et éliminer l'ambiguïté.
- **`__main__.py` — stdout non restauré sur exception** — La redirection de `sys.stdout` vers `/dev/null` (mode JSON) n'était restaurée que sur le chemin nominal. Enveloppé dans un `try/finally` pour garantir la restauration et la fermeture de `_devnull` même en cas d'exception.
- **`firewall.py` — détection de règles dupliquées** — L'heuristique `rule[:20] in seen` (20 premiers caractères) pouvait produire des faux positifs pour des règles avec des préfixes identiques mais des destinations différentes. Remplacé par un booléen `found_duplicate` avec correspondance exacte.
- **`logs.py` — borne d'année pour les timestamps syslog** — Les timestamps syslog n'incluent pas l'année. Un log de décembre parsé en janvier se retrouvait daté dans le futur. Correctif : si le timestamp parsé est supérieur à `datetime.now()`, l'année est décrémentée de 1.
- **`logs.py` — exclusion des liens symboliques GeoIP2 `.mmdb`** — Le garde `is_symlink()` rejetait les fichiers `.mmdb` valides sur Debian/Ubuntu, où les bases MaxMind sont gérées via `update-alternatives` et sont toujours des liens symboliques. Garde supprimé.
- **`_run.py` — `_is_safe_config_path()` centralisée** — La vérification de sécurité des chemins était copiée-collée entre `ddns.py` et `services.py`. Déplacée dans `checks/_run.py` comme implémentation unique de référence.
- **`cron.py` — plusieurs correctifs** :
  - `read_text()` appelé sans `encoding=` (la valeur par défaut Python dépend de la locale) ; désormais `encoding="utf-8"` sur toutes les occurrences
  - Borne de plage : `min(int(end_s), int(start_s) + 999)` prévient les allocations mémoire non bornées tout en conservant la validation « hors plage » en aval
  - Regex NOTIFY_EMAIL : accepte désormais guillemets simples et doubles (ne correspondait qu'aux guillemets doubles)
- **`json_output.py` — timestamp UTC** — `datetime.now()` dépend du fuseau horaire système, rendant les timestamps non comparables entre machines. Changé en `datetime.now(timezone.utc)`.
- **`completion.py` — garde pour bash_completion.d absent** — Sur les distros sans `bash-completion` installé, `/etc/bash_completion.d/` peut ne pas exister. Ajout d'une vérification explicite avec message d'erreur descriptif avant la copie.
- **`completion.py` — sécurité écrasement lien symbolique** — L'ancien code faisait `unlink()` sur n'importe quel fichier en `/usr/local/bin/ufw-audit`, y compris un vrai binaire installé par un autre outil. Changé pour : unlink uniquement si c'est un lien symbolique ; refus avec message d'erreur si c'est un fichier régulier.

### Améliorations

- **`json_output.py` — paramètres typés** (`SystemInfo`, `list[ServiceSnapshot]`) — Précédemment typés comme `sys_info` nu et `list`, masquant la structure attendue aux IDE et aux outils d'analyse statique.
- **`json_output.py` — champ `schema_version: "1"`** — Les consommateurs (SIEM, scripts, outils CI) peuvent détecter les changements de format sans parser la chaîne `version`.
- **`display.py`** — Alias mort `print_info` supprimé (inutilisé après une refactorisation précédente).
- **`manage_logs.py`** — Variable inutilisée `home = get_user_home()` et son import supprimés dans la branche `change`.
- **`sysinfo.py`** — `open("/etc/os-release")` utilise désormais `encoding="utf-8", errors="replace"`.

### Tests

- **`TestFinding`** (`tests/test_scoring.py`) — 5 nouveaux tests : valeur par défaut du champ `note` ; `note` propagé via `warn()`, `alert()`, `add_finding()` ; `note` absent quand non fourni
- **Tests de ports avec processus connu** (`tests/test_ports.py`) — 4 nouveaux tests : le nom du processus apparaît dans le message du finding ; le nom du processus déclenche WARN (pas ALERT) ; le finding contient la note de disclaimer ; la note est vide si le processus est inconnu
- **Tests de conscience deny par défaut** (`tests/test_ports.py`) — 7 nouveaux tests : politique deny rétrograde en INFO ; aucune déduction appliquée ; message INFO affiché ; politique reject rétrograde aussi ; politique allow conserve ALERT ; politique unknown conserve ALERT ; plusieurs ports tous rétrogradés
- **Isolation plugins + chargement** (`tests/test_registry.py`) — Fixture `no_plugins` qui patche `_PLUGIN_DIR` vers un chemin inexistant ; 9 tests `TestPluginLoading` : plugin valide chargé ; JSON malformé ignoré ; champ requis manquant ignoré ; ID dupliqué ignoré ; format de port validé ; traversée de répertoire rejetée ; plugin fusionné avec le built-in ; plugin remplace le risque built-in ; plusieurs plugins chargés
- **Flags CLI paramétrés** (`tests/test_cli.py`) — 5 paires de flags converties en `@pytest.mark.parametrize` : `--verbose`/`-v`, `--detailed`/`-d`, `--yes`/`-y`, `--help`/`-h`, `--offline`/`-o`

---

## [v1.3.0] — 2026-03-31

### TL;DR
- i18n complète : toutes les chaînes `Deduction.reason` traduites via `t()` — zéro chaîne codée en dur dans le breakdown du score
- Robustesse réseau : mode `--offline`, chaîne de fallback 3 providers, détection d'adresse IPv6 publique
- 652/652 tests unitaires (+13)

### Nouvelles fonctionnalités

- **i18n — raisons de déduction entièrement traduites** (`checks/docker.py`, `checks/ports.py`, `checks/logs.py`, `checks/services.py`, `locales/en.json`, `locales/fr.json`) — Les cinq chaînes `Deduction.reason` codées en dur en anglais passent désormais par `_t()`. Espace de noms `"deduction"` ajouté dans les deux fichiers de locale avec les clés : `docker_bypass`, `netbios_no_rule`, `port_no_rule`, `brute_force`, `service_open_world`. Le breakdown du score s'affiche désormais dans la langue active.

- **Flag `--offline` / `-o`** (`cli.py`, `sysinfo.py`, `__main__.py`) — Nouveau flag CLI qui désactive tous les appels HTTP externes. `get_public_ip(offline=True)` retourne `""` immédiatement sans toucher le réseau. Utile pour les machines isolées, les tâches cron dans des environnements avec pare-feu sortant strict, ou pour un audit rapide sans latence réseau. Câblé via `AuditConfig.offline` → `detect_network_context(offline=)` → `get_public_ip(offline=)`.

- **`get_public_ip()` — chaîne de fallback 3 providers** (`sysinfo.py`) — Utilisait précédemment uniquement `api.ipify.org`. Essaie maintenant `api.ipify.org` → `ifconfig.me/ip` → `icanhazip.com` dans l'ordre, retournant la première réponse IPv4 valide. Retourne `""` si les trois échouent ou si `offline=True`.

- **`detect_network_context()` — détection d'adresse IPv6 publique** (`sysinfo.py`) — Après vérification des adresses IPv4 via `ip addr show`, la fonction scanne désormais les entrées `inet6` pour les adresses IPv6 publiques. Les adresses correspondant à `::1` (loopback), `fe80:` (link-local) ou aux préfixes `fc`/`fd` (ULA) sont exclues. Une machine avec une adresse publique `2001:db8::1` est désormais correctement reportée comme `"public"`.

- **Autocomplétion bash mise à jour** (`ufw_audit/data/ufw-audit.bash-completion`) — `--offline` ajouté aux options longues et `-o` aux options courtes.

### Tests

- `tests/test_sysinfo.py` — 11 nouveaux tests : `TestGetPublicIp` (5 tests : garde offline, succès premier provider, fallback vers second provider, échec tous providers, réponse invalide ignorée) + `TestDetectNetworkContext` (6 tests : passerelle privée, transmission offline, IPv4 public, IPv6 public, IPv6 link-local ignoré, fallback sur erreur subprocess)
- `tests/test_cli.py` — `test_offline_long`, `test_offline_short` ajoutés ; `offline: False` ajouté à l'assertion des valeurs par défaut

---

## [v1.2.1] — 2026-03-31

### Suppression

- **`install.sh` définitivement supprimé** — Déprécié depuis v1.0 lors de l'introduction du packaging PyPI. La méthode d'installation canonique est `pipx install ufw-audit` + `sudo ufw-audit --install-completion`. Le fichier était marqué déprécié depuis deux cycles de release et n'était plus maintenu.

### Packaging

- **`pyproject.toml` — `license-files = ["LICENSE"]`** — Était explicitement à `[]`, ce qui excluait le fichier `LICENSE` des métadonnées du package. Corrigé pour inclure le fichier ; présence vérifiée dans le sdist et le wheel (`dist-info/licenses/LICENSE`).
- **`pyproject.toml` — Classifier `Python :: 3 :: Only` ajouté** — Rend explicite que le package ne supporte pas Python 2. Cohérent avec `requires-python = ">=3.9"`.
- **`pyproject.toml` — URL `Repository` remplacée par `Issues`** — `Homepage` et `Repository` pointaient vers le même dépôt GitHub. `Repository` remplacé par l'URL des issues GitHub pour des métadonnées PyPI plus utiles.

---

## [v1.2.0] — 2026-03-30

### TL;DR
- Passage qualité basé sur une revue senior : 12 corrections défensives sur 8 modules
- Aucun changement de comportement, aucune nouvelle fonctionnalité
- 639/639 tests unitaires

### Corrections

- **`i18n.current_lang()` retournait la locale demandée au lieu de la locale chargée** (`i18n.py`) — Lors d'un fallback (ex. demande `"de"` → charge `en.json`), `_lang` était tout de même mis à `"de"`. Corrigé en assignant `locale_path.stem` après chargement.

- **`manage_logs.py` — appels `unlink()` non protégés** (`manage_logs.py`) — Les trois chemins de suppression (single, multi, all) encapsulent désormais `f.unlink()` dans `try/except OSError`, affichant un message d'erreur par fichier.

- **`i18n.init()` — `JSONDecodeError` brut sur locale malformée** (`i18n.py`) — Un JSON de locale malformé levait un `json.JSONDecodeError` brut. Intercepté et re-levé en `ValueError` avec un message diagnostique clair.

- **`resolve_share_dir()` — `Path.resolve()` non protégé** (`_paths.py`) — `Path.resolve()` peut lever `OSError` sur des liens symboliques cassés. Encapsulé dans `try/except OSError` ; retourne `None` en cas d'échec avec un log d'avertissement.

- **`registry.py` — validation faible de `config_key` et format des ports** (`registry.py`) — `VALID_CONFIG_KEYS` était défini mais jamais appliqué. `config_key` est maintenant validé : doit être l'un de `{"fixed", "auto", "ask"}` ou un identifiant Python valide. Les chaînes de port sont validées contre `^\d{1,5}/(tcp|udp)$`. Les services avec `config_key="fixed"` et une liste de ports vide lèvent désormais `ValueError`.

- **`report_markdown.py` — détection des tables échoue sur les lignes indentées** (`report_markdown.py`) — La détection utilisait `line.startswith("|")` qui échouait en cas d'espaces en début de ligne. Changé en `line.strip().startswith("|")`.

- **`report_markdown.py` — filtre cadres ASCII provoque des faux positifs** (`report_markdown.py`) — `_audit_log_to_html()` utilisait `any(c in line for c in "╔╗...")` qui se déclenchait sur toute ligne contenant un caractère de cadre (ex. chemins). Remplacé par `re.match(r"^[╔╗╚╝║═┌┐└┘─┼ ]+$", line.strip())` — ne matche que les lignes entièrement composées de caractères de cadre.

- **`report_markdown.py` — `send_html_email()` vérifie `mail` mais appelle `sendmail`** (`report_markdown.py`) — `shutil.which("mail")` était utilisé comme vérification de disponibilité, mais l'appel subprocess utilise `sendmail`. Changé en `shutil.which("sendmail")`.

- **`output.py` — débordement de colonne du panorama sur labels/ports longs** (`output.py`) — Les chaînes label et port étaient formatées avec `f"{label:<{COL_SVC}}"` sans troncature. Des chaînes plus longues que la largeur de colonne cassent la mise en page. Les deux sont désormais tronquées à `COL_SVC` / `COL_PORT` caractères avant formatage.

- **`scoring.py` — cap invisible dans le breakdown du score** (`scoring.py`) — Lorsqu'un cap réduisait le score (ex. pare-feu inactif → max 3), la raison du cap n'apparaissait jamais dans la liste du breakdown. `finalize()` injecte désormais une `Deduction(context="structural")` synthétique pour le delta cappé, rendant la raison visible dans la synthèse du score.

- **`scoring.py` — `Deduction.context` non validé** (`scoring.py`) — `context` acceptait n'importe quelle chaîne. Ajout de `VALID_CONTEXTS = {"local", "public", "structural"}` et d'une vérification `__post_init__` qui lève `ValueError` sur les valeurs invalides.

- **`sysinfo.py` — regex IP privée `172.` trop large** (`sysinfo.py`) — `re.search(r"via\s+(10\.|192\.168\.|172\.)", ...)` matchait toutes les adresses `172.x.x.x`, y compris les plages publiques (la RFC 1918 ne couvre que `172.16–31`). Un unique `_PRIVATE_IPV4_RE` centralisé est désormais appliqué dans les deux chemins de détection réseau. Les chaînes `kernel` et `user` passent maintenant par `_sanitize()` pour cohérence.

### Tests

- `tests/test_i18n.py` — `test_init_unknown_lang_falls_back_to_english` : assertion mise à jour de `current_lang() == "de"` vers `current_lang() == "en"`
- `tests/test_registry.py` — `test_main_port_empty` : utilise `config_key="auto"` (`ports=[]` est désormais rejeté pour `config_key="fixed"`)

---

## [v1.1.1] — 2026-03-30

### Correction

- **Colonne UFW du panorama — faux ✖ pour les expositions `NO_RULE`** (`panorama.py`) — Les services dont le port n'a pas de règle UFW explicite (ex. Avahi 5353/udp classifié `Exposure.NO_RULE`) s'affichaient avec ✖ dans le panorama. C'est incorrect : lorsqu'UFW est actif avec une politique deny par défaut (vérifiée dans la section pare-feu), un port sans règle est bloqué par cette politique et doit afficher ✔. La branche `has_no_rule → "none"` a été supprimée ; `NO_RULE` tombe désormais dans `"ok"` comme les autres expositions couvertes.

### Tests

- `test_no_rule_shows_none` renommé en `test_no_rule_shows_ok` — assertion mise à jour à `"ok"`

---

## [v1.1.0] — 2026-03-30

### TL;DR
- Boîte de synthèse repensée : retour à la ligne, commandes de correction inline, disclaimer rouge
- `listen_port` vsftpd et `rpc-port` Transmission (JSON) maintenant détectés
- Passage qualité interne sur 7 modules (aucun changement de comportement)
- 639/639 tests unitaires (+5)

### Nouvelles fonctionnalités

- **Boîte de synthèse — retour à la ligne** (`display.py`) — `_truncate()` (coupure à 48 caractères) remplacé par `_wrap_for_box()`, qui distribue les messages longs sur plusieurs lignes dans le cadre de la boîte. Aucun texte de finding n'est jamais tronqué.

- **Boîte de synthèse — commandes de correction inline** (`display.py`) — Chaque finding dans les blocs « Possible improvements » et « Action required » affiche désormais sa commande associée (`→ cmd`) sur la ligne immédiatement en dessous, lorsqu'une commande est disponible.

- **Boîte de synthèse — disclaimer rouge** (`display.py`) — Une ligne de disclaimer rouge est affichée après le bloc « Possible improvements » : *« Les commandes affichées sont des suggestions — vérifiez et adaptez à votre réseau avant de les exécuter »*. Affiché à chaque fois que le bloc est présent. Clé locale : `summary.block_improve_disclaimer`.

### Corrections

- **vsftpd `listen_port` non détecté** (`checks/services.py`) — Le regex de `_auto_detect_port()` ne correspondait qu'aux directives `port`, `listen` et `Port`. Ajout de `listen_port` dans l'alternance pour que `listen_port=2121` dans `/etc/vsftpd.conf` soit correctement capturé.

- **`rpc-port` Transmission non détecté** (`checks/services.py`) — Transmission stocke sa configuration en JSON (`/etc/transmission-daemon/settings.json`). Le parseur générique `_auto_detect_port()` ne gérait que les formats texte clé=valeur et clé: valeur. Ajout d'une branche JSON : les fichiers à extension `.json` sont analysés avec `json.loads()` et la clé `rpc-port` est extraite directement.

### Améliorations internes

- **`checks/_run.py`** — `_run()` reçoit un paramètre optionnel `timeout: int = _CMD_TIMEOUT`, permettant des surcharges par appel. Le log de debug inclut désormais le `stderr` complet du subprocess en échec.

- **`checks/ddns.py`** — Regex de validation de domaine remplacé par un pattern conforme RFC (`^(?!-)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}$`) qui rejette les tirets en début et les noms sans point. Typage `Optional[set[str]]` appliqué (4 occurrences).

- **`checks/docker.py`** — `ContainerPort.is_public` utilise désormais `ipaddress.ip_address().is_loopback` au lieu d'une vérification codée en dur `("0.0.0.0", "::")` — identifie correctement les liaisons sur interface spécifique (ex. `192.168.1.10`) comme publiques. `_get_exposed_ports()` déduplique par `(container_name, host_port, proto)` pour éviter le double comptage des paires IPv4+IPv6. Clé locale distincte `docker.no_public_ports` pour le cas « aucun port exposé ».

- **`checks/firewall.py`** — Annotation `lines: list[str]` ajoutée dans les trois fonctions d'aide (`_check_duplicates`, `_check_open_any`, `_check_ipv6_coverage`).

- **`checks/logs.py`** — Les fichiers de logs volumineux sont désormais lus depuis la fin (seek vers `file_size - 10 Mo`) pour capturer les entrées récentes plutôt que les plus anciennes. Le seuil de date passe d'une comparaison de chaînes à un objet `datetime` (`ts < cutoff_dt`).

- **`checks/ports.py`** — Suppression du regex `_PRIVATE_ADDR` inutilisé (code mort depuis l'introduction de `_LOOPBACK` et `_ALL_INTERFACES`).

- **`checks/services.py`** — Typage `Optional[set[str]]` appliqué dans `_build_snapshot`, `collect`, `collect_all` (4 occurrences).

### Tests

- 639/639 (+5 nouveaux) : `test_vsftpd_listen_port`, `test_vsftpd_commented_listen_port_ignored`, `test_transmission_json_rpc_port`, `test_transmission_json_default_port`, `test_transmission_json_invalid_falls_back`
- `test_docker.py` : `test_not_public_private` renommé en `test_public_specific_interface` — assertion mise à jour à `is_public is True` pour `192.168.1.10` (comportement correct après le fix `ipaddress`)
- `test_logs.py` : tous les appels `_parse_log(content, "YYYY-MM-DD")` mis à jour vers `_parse_log(content, datetime(Y, M, D))` suite au changement de signature

---

## [v1.0.4] — 2026-03-29

### Corrections

- **Ports éphémères dans lOVERVIEW** — `display_ports_overview()` affichait le raw `ss` complet, contournant le filtre éphémère appliqué dans `check_ports()`. La couche affichage filtre désormais les ports UDP éphémères (port > 32767) avant de calculer le compteur et dafficher le tableau.

---

## [v1.0.3] — 2026-03-29

### Corrections

- **Inondation de messages ports éphémères** — Chaque port UDP éphémère générait un finding INFO individuel. Sur les bureaux actifs faisant tourner Samba ou avec de nombreux sockets UDP ouverts, cela produisait des centaines de lignes inutiles dans la section ports. Les ports éphémères sont maintenant silencieusement ignorés (`continue` sans finding). La clé locale `ports.ephemeral_ignored` n'est plus utilisée.

### Tests

- `test_ephemeral_info` renommé en `test_ephemeral_silent` — vérifie qu'aucun finding INFO n'est produit et que la section se termine par le OK `all_covered`.

---

## [v1.0.1] — 2026-03-29

### Corrections

- **Détection du port SSH** — SSH sur un port non-standard était toujours signalé sur le port 22. Cause : `config_key` valait `"ssh_port"` dans le registre mais `_resolve_ports()` ne déclenche la détection automatique que pour `"auto"`. De plus, le regex de `_auto_detect_port()` exigeait `=` ou `:` comme séparateur, alors que sshd_config utilise un espace (`Port 49732`). Les deux points corrigés : `config_key` passé à `"auto"`, regex mis à jour vers `(?:\s*[=:]\s*|\s+)`.
- **Ports TCP élevés classés comme éphémères** — Les ports supérieurs à 32767 en TCP étaient marqués éphémères et silencieusement ignorés. Les sockets TCP retournés par `ss -tuln` sont toujours en état LISTEN (sockets serveur) — ils ne peuvent pas être éphémères. Le filtre éphémère s'applique désormais à UDP uniquement.

### Tests

- 634/634 — 15 nouveaux tests : `test_ephemeral_udp`, `test_tcp_high_port_not_ephemeral`, `test_sshd_config_space_format`, `test_sshd_config_commented_port_ignored`

---

## [v1.0] — 2026-03-29

### TL;DR
- Packaging PyPI — `pipx install ufw-audit` devient la méthode d'installation recommandée
- Nouveau flag `--install-completion` — installe la complétion bash et le lien symbolique `/usr/local/bin/` pour le PATH sudo
- Correction : la clé de traduction `services.exposure.not_listening` s'affichait brute dans la sortie de l'audit
- `install.sh` déprécié au profit de pip/pipx

### Nouvelles fonctionnalités

- **`pyproject.toml`** — Paquet déclaré avec setuptools>=77. Point d'entrée `ufw-audit = "ufw_audit.__main__:main"` enregistré. Fichiers de données (`data/*`, `locales/*.json`) embarqués dans le paquet. Permet `pipx install ufw-audit` et `pip install ufw-audit`.

- **`--install-completion`** — Nouveau flag CLI. Copie le script de complétion bash embarqué vers `/etc/bash_completion.d/ufw-audit`. Crée un lien symbolique `/usr/local/bin/ufw-audit → ~/.local/bin/ufw-audit` pour que `sudo ufw-audit` fonctionne lors d'une installation via pipx (qui place le binaire dans `~/.local/bin/`, hors du PATH restreint de sudo). Utilise `SUDO_USER` pour résoudre le répertoire home de l'utilisateur réel.

- **`ufw_audit/data/ufw-audit.bash-completion`** — Script de complétion bash embarqué dans le paquet, disponible après `pipx install` sans nécessiter de clone git.

### Corrections

- **`locales/en.json` + `locales/fr.json` — clé `services.exposure.not_listening` manquante** — Les ports classifiés comme `Exposure.NOT_LISTENING` (présents dans le registre mais sans listener actif sur le système) affichaient la clé de traduction brute `[services.exposure.not_listening]` dans la sortie de l'audit. Clé ajoutée : EN `"not actively listening — port in registry but not detected on this system"`, FR `"n'écoute pas activement — port présent dans le registre mais non détecté sur ce système"`.

### Dépréciations

- **`install.sh`** — Le script d'installation shell est déprécié. La méthode recommandée est `pipx install ufw-audit` suivi de `sudo ufw-audit --install-completion`. Le script est conservé pour les systèmes sans pip/pipx.

### Suppressions

- **`ufw-audit.bash-completion` (racine du dépôt)** — Doublon supprimé. Le script de complétion est désormais embarqué dans le paquet à `ufw_audit/data/ufw-audit.bash-completion`.

### Infrastructure

- **`.github/workflows/tests.yml`** — La CI met maintenant pip à jour avant l'installation, installe le paquet avec `pip install -e .`, et vérifie le point d'entrée. Python 3.8 retiré de la matrice de test (EOL depuis octobre 2024 ; `setuptools>=77` requiert Python 3.9+). Matrice : Python 3.9, 3.10, 3.12.

- **`pyproject.toml` — version Python minimum portée à 3.9** — `setuptools>=77` (requis pour PEP 639 `license-files = []`) ne supporte pas Python 3.8. `requires-python` mis à jour à `>=3.9`.

---

## [v0.22.1] — 2026-03-29

### TL;DR
- Hotfix : pare-feu détecté comme inactif sur les systèmes en locale française

### Correction de bug

- **`checks/_run.py` — locale française provoque un faux "pare-feu inactif"** — Tous les appels subprocess s'exécutent maintenant avec `LC_ALL=C`, `LANG=C` et `LANGUAGE=""`. Sans vider `LANGUAGE`, gettext (utilisé par UFW, un script Python) écrase `LC_ALL` et retourne `État : actif` au lieu de `Status: active`, faisant détecter le pare-feu comme inactif à tort. Affectait tout système avec `LANGUAGE` défini sur une locale non-anglaise.

---

## [v0.22] — 2026-03-29

### TL;DR
- Passe qualité interne : 5 modules refactorisés, aucune nouvelle fonctionnalité
- Alignement des bordures de cadres corrigé sur toutes les interfaces (Unicode large + formule de padding incorrecte)
- `meta: dict` supprimé de `CheckResult` — remplacé par `open_ports: list[str]` typé
- `FirewallStatus` met en cache la sortie subprocess — plus d'appel double à `ufw status`
- `__main__.py` découpé en `_run()` + `main()` pour une gestion propre des erreurs

### Corrections de bugs

- **`output.py` — décalage des bordures de cadres** — Toutes les fonctions de dessin de cadres (`print_section`, `print_summary_box`, `print_banner`, `fixes.py`, `cron.py`, `manage_logs.py`) avaient des formules de padding incorrectes causant le décalage du bord droit `║`. Deux bugs distincts : (1) l'overhead du padding comptait 2 au lieu de 4/6 ; (2) les caractères Unicode larges (emoji `🏠`) comptaient 1 colonne dans `len()` mais en occupent 2 dans le terminal. Corrigé par l'introduction de `_visual_width()` via `unicodedata.east_asian_width` et la correction de toutes les constantes d'overhead.

### Refactorisations

- **`__main__.py`** — `_bootstrap()` découpé en `require_root()` (lève `PermissionError`) + corps d'audit `_run(argv)` + garde globale `main(argv)`. Version déplacée dans `ufw_audit/__init__.py` comme source unique de vérité. Appel subprocess dupliqué `ufw status` supprimé — réutilise `fw_status.numbered_output` / `fw_status.ufw_output` en cache. Les caps de score de `check_firewall` sont traités automatiquement par `engine.apply()`, sans appel manuel à `engine.cap()`.

- **`checks/firewall.py`** — `FirewallStatus` gagne `numbered_output: str` (cache de `ufw status numbered`) et `ipv6_ufw_enabled: bool` (lit `/etc/default/ufw`). `check_firewall()` utilise `result.set_cap()` au lieu de `meta`. `check_rules()` découpé en trois helpers privés : `_check_duplicates`, `_check_open_any`, `_check_ipv6_coverage`. Avertissement IPv6 supprimé quand `IPV6=no` dans `/etc/default/ufw`.

- **`checks/services.py`** — Dictionnaire `_STATE_PRIORITY` remplace la logique fragile premier-match dans `_detect_state()`. `_detect_single_unit_state()` extrait pour la détection d'état par unité. Classmethod `_build_snapshot()` déduplique `collect()` / `collect_all()`. L'état `NOT_LISTENING` émet désormais un finding `INFO` au lieu de passer silencieusement.

- **`scoring.py`** — `_Cap` renommé `ScoreCap` (public). `CheckResult` gagne `caps: List[ScoreCap]` et `set_cap()`. `meta: dict` supprimé — remplacé par `open_ports: List[str]` (utilisé par le check DDNS). `ScoreEngine.apply()` traite automatiquement les caps embarqués.

---

## [v0.21] — 2026-03-28

### TL;DR
- Passe qualité pré-v1.0 : 78 nouveaux tests + 3 corrections de bugs
- Suite atteint 619/619
- `virtualization.py` entièrement couvert (seul module core sans tests)
- Deux faux positifs corrigés : plages CGNAT/IPv6 privées, lignes commentées dans les configs
- `--manage-cron` dispose d'un carnet d'adresses email complet : ajout, suppression par numéro/plage/all

### Corrections de bugs

- **`checks/services.py` — `_classify_exposure` — CGNAT et plages IPv6 privées** — Les règles autorisant l'accès depuis le CGNAT (`100.64.0.0/10`) ou les plages IPv6 privées (`::1`, `fe80::/10`, `fc00::/7`, `fd00::/8`) étaient incorrectement classées `OPEN_WORLD` au lieu de `OPEN_LOCAL`, déclenchant des déductions de score en faux positif. Le regex `_PRIVATE` inline a été remplacé par une constante module `_PRIVATE_ADDR` couvrant toutes les plages privées/locales.

- **`checks/services.py` — `_auto_detect_port` — lignes de config commentées** — Des lignes comme `# port = 2121` dans les fichiers de config étaient matchées par le regex de détection de port. La fonction supprime maintenant les lignes commentées avant la recherche, n'examinant que les directives actives.

- **`cli.py` — `parse_args` — modes mutuellement exclusifs** — `--manage-logs`, `--install-cron`, `--manage-cron` et `--fix` pouvaient précédemment être combinés sans erreur. Toute combinaison lève désormais une `CLIError` avec un message explicite.

### Nouvelle fonctionnalité

- **`--manage-cron` — carnet d'adresses email** — Nouvelle commande `m` dans le TUI de gestion des crons. Ouvre un sous-menu dédié pour gérer l'`EmailStore` directement, sans passer par `--install-cron` :
  - Affiche toutes les adresses enregistrées avec leur numéro
  - `a` — ajouter une nouvelle adresse validée
  - `N` — supprimer l'adresse numéro N
  - `1,3` ou `1-3` — supprimer une liste ou une plage
  - `all` — supprimer toutes les adresses

### Suite de tests — 619/619

Nouveaux tests par domaine (+78) :

| Fichier | Nouveaux | Couverture ajoutée |
|---------|---------|-------------------|
| `tests/test_virtualization.py` | 24 | Couverture complète de `check_virtualization()` : snapshot vide, chaque type d'hyperviseur, paquets snap, correspondance préfixe interface (virbr/vboxnet/vmnet/lxdbr/lxcbr) |
| `tests/test_email_store_mgmt.py` | 24 | `_manage_email_store()` : quitter, ajout valide/invalide/doublon, supprimer tout, supprimer par numéro, liste virgule, plage, hors limites, saisie invalide |
| `tests/test_services.py` | 16 | `_classify_exposure` : CGNAT, ULA IPv6 (fc/fd), link-local (fe80), loopback (::1), régression IP publique ; `TestAutoDetectPort` (9 tests) : toutes les directives, lignes commentées, fichier manquant, détection proto |
| `tests/test_cli.py` | 10 | `TestMutuallyExclusiveModes` : les 6 paires invalides lèvent `CLIError` ; 4 cas mode-unique valides passent |
| `tests/test_logs.py` | 7 | `_max_in_window` : frontière 60s (incluse), 61s (exclue), entrée désordonnée ; `_detect_bruteforce` : exactement le seuil (non détecté), seuil+1, IPs différentes, timestamps désordonnés |

---

## [v0.20] — 2026-03-28

### TL;DR
- 17 nouveaux tests en mode dégradé : comportement quand `ss`, la sortie des règles UFW ou le fichier de log sont absents
- Nouveau fichier `tests/test_degraded.py` — 4 classes couvrant chaque scénario dégradé + une classe combinée
- Suite atteint 548/548

### Suite de tests — 548/548

**`tests/test_degraded.py`** (nouveau fichier — 17 tests)

| Classe | Tests | Scénario |
|--------|-------|---------|
| `TestSSNotAvailable` | 4 | `ss` absent → `PortsSnapshot` vide → OK, zéro déductions, pas d'alerte |
| `TestCheckRulesEmptyOutput` | 5 | `check_rules` appelé avec `""`, espaces, ou sortie entête-seulement → zéro déductions |
| `TestLogFileDegraded` | 4 | `log_found=False` et entrées vides → INFO/OK, zéro déductions |
| `TestCombinedDegradation` | 4 | Les trois modules dégradés simultanément — pas de crash, pas de déductions cumulées |

---

## [v0.19] — 2026-03-28

### TL;DR
- CI GitHub Actions : pytest s'exécute automatiquement à chaque push et pull request
- Matrice : Python 3.8, 3.10, 3.12 — trois versions validées à chaque modification

### CI

- **`.github/workflows/tests.yml`** — Nouveau workflow `Tests` déclenché sur push/PR pour toutes les branches. Lance `python -m pytest tests/ -v --tb=short` sur `ubuntu-latest` avec une matrice Python 3 versions (3.8, 3.10, 3.12). Aucune dépendance externe hormis `pytest` — le projet n'utilise que la stdlib.

---

## [v0.18] — 2026-03-28

### TL;DR
- 26 nouveaux tests unitaires pour `fixes.py` — `run_fixes()` était le dernier module core sans tests
- Couverture : classification des items, ordre de suppression UFW, succès/échec/timeout subprocess, mode interactif, mode auto (`--yes`), résumé automatique
- Suite atteint 531/531

### Suite de tests — 531/531

**`tests/test_fixes.py`** (nouveau fichier — 26 tests)

Couvre `run_fixes()` dans `fixes.py` :

- **Classification des items** — `action + cmd` → item auto ; `action + pas de cmd` → compté dans l'en-tête mais ignoré dans la boucle ; `improvement`/`structural`/`ok` → ignorés (chemin `fixes.none`)
- **Ordre de suppression UFW** — les suppressions sont triées par index décroissant pour éviter les effets de renumérotation (supprimer la règle 5 avant la règle 3)
- **Ordre non-suppression** — les commandes non-delete s'exécutent après toutes les suppressions UFW
- **Chemin aucun item** — un engine vide et un engine avec uniquement des findings OK affichent tous les deux `fixes.none`, sans appel subprocess ni input
- **Succès subprocess** — `returncode=0` → `fixes.applied` affiché ; commande correctement découpée transmise à `subprocess.run`
- **Échec subprocess** — code retour non nul → `fixes.manual` affiché ; code de sortie inclus dans la sortie
- **Timeout subprocess / OSError** — `TimeoutExpired` et `OSError` tombent tous les deux sur `fixes.manual`
- **Mode interactif non** — `input()` retourne `"n"` → subprocess ignoré, item affiché comme manuel
- **Mode auto (`--yes`)** — `input()` jamais appelé ; tous les items auto appliqués ; bannière mode auto affichée
- **Résumé auto** — commandes appliquées listées après un run `--yes` ; pas de résumé si tout échoue ; `fixes.done` toujours affiché

---

## [v0.17] — 2026-03-28

### TL;DR
- Suite de tests unitaires complète : 505/505 — 15 échecs préexistants corrigés dans 6 fichiers
- Deux corrections de code : extraction de domaine DuckDNS et fallback des plages dans `cron_to_human`
- Aucun changement fonctionnel sur l'audit lui-même

### Corrections de bugs

- **`checks/ddns.py` — `_extract_duckdns_domain`** — La fonction retournait `www.duckdns.org` lors du parsing d'une URL DuckDNS de la forme `?domains=myhost&token=...`. Corrigé : le paramètre `?domains=` est désormais parsé en priorité et reconstruit en `myhost.duckdns.org` ; le fallback regex simple est conservé pour le contenu contenant déjà un domaine complet.

- **`cron.py` — `cron_to_human`** — Une expression cron avec une plage DOW telle que `0 */6 * * 1-5` était routée vers le chemin jours de la semaine car `dow != "*"` était la seule garde. Corrigé : le chemin jours de la semaine exige désormais que `dow` corresponde à `[\d,]+`. Les plages, les pas et les noms de jours tombent dans le fallback expression personnalisée.

### Suite de tests — 505/505

- **`test_check_rules.py`** — `has_warn` utilisait `FindingLevel.WARNING` (inexistant) ; corrigé en `FindingLevel.WARN`.
- **`test_firewall.py`** — `TestIPv6Consistency` appelait `check_firewall()` mais le check IPv6 est dans `check_rules()`. Réécrit pour appeler `check_rules("", texte_règles, t)`. Le scénario combiné `test_allow_policy_plus_no_ipv6` appelle désormais les deux fonctions et somme les déductions.
- **`test_cli.py`** — `test_yes_short` / `test_yes_long` appelaient `parse_args(["-y"])` seul ; le CLI requiert `--yes` avec `--fix`. Mis à jour en `parse_args(["-y", "--fix"])`.
- **`test_docker.py`** — Quatre tests supposaient que `check_docker` émet `alert` et déduit en contexte `local` pour un contournement iptables ; l'implémentation émet `warn` et ne déduit qu'en contexte `public`. Tests mis à jour pour correspondre au comportement réel.

---

## [v0.16] — 2026-03-28

### TL;DR
- Deux corrections de faux positifs panorama découvertes lors des tests de régression en direct
- Les ports du registre non en écoute n'affichent plus ✖ (`Exposure.NOT_LISTENING`)
- Les ports loopback sans règle UFW affichent désormais ✔ (`Exposure.LOOPBACK_NO_RULE`)
- Suite de tests de régression complète — C6 (9 services), C8 (OPEN_LOCAL), E1 validés, zéro entrée `pending`

### Corrections de bugs

- **`checks/services.py` — `Exposure.NOT_LISTENING`** — Les ports du registre sans listener actif (ex. `8883/tcp` de Mosquitto quand le TLS n'est pas configuré) étaient classifiés `NO_RULE`, provoquant un faux ✖ au panorama. Un nouveau variant `Exposure.NOT_LISTENING` est assigné à tout port du registre absent des listeners actifs (`ss`). Le panorama traite ceci comme `ok` (✔). Aucun message émis.

- **`checks/services.py` — `Exposure.LOOPBACK_NO_RULE`** — Les ports liés exclusivement au loopback *sans* règle UFW (ex. Redis `6379/tcp` en config par défaut) étaient classifiés `NO_RULE`, provoquant également un faux ✖. Un nouveau variant `Exposure.LOOPBACK_NO_RULE` remplace `NO_RULE` quand le port est dans l'ensemble loopback-only. Le panorama traite ceci comme `ok` (✔). Message : *"lié uniquement sur localhost — aucune règle UFW requise (couvert par refus par défaut)"*.

### Infrastructure

- **`__main__.py`** — Ensemble `all_listening_ports` calculé depuis `loopback_only_ports | active_external_ports` et transmis à `ServiceSnapshot.collect()` et `display_services_panorama()`.
- **`display.py`** — Signature de `display_services_panorama()` étendue pour accepter et transmettre `all_listening_ports`.

### Tests

- **`TESTING.md` / `TESTING_FR.md`** — Suite de tests de régression complète sur VM Linux Mint 22.3. C6 étendu à 9 services (VNC, FTP, PostgreSQL, Mosquitto, WireGuard, Gitea, Jellyfin, Home Assistant, Cockpit). C8 ajouté (OPEN_LOCAL — SSH restreint au LAN). E1 validé (loopback, sans règle UFW). Zéro entrée `pending` restante. Anomalie panorama ✖ Avahi documentée (cosmétique, sans impact sur le score).

---

## [v0.15.1] — 2026-03-27

### TL;DR
- Le script d'installation est désormais transactionnel — un échec en cours d'installation déclenche un rollback automatique, aucune installation partielle laissée sur le disque
- Correction de bug : un format de sortie UFW inhabituel ne génère plus de commande de fix invalide
- Interface de fix plus propre — la sortie subprocess UFW ne fuite plus dans le terminal
- Choix d'installation documenté (pourquoi install globale, pas de virtualenv)

### Script d'installation — robustesse

- **Trap + rollback en cas d'échec** — chaque fichier copié et répertoire créé est désormais suivi en mémoire. Si une étape échoue (`set -e`), un `trap` se déclenche à la sortie et supprime ce qui a déjà été installé, laissant le système propre. Une installation partielle sans manifeste n'est plus possible.
- **`do_copy_dir` supprimée** — helper mort utilisant `cp -r` sans filtrage (aurait copié `__pycache__`, `.pyc`, artefacts `.git` si jamais appelé). Toutes les copies utilisent déjà des listes de fichiers explicites ou des globs `*.json`.
- **En-tête du manifeste** — trois `echo >> fichier` consécutifs remplacés par un seul bloc `{ } >> fichier` (une ouverture de fichier au lieu de trois).

### Corrections de bugs

- **`checks/firewall.py`** — une ligne de règle open-any sans préfixe d'index `[N]` (format de sortie UFW inattendu) générait `sudo ufw --force delete ?` comme commande de correction. Retombe désormais sur `cmd=""`, en faisant un item manuel dans l'interface de fix plutôt qu'une commande invalide.
- **`fixes.py`** — `subprocess.run()` appelé sans `capture_output` ; la sortie UFW fuitait dans le terminal au milieu de l'interface de fix. Ajout de `capture_output=True` ; le stderr n'est affiché qu'en cas d'échec (`exit N — <stderr>`), gardant l'interface propre en cas de succès.

### Maintenance

- **`locales/en.json`, `locales/fr.json`** — `_meta.version` était encore à `0.13` ; mis à jour en `0.15`.

### Documentation

- **`README_TECH.md` (EN + FR)** — Ajout de la sous-section *Choix d'installation* expliquant le layout global `/usr/local/` (pas de dépendances PyPI, tourne en root, même convention qu'Ansible/Certbot), pourquoi aucun virtualenv n'est utilisé, le comportement du shebang Python système lors d'une mise à jour, et le nouveau trap de rollback.

---

## [v0.15] — 2026-03-27

### TL;DR
- Audit de sécurité complet : 8 problèmes corrigés en 3 passes (permissions cron, traversée de chemin, injection HTML, validation de plage dans les logs)
- Refactoring DRY : modules partagés `checks/_run.py` et `_paths.py`, code dupliqué éliminé dans 7 fichiers
- Correction de bug : les règles wildcard IPv6 (`ufw allow from any`) sont désormais entièrement détectées et supprimées par `--fix`
- 6 corrections du script d'installation (`__init__.py` manquant, vérification version Python, copie par glob)

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

#### Corrections — second passage

- **`cron.py`** — `edit_cron_schedule()` recréait les fichiers cron avec `0o644` (lisible par tous), régressant le `0o640` posé par `run_install_cron()`. Unifié en `0o640`.
- **`__main__.py`** — Branche morte `if False else` laissée lors d'une transition i18n supprimée (`t("report.title")` était inaccessible ; l'expression évaluait toujours la chaîne codée en dur).
- **`report_markdown.py`** — `_inline_format()` appliquait les substitutions regex gras/code/lien avant d'échapper le HTML de l'entrée. Du contenu généré par le système contenant `<`, `>` ou `&` (noms de processus, chemins) pouvait produire du HTML malformé dans les rapports email. Ajout de `html.escape()` en première étape. Suppression également de deux `import re` inline devenus obsolètes (import déjà présent au niveau du module).
- **`checks/ports.py`** — Les ports `UNCOVERED_LOCAL` (bindings loopback/LAN sans règle UFW) n'avaient pas de garde de déduplication. Les ports liés à la fois sur `127.0.0.1` et `[::1]` — comme Postfix sur `25/tcp` — étaient rapportés deux fois. Ajout d'un ensemble `reported_local_ports`, analogue aux gardes existants pour les autres catégories.

#### Corrections — troisième passage

- **`cron.py`** — Deux appels `re.sub()` utilisaient des chaînes fournies par l'utilisateur (email de notification, expression de planification + chemin du script) directement comme argument de remplacement. Une valeur contenant `\1` ou d'autres séquences backslash serait interprétée comme une backreférence par `re.sub()`, provoquant une `re.error` ou une sortie incorrecte silencieuse. Les deux arguments de remplacement remplacés par des lambdas, que `re.sub()` n'interpole jamais comme des patterns.
- **`report_markdown.py` (`_audit_log_to_html`)** — Tout le contenu dynamique (titres de section extraits du journal d'audit, niveau de log, horodatage, message, paires clé/valeur, éléments de liste, texte de paragraphe) était inséré dans le HTML sans échappement. Des chaînes générées par le système contenant `<`, `>` ou `&` — comme des noms d'hôtes, sorties de commandes ou chemins de fichiers — produiraient du HTML malformé dans les rapports email. Appliqué `html.escape()` à chaque point d'insertion. `except Exception` → `except OSError` sur la lecture du fichier journal.
- **`checks/firewall.py`** — `import re` redondant à l'intérieur de `check_rules()` supprimé (`re` déjà importé au niveau du module).
- **`output.py`** — Même `import re` inline redondant supprimé de `_strip_ansi()`.
- **`checks/logs.py`** — Après extraction de `DPT` depuis une ligne de journal noyau, `int(dpt)` était appelé sans validation de plage. Une entrée de journal malformée avec une valeur hors de `1–65535` créerait silencieusement un `LogEntry` invalide. Vérification explicite des bornes ajoutée avant l'ajout.

### Refactoring — extraction DRY

- **`checks/_run.py`** (nouveau) — hub partagé pour tous les modules de vérification : `_run()`, `_CMD_TIMEOUT = 10`, `_command_exists()`, `_identity_t()`. Les cinq implémentations dupliquées dans `firewall.py`, `services.py`, `ports.py`, `ddns.py`, `docker.py`, `virtualization.py`, `logs.py` supprimées.
- **`_paths.py`** (nouveau) — `resolve_share_dir()` extrait de `i18n.py` et `registry.py`. Valide la variable d'environnement `UFW_AUDIT_SHARE` avec `Path.resolve()` (sûr vis-à-vis des liens symboliques) avant utilisation.
- **`display.py`** — Helper `_truncate(text, max_len)` extrait ; cinq ternaires inline dans `display.py` et `fixes.py` remplacés.
- **`checks/ports.py`** — Les ports `UNCOVERED_LOCAL` (loopback/LAN, sans règle UFW) utilisent désormais la clé locale distincte `ports.uncovered_local` au lieu de `ports.uncovered`. Évite les messages trompeurs « en écoute sur toutes les interfaces » pour les services liés uniquement à localhost (ex. Postfix sur `25/tcp`).
- **`checks/logs.py`** — `_MAX_LOG_SIZE` réduit de 100 Mo à 10 Mo, suffisant pour plusieurs semaines de logs UFW. Prévient l'épuisement de la mémoire sur des fichiers journaux gonflés.

### Sécurité — permissions du répertoire de configuration

- **`config.py`** — `_ensure_dir()` appelait `mkdir(mode=0o700)` mais Python ignore `mode` si le répertoire existe déjà. Ajout d'un `chmod(0o700)` explicite après `mkdir` pour que les permissions soient appliquées à chaque écriture, pas seulement à la création.

### Corrections du script d'installation

- **`__init__.py` manquant** — `checks/__init__.py` était mentionné dans un commentaire comme « géré séparément » mais n'était jamais copié ni ajouté au manifeste. Corrigé.
- **Logique de vérification de version Python** — `major >= 3 AND minor >= 8` est incorrecte pour Python 4+. Corrigé en `(major > 3) OR (major == 3 AND minor >= 8)`.
- **Variable morte `LAYOUT`** — variable inutilisée supprimée.
- **Copie des locales** — deux lignes `do_copy` codées en dur remplacées par une boucle glob sur `${SRC_LOCALES}/*.json` ; le manifeste utilise le même glob sur les fichiers installés.
- **Copie de la documentation** — liste codée en dur remplacée par les fichiers racine (`README.md`, `README_FR.md`, `LICENSE`) plus un glob sur `DOCUMENTS/*.md`.
- **Nouveaux modules absents des listes** — `_paths.py` et `checks/_run.py` ajoutés à la fois à la boucle de copie et à la boucle du manifeste.

### Correction de bug — détection des règles wildcard IPv6

- **`checks/firewall.py`** — `open_any_pattern` ne correspondait pas aux lignes `Anywhere (v6) ALLOW IN Anywhere (v6)`. `ufw allow from any` ajoute à la fois une règle IPv4 et une règle IPv6 ; seule la règle IPv4 était détectée et proposée à la suppression. La règle wildcard IPv6 subsistait après `--fix`, laissant une faille de sécurité réelle. Corrigé : motif étendu avec `(?:\s+\(v6\))?` des deux côtés pour couvrir les quatre variantes (`bare`, `/tcp`, `/udp`, `(v6)`). Test unitaire `test_open_any_v6_both_detected` renforcé de `>= 1` à `== 2`.

---

## [v0.14.1] — 2026-03-26

### TL;DR
- Faux positifs corrigés : les services liés au loopback (Redis sur 127.0.0.1) ne déclenchent plus d'alerte
- Faux positifs DDNS éliminés (ports système, règles orphelines)
- Bannière VERSION et `--remove-cron` oubliés lors de v0.14 corrigés

### Corrections de bugs (corrections post-sortie)

- **Faux positif ALERT — services liés au loopback** : un service écoutant exclusivement sur `127.0.0.1` (ex. Redis sur `6379/tcp`) était incorrectement signalé comme *"exposé sur internet"* lorsqu'une règle UFW ouverte existait pour ce port. `PortsSnapshot` est désormais collecté avant le CHECK 3 ; les ports dont tous les bindings `ss` sont sur loopback reçoivent `Exposure.LOOPBACK` (INFO, sans déduction) au lieu de `OPEN_WORLD`.
- **Faux positifs DDNS** : les ports système (`53`, DHCP, mDNS) et les ports exclusivement loopback apparaissaient dans la liste d'exposition DDNS. Ajout du filtre `_DDNS_SYSTEM_PORTS` et vérification croisée avec les listeners non-loopback réels — les règles UFW orphelines (aucun service actif) et les règles bare (sans `/proto`) ne génèrent plus d'entrées fantômes.
- **`--remove-cron` non supprimé à la sortie** : le flag était marqué déprécié *"sera supprimé en v0.14"* mais n'avait jamais été retiré. Supprimé de `cli.py`, `__main__.py`, `cron.py`, `locales/en.json`, `locales/fr.json` et `ufw-audit.bash-completion`.
- **Bannière VERSION** : la bannière affichait encore `v0.13.0b` après la sortie de la v0.14. Corrigé.

---

## [v0.14] — 2026-03-25

### TL;DR
- Refactoring majeur : `__main__.py` réduit de 1820 à 481 lignes — 5 nouveaux modules dédiés extraits
- `check_rules()` déplacé dans son emplacement naturel `checks/firewall.py`
- Orchestrateur pur sans logique métier — architecture nettement plus claire

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

### TL;DR
- Planificateur multi-cron : plusieurs jobs nommés, wizard de planification en 4 étapes, TUI `--manage-cron`
- Chaque job a son propre nom, fichier et métadonnées — plus de `/etc/cron.d/ufw-audit` unique
- 40+ tests unitaires ajoutés pour toute la logique cron

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

### TL;DR
- Les rapports email incluent désormais une version HTML en plus du texte brut — rendu soigné dans tous les clients mail
- Zéro dépendance externe : convertisseur markdown → HTML écrit en Python stdlib pur
- Le script nightly cron est mis à jour pour envoyer des emails MIME multipart automatiquement

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

### TL;DR
- Regex open-any corrigée : espaces trailing, variantes `/tcp`/`/udp`, doublons sémantiques tous détectés
- Les services CRITICAL/HIGH exposés à internet vont désormais dans *Action requise* — plus noyés dans les *Améliorations*
- `TESTING.md` ajouté : premier plan de régression formel avec résultats VM en direct

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

### TL;DR
- `--install-cron` : planifiez des audits automatiques avec notifications email
- `--manage-logs` : interface interactive pour parcourir et supprimer les rapports sauvegardés
- Panorama des services : tableau compact des 22 services connus après chaque audit
- Le mode auto-fix (`-y`) affiche désormais une bannière d'avertissement et un résumé complet des commandes

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

### TL;DR
- Bandeau entièrement redessiné : "UFW-AUDIT" en art ASCII bloc Doom, largeur 80 chars
- Messages d'exposition des ports réécrits pour être entièrement auto-explicatifs
- Tableau des ports affiché uniquement en mode verbose (`-v`) — sortie par défaut plus lisible

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

### TL;DR
- Patch sécurité : 20 vulnérabilités corrigées (injection shell, injection ANSI, traversée de chemin, attaques symlink, ReDoS, JSON bomb)
- Aucun changement fonctionnel — toutes les fonctionnalités v0.11 identiques
- Permissions fichiers durcies : rapports `0o600`, répertoire de configuration `0o700`

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

### TL;DR
- Tests terrain sur 3 distributions (Mint, Debian, Kali) — tous les bugs trouvés corrigés
- Mode `--quiet` avec codes de sortie (0–3) pour l'automatisation et le cron
- Détection de virtualisation : libvirt/KVM, VirtualBox, VMware, LXD, paquets Snap réseau

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

### TL;DR
- `whois` supprimé — remplacé par GeoIP2 optionnel (plus rapide, hors-ligne, mis en cache par session)
- Flags courts ajoutés (`-f`, `-y`, `-r`, `-n`) — `-h` et `-V` ne nécessitent plus sudo
- Avertissement de portée du score affiché après chaque récapitulatif

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

### TL;DR
- Réécriture complète de Bash vers Python — 421 tests unitaires, zéro dépendance PyPI
- 22 services détectés avec contexte de risque à deux axes (exposition + niveau de menace)
- Installateur transparent avec manifeste, `--uninstall`, `--dry-run`, autocomplétion bash
- Interface bilingue EN/FR

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
