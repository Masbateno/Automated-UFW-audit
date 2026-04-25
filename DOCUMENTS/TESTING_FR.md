*[Read in English](TESTING.md)*

# UFW-audit — Plan de test : règles UFW dangereuses

Tests de régression manuel utilisant délibérément des règles UFW dangereuses.
Chaque test vérifie qu'ufw-audit détecte (et corrige) une mauvaise configuration spécifique.

---

## Historique des tests unitaires

| Version | Tests | Notes |
|---------|-------|-------|
| v1.24.0 | 4134  | +92 tests — `test_iptables_nftables.py` nouveau (51) ; `test_kernel_modules.py` : `TestKernelAptUpdate` (+9) ; `test_services.py` : `TestInactiveDisabled` (+5) + `TestPortExposureFindings` (+4) ; clés locale : `installed_inactive_critical`, `forward_unknown`, `kernels_update_available`, `kernels_up_to_date` |
| v1.23.0 | 4042  | +35 tests — `test_cli.py` : `TestFormatFlag` (+22) + `TestCheckSkipFlags` (+4) ; `test_manage_logs.py` : `TestExtractSummaryView` (+7) ; qualificateur portée (+2) ; `tests/helpers.py` utilitaires partagés introduit ; 62 fichiers migrés |
| v1.22.3 | 4007  | +2 tests — `test_ports.py` : split 3-tuple + virbr0 iface + is_all_interfaces scoped ; `test_exposure.py` : UDP éphémère exclu + TCP port élevé affiché ; fonctionnalité : `ufw status verbose` dans la section règles |
| v1.22.2 | 4004  | +3 tests — `test_exposure.py` : 2 renommés + 3 tests DDNS ; correctifs : filtre snakeoil global, exposition DDNS, port serveur élevé, double préfixe SSH, séparation notes runner |
| v1.22.1 | 4001  | +5 tests — `test_correlation.py` +1 (`test_message_uses_translation_key`) ; `test_recurrence.py` +1 (`test_float_value_in_prev_is_normalized`) ; assertion renforcée dans `test_exposure.py` (`fw_policy=None → alert`) ; politique float unifiée dans `recurrence.py` |
| v1.22.0 | 3996  | +218 tests — `test_correlation.py` (49), `test_exposure.py` (50), `test_recurrence.py` (27) ; `test_ipv6.py` +26 (`TestReadGlobalIPv6`) ; `test_explain.py` mis à jour (87→112 clés) ; `test_exposure.py` +7 (durcissement politique/bornes/contrats) ; `test_correlation.py` +7 (all_of/any_of vides, any_of vide + active vide, triggered_by tous les any_of actifs, résultat exact) |
| v1.21.0 | 3778  | +284 tests — `test_ssl_certs.py` (59), `test_systemd_timers.py` (58), `test_firmware.py` (54), `test_html_output.py` (56) ; fichiers existants : +57 (`test_cli.py`/`test_runner.py` — `--check`/`--skip`/`--output-dir`/`--html` ; `test_auditd.py` — INFO desktop ; assertions passage qualité) |
| v1.20.0 | 3494  | +235 tests — `test_auth_log.py` (62), `test_history.py` (36), `test_ignore.py` (44), `test_umask.py` (54), `test_ufw_logging.py` (32) ; corrections : auth_log days=0, ports système process-aware, nom de processus dans les messages |
| v1.19.0 | 3259  | +530 tests — `test_hardening.py` +29 (6 nouvelles classes sysctl) ; `test_ssh.py` +7 (cas OK PermitRootLogin) ; nouveaux : `test_suid_audit.py`, `test_kernel_hardening.py`, `test_docker_audit.py`, `test_log_rotation.py`, `test_csv_output.py`, `test_markdown_output.py`, `test_min_level.py`, `test_watch.py` |
| v1.18.0 | 2729  | +222 tests — `test_mac_policy.py` (nouveau, 40), `test_backup.py` (nouveau, 39), autres fichiers modifiés (+143) |
| v1.17.0 | 2507  | +215 tests — `test_auditd.py` (nouveau, 41), `test_secure_boot.py` (nouveau, 21), `test_file_integrity.py` (nouveau, 33), `test_explain.py` +81 (variantes par profil), autres fichiers modifiés +39 |
| v1.16.0 | 2292  | +153 tests — `test_desktop_apps.py` (nouveau), `test_ntp.py` (nouveau), `test_fail2ban.py` (42), `test_rootkit.py` (38), `test_exit_codes.py` (18) ; `test_hardening.py` −3 (fail2ban retiré) ; `test_explain.py` 77→76 clés |
| v1.15.1 | 2139  | Pas de nouveaux tests — correctif bash-completion (`--explain` sans `=` ; `compopt -o nospace`) |
| v1.15.0 | 2139  | +93 tests — `test_smtp.py` (31 + 9 passage qualité), `TestDominantLocalSource` (13), `TestApplyFlag` (12), `TestTargetFlag` (10), `TestDryRun` (8), `test_explain.py` mis à jour (73→77 clés), `test_cli.py` mis à jour (sémantique `--apply`) |
| v1.14.0 | 2045  | +155 tests — `test_samba.py` (68), `test_clamav.py` (52) ; `test_explain.py` mis à jour (63→73 clés) ; `test_compare.py` tests info_delta (+5) |
| v1.13.0 | 1890  | +187 tests — `test_disk.py` (60), `test_memory.py` (37) ; `test_explain.py` mis à jour (assertion 33→63 clés) |
| v1.12.0 | 1703  | +28 tests — profil workstation, assertions de dates, fixtures dict dans les fichiers existants |
| v1.11.0 | 1675  | +134 tests — `test_user_accounts.py` (51), `test_password_policy.py` (51) ; clés A2 `--explain` dans `test_explain.py` (+13 assertions) ; passage qualité sur les deux nouveaux fichiers |
| v1.10.0 | 1541  | +209 tests — `test_display_explain_hint.py` (25), `test_kernel_modules.py` (48), `test_cron_audit.py` (47), `test_services_state.py` (35) ; passage qualité : `test_check_rules.py` (+10), `test_cli.py` (+38), `test_compare.py` (+7), `test_cron.py` (+10), `test_ddns.py` (+5), `test_degraded.py` (+3) |
| v1.9.0  | 1332  | +228 tests — `test_updates.py` (34), `test_explain.py` (~94), `test_domain_scores.py` (~48), `test_webhook.py` (~54) ; passages qualité sur `test_hardening.py` + `test_profiles.py` |
| v1.8.0  | 1104  | +138 tests — `test_ssh.py` (93) + `test_file_perms.py` (45) : modifiable-par-tous (7), trop-permissif (5), clés-hôtes-SSH (4), NOPASSWD-ALL (5), NOPASSWD-spécifique (4), combinés (5), _is_nopasswd_all (8), dataclass (2), tout-correct (4) |
| v1.7.0  | 966   | +38 tests — `test_profiles.py` (36), `test_compare.py` (+2 filtre ports éphémères), `test_ipv6.py` (+2 entrées malformées) |
| v1.6.0  | 928   | +162 tests — `test_hardening.py` (49), `test_ipv6.py` (33), `test_compare.py` (49), `test_plugin_checks.py` (31) |
| v1.5.0  | 766   | +89 tests — `test_firewall_stack.py` (38), `test_network_context.py` (51) ; banner kernel/iptables/nftables |
| v1.4.2  | 677   | +1 test — NetBIOS 137/138 désormais COUVERT si règle UFW existante |
| v1.4.1  | 676   | Pas de nouveaux tests — correctif bash completion `--install-completion` |
| v1.4.0  | 676   | +24 tests — isolation plugins, ports process-aware, `TestFinding`, flags CLI paramétrés |
| v1.3.0  | 652   | +13 tests dans `test_sysinfo.py` — `--offline`, IP publique IPv6, repli 3 fournisseurs |
| v1.2.1  | 639   | Pas de nouveaux tests — nettoyage packaging |
| v1.2.0  | 639   | Pas de nouveaux tests — 12 corrections défensives sur 8 modules |
| v1.1.0  | 639   | +20 tests — boîte résumé redesignée, corrections détection vsftpd/Transmission |
| v1.0    | 619   | Pas de nouveaux tests — packaging (`pipx`), correctif locale `not_listening`, Python 3.9 minimum |
| v0.21   | 619   | 78 nouveaux tests + 3 corrections + carnet email ; passe qualité pré-v1.0 |
| v0.20   | 548   | 17 tests en mode dégradé ; scénarios `ss`/règles/log absents |
| v0.18   | 531   | 26 nouveaux tests pour `fixes.py` ; `run_fixes()` entièrement couvert |
| v0.17   | 505   | 15 échecs préexistants corrigés ; suite entièrement verte |
| v0.9    | 421   | Première suite complète |

### v1.24.0 — 4134/4134 (2026-04-25)

**Plateforme :** Linux Mint 22.3 — `so6desktop` — Python 3.12.3, pytest 7.4.4

```
pytest tests/ -q
4134 passed in 4.71s
```

#### Nouveaux / tests modifiés (+92)

| Fichier | Changement | Couverture |
|---------|------------|------------|
| `tests/test_iptables_nftables.py` | Nouveau fichier — 51 tests | CHECK 46 : audit iptables/nftables quand UFW inactif ; `_get_iptables_backend`, `_parse_iptables_policy`, `_check_conntrack`, `_check_iptables_nftables` ; détection backend (iptables-legacy vs nftables) ; analyse politique INPUT/FORWARD ; conntrack ACCEPT ; FORWARD inconnu→INFO ; chemins dégradé/absent |
| `tests/test_kernel_modules.py` | +9 tests (`TestKernelAptUpdate`) | `check_kernel_update_available` : chemin principal apt-cache policy ; repli apt list --upgradable ; noyau à jour → `✔ [OK]` ; mise à jour disponible → WARN ; apt indisponible → ignoré ; flag `apt_checked` positionné ; chemins Ubuntu et Debian |
| `tests/test_services.py` | +5 tests (`TestInactiveDisabled`) | `test_warn_for_critical_inactive_disabled` ; `test_warn_for_high_inactive_disabled` ; `test_no_deduction_for_critical_inactive` ; `test_no_port_check_for_critical_inactive` ; base faible risque préservée (`test_info_finding_for_low_risk_inactive`) |
| `tests/test_services.py` | +4 tests (`TestPortExposureFindings`) | `test_not_listening_critical_adds_warn` ; `test_not_listening_high_adds_warn` ; `test_not_listening_no_deduction` ; `test_not_listening_critical_no_deduction` ; `test_not_listening_adds_info_for_low_risk` (renommé depuis `test_not_listening_adds_info`) |

---

### v1.23.0 — 4042/4042 (2026-04-24)

**Plateforme :** Linux Mint 22.3 — `so6desktop` — Python 3.12.3, pytest 7.4.4

```
pytest tests/ -q
4042 passed in 4.52s
```

#### Nouveaux / tests modifiés (+35)

| Fichier | Changement | Couverture |
|---------|------------|------------|
| `tests/test_cli.py` | +22 tests (`TestFormatFlag`) | `--format=json/json-full/csv/markdown/html` ; formes `=` et espace ; parité aliases legacy ; erreurs d'exclusion mutuelle ; conflits `--format`+`--output`/`--html` ; valeur invalide rejetée |
| `tests/test_cli.py` | +4 tests (`TestCheckSkipFlags`) | `--check=list` positionne `list_checks=True` ; non combinable avec `--skip` ; liste affichée contient les sections connues |
| `tests/test_manage_logs.py` | +7 tests (`TestExtractSummaryView`) | Entrée vide → vide ; pas de séparateur → vide ; séparateur sans ligne score → vide ; bloc valide extrait ; lignes ALERT/WARN avec continuation ; lignes non-ALERT/WARN ignorées ; plusieurs séparateurs utilise le dernier |
| `tests/test_display_explain_hint.py` / `tests/test_runner.py` | +2 tests | `display_risk_context(is_local=True)` ajoute `• LAN` ; `build_risk_context_entries` avec `network_context="local"` produit le label `• LAN` |

---

### v1.22.3 — 4007/4007 (2026-04-20)

**Plateforme :** Linux Mint 22.3 — `so6desktop` — Python 3.12.3, pytest 7.4.4

```
pytest tests/ -q
4007 passed in 4.31s
```

#### Nouveaux / tests modifiés (+2)

| Fichier | Changement | Couverture |
|---------|------------|------------|
| `tests/test_ports.py` | +2 tests | `test_ipv4_virbr0_iface` — `_split_addr_port("0.0.0.0%virbr0:67")` retourne `("0.0.0.0", "67", "virbr0")` ; `test_is_all_interfaces_false_when_iface_scoped` — `ListeningPort(address="0.0.0.0", iface="virbr0").is_all_interfaces is False` |
| `tests/test_exposure.py` | 1 renommé + 1 ajouté (55 au total) | `test_high_numbered_tcp_port_is_shown` — 49152/tcp affiché ; `test_high_numbered_udp_port_excluded` — 49152/udp → icône `✔` (absent du détail) |

---

### v1.22.2 — 4004/4004 (2026-04-20)

**Plateforme :** Linux Mint 22.3 — `so6desktop` — Python 3.12.3, pytest 7.4.4

```
pytest tests/ -q
4004 passed in 4.74s
```

#### Nouveaux / tests modifiés (+3)

| Fichier | Changement | Couverture |
|---------|------------|------------|
| `tests/test_exposure.py` | renommés + 3 ajoutés (54 au total) | `test_high_numbered_listen_port_is_shown` — port 49152 présent dans detail ; `test_port_32768_is_shown` — port 32768 présent dans detail ; `test_ddns_warn_is_warn` / `test_ddns_warn_detail_contains_ddns` / `test_public_overrides_ddns` |

---

### v1.22.1 — 4001/4001 (2026-04-20)

**Plateforme :** Linux Mint 22.3 — `so6desktop` — Python 3.12.3, pytest 7.4.4

```
pytest tests/ -q
4001 passed in 4.50s
```

#### Nouveaux / tests modifiés (+5)

| Fichier | Changement | Couverture |
|---------|------------|------------|
| `tests/test_correlation.py` | +1 test (51 au total) | `test_message_uses_translation_key` : injecte `fake_t(key) → "translated:{key}"` ; assert `match.message == "translated:corr.root_no_protection"` — vérifie que `t(rule.message_key)` est appelé |
| `tests/test_exposure.py` | assertion renforcée (51 au total) | `test_fw_policy_none_does_not_crash` : `assert item.color == "alert"` (était `in ("ok","warn","alert")`) ; documente que `fw_policy=None` tombe dans la branche permissive |
| `tests/test_recurrence.py` | +1 test (29 au total) | `test_float_value_in_prev_is_normalized` : `update_recurrence({"k": 1.9}, {"k"})` → `int(1.9)=1` puis `+1` → `assert result["k"] == 2` ; couvre la normalisation float désormais cohérente avec `load_recurrence` |

---

### v1.22.0 — 3996/3996 (2026-04-20)

**Plateforme :** Linux Mint 22.3 — `so6desktop` — Python 3.12.3, pytest 7.4.4

```
pytest tests/ -q
3996 passed in 4.29s
```

#### Nouveaux / tests modifiés (+218)

| Fichier | Changement | Couverture |
|---------|------------|------------|
| `tests/test_correlation.py` | Nouveau — 49 tests | `TestCorrelationRuleMatches` (13) : all_of satisfait, all_of incomplet, any_of satisfait/non, active vide, any_of vide = pas de contrainte, les deux satisfaits, any_of partiel ; all_of + any_of tous vides → True même sur active vide ; all_of vide + any_of non vide + active vide → False ; `TestRunCorrelationsNoMatch` (5) : moteur vide, findings OK ignorés, findings INFO ignorés, finding sans clé ignoré, clé all_of au niveau INFO ne déclenche pas la règle ; tests par règle : root_no_protection (deux variantes fail2ban + triggered_by tous les any_of actifs), password_auth_under_attack, ssh_root_password, privilege_escalation, stale_unmonitored (deux variantes), fully_blind ; `TestMultiRuleCoexistence` (5, trois règles avec vérification d'ensemble exact) ; `TestCorrelatedFindingStructure` (2) ; `TestRulesSanity` (5) |
| `tests/test_exposure.py` | Nouveau — 50 tests | `FakeEngine` + `_FakePortsSnapshot` ; item firewall : allow/unknown/None → alert, deny/reject → ok ; couleur open_ports : allow/unknown → alert, deny → warn ; bornes : 32767 inclus, 32768 exclu ; `test_not_installed_overrides_password_auth` (documente l'intention) ; `test_info_findings_do_not_affect_ssh` ; `test_items_order` (contrat) ; `TestPortDeduplication` ; `TestEdgeCases` ; `TestSshAllIssues` ; `TestIconColorInvariant` ; `TestFullyExposedScenario` |
| `tests/test_recurrence.py` | Nouveau — 27 tests | `load_recurrence` : fichier absent (dict vide), JSON valide, valeurs corrompues ignorées, clé vide ignorée, valeur négative ignorée, float converti en int ; `save_recurrence` : crée le fichier, écrase, pas de fichier tmp restant (`test_no_tmp_file_leftover`) ; `update_recurrence` : nouvelle clé commence à 1, clé existante incrémentée, clé résolue supprimée, prev négatif ramené à 1 (`test_negative_counter_clamped_to_one`), prev non-int réinitialisé à 1, clés résultat == clés actives, 3 exécutions consécutives, 10k clés aller-retour, écrasements répétés conservent le dernier |
| `tests/test_ipv6.py` | +26 tests (57 total) | `TestReadGlobalIPv6` : unicast global 2001:db8, préfixe 3ffe, loopback ::1 → False, fe80 link-local → False, fc00 ULA → False, fd00 ULA → False, sortie vide → False, adresses multiples (global gagne), monkey-patch `_run` via attribut module ; `make_snapshot()` mis à jour avec `has_global_ipv6=True` par défaut |
| `tests/test_explain.py` | Mis à jour | `test_has_one_hundred_twelve_keys` : assert `len(EXPLAIN_KEYS) == 112` (était 87) |

---

### v1.21.0 — 3778/3778 (2026-04-19)

**Plateforme :** Linux Mint 22.3 — `so6desktop` — Python 3.12.3, pytest 7.4.4

```
pytest tests/ -q
3778 passed in 5.09s
```

#### Nouveaux / fichiers modifiés (+284)

| Fichier | Modification | Couverture |
|---------|-------------|------------|
| `tests/test_ssl_certs.py` | Nouveau — 59 tests | Defaults snapshot ; `_add_path` — dédup, symlink cassé ignoré, bundle CA ignoré (>50 Ko) ; `_collect_from_configs` — chemin cité nginx, apache2, postfix, commentaire inline ignoré, espaces ; `check_ssl_certs()` — expiré ALERT −2, <7j ALERT −2, <30j WARN −1, valide OK, plafond −4, limite `_MAX_CERTS` ; no-t guard |
| `tests/test_systemd_timers.py` | Nouveau — 58 tests | Defaults snapshot ; `TestPipeToShellDetection` (11 cas paramétrés : `\| bash`, `\| /bin/bash`, `\| bash -c`, wget+bash, zsh, ksh, sans pipe, sans downloader, etc.) ; test dernier service sur ligne ambiguë ; `TestParseServiceFile` (préfixe minus, préfixe at, sans ExecStart, User=root) ; `TestFromSystem` (plafond _MAX_TIMERS, dédup scripts, ExecStart mixte, User=root) ; logique check ; no-t guard |
| `tests/test_firmware.py` | Nouveau — 54 tests | Defaults snapshot ; `_detect_cpu_vendor` (intel, amd, unknown, arm) ; `_dpkg_installed` (basic, arch-qualifié `intel-microcode:amd64`, non installé) ; `check_firmware()` — tous les chemins ; adapté au profil ; assertions comptage déductions (len==1 avant accès) |
| `tests/test_html_output.py` | Nouveau — 56 tests | `build_html_output()` — doctype HTML5, `<title>`, CSS présent, couleur cercle score (vert/orange/rouge), label niveau, comptages alertes/avertissements, hostname échappé HTML, injection XSS dans message (pas de `<img>` dans le DOM), tableau déductions rendu, message "Aucun finding", tous les niveaux de sévérité ; classe `FakeEngine` (pas de mock) ; assertions DOM via BeautifulSoup |
| Fichiers existants | +57 tests | `test_cli.py`/`test_runner.py` : `--check` simple/multiple, `--skip`, CLIError combinaison, `_section_enabled`, `--output-dir`, `--html` ; `test_auditd.py` : finding `no_rules` est INFO (pas WARN) sur le profil desktop ; assertions passage qualité |

---

### v1.20.0 — 3494/3494 (2026-04-18)

**Plateforme :** Linux Mint 22.3 — `so6desktop` — Python 3.12.3, pytest 7.4.4

```
pytest tests/ -q
3494 passed in 4.06s
```

#### Nouveaux / modifiés (+235)

| Fichier | Modification | Couverture |
|---------|-------------|------------|
| `tests/test_auth_log.py` | Nouveau — 62 tests | Défauts `AuthLogSnapshot` ; `_estimate_days()` — fichier vide (0 jour), fichier normal ; `check_auth_log()` — aucune entrée days>0 (OK, clé `no_logins`), aucune entrée days=0 (OK, clé `no_logins_no_range`, pas de « 0 » dans le message), force-brute >10 tentatives/60 s (ALERT, −2 pts, clé déduction, IP source dans message), dernières connexions réussies (INFO), top sources échouées (WARN) ; assertions de clés ; garde no-t |
| `tests/test_history.py` | Nouveau — 36 tests | Dataclass `HistoryEntry` ; `load_history()` — fichier absent (liste vide), JSONL valide, lignes malformées ignorées ; `save_history()` — crée le fichier, rotation à 90 entrées, écrase ; `render_sparkline()` — liste vide, entrée unique, correspondance d'échelle (0→▁, 10→█), étiquettes de dates ; intégration flag CLI `--history` |
| `tests/test_ignore.py` | Nouveau — 44 tests | `load_ignore()` — fichier absent (set vide), YAML valide, YAML malformé ; `save_ignore()` — crée le fichier, écrase ; `ScoreEngine.ignore_keys` — finding ignoré non scoré, collecté dans `ignored_findings`, déduction non ajoutée ; clé `ignored.hint` utilise `check_key=` (pas `key=`) ; CLI `--ignore KEY` ; CLI `--show-ignored` |
| `tests/test_umask.py` | Nouveau — 54 tests | Défauts `UmaskSnapshot` ; couverture chemins `from_system()` (login.defs/pam/profile/courant) ; `check_umask()` — permissif 0002 (WARN, −1 pt, clé, clé déduction, cmd), permissif 0000 (WARN, −1 pt), strict 0027 (OK, sans déduction), défaut 0022 (OK), sources conflictuelles (WARN −1 pt, pas de cmd), pas de finding si tout OK ; `_fix_cmd()` par profil ; cohérence des constantes |
| `tests/test_ufw_logging.py` | Nouveau — 32 tests | `check_ufw_logging()` — off (ALERT, −2 pts, clé, clé déduction, cmd), low (OK, clé, sans déduction), medium (OK), high (INFO, clé, sans déduction), full (INFO) ; doublement déduction contexte public ; niveau affiché dans messages OK/INFO ; garde no-t |
| Fichiers existants | +7 tests | `tests/test_ports.py` : import `_SYSTEM_DAEMONS` ; UPnP appartenant à avahi → SYSTEM_INTERNAL ; UPnP appartenant à Spotify → UNCOVERED_PUBLIC ; propriétaire inconnu sur port système → SYSTEM_INTERNAL ; `test_auth_log.py` : days=0 OK utilise clé `no_logins_no_range` (message sans « 0 jour ») |

---

### v1.19.0 — 3259/3259 (2026-04-17)

**Plateforme :** Linux Mint 22.3 — `so6desktop` — Python 3.12.3, pytest 7.4.4

```
pytest tests/ -q
3259 passed in 3.77s
```

#### Nouveaux / modifiés (+530)

| Fichier | Modification | Couverture |
|---------|-------------|------------|
| `tests/test_hardening.py` | +29 tests | `TestTcpSyncookies` (6) : OK ≥1, désactivé WARN, déduction 1 pt ; `TestAcceptSourceRoute` (5) : OK false, activé WARN, déduction 1 pt ; `TestAcceptRedirectsV6` (5) : même motif ; `TestSendRedirects` (5) : même motif ; `TestProtectedHardlinks` (4) : OK true, désactivé WARN, déduction 1 pt, pas de déduction si OK ; `TestProtectedSymlinks` (4) : même motif ; `make_snapshot` gagne 6 nouveaux défauts |
| `tests/test_ssh.py` | +7 tests | `test_permit_root_login_no_is_ok`, `test_permit_root_login_prohibit_password_is_ok`, `test_permit_root_login_forced_commands_is_ok`, `test_permit_root_login_default_is_ok`, `test_permit_root_login_no_deduction_when_ok`, `test_permit_root_login_unknown_value_is_info`, `test_permit_root_login_no_no_alert` |
| Nouveaux fichiers de tests | +494 tests | `test_suid_audit.py`, `test_kernel_hardening.py`, `test_docker_audit.py`, `test_log_rotation.py`, `test_csv_output.py`, `test_markdown_output.py`, `test_min_level.py`, `test_watch.py` |

---

### v1.18.0 — 2729/2729 (2026-04-16)

**Plateforme :** Linux Mint 22.3 — `so6desktop` — Python 3.12.3, pytest 7.4.4

```
pytest tests/ -q
2729 passed in 3.12s
```

#### Nouveaux / modifiés (+222)

| Fichier | Modification | Couverture |
|---------|-------------|------------|
| `tests/test_mac_policy.py` | Nouveau — 40 tests | Défauts `MacPolicySnapshot` ; chemins `from_system()` ; `check_mac_policy()` — aucun MAC (WARN −1 pt), AppArmor inactif (WARN −1 pt), AppArmor actif sans enforce server (WARN −1 pt) / desktop (INFO), AppArmor enforcing (OK), SELinux enforcing (OK), SELinux permissive (WARN −1 pt) |
| `tests/test_backup.py` | Nouveau — 39 tests | Défauts `BackupSnapshot` ; niveaux de confiance actif vs. installé ; `check_backup()` — aucun outil server (WARN −1 pt), aucun outil desktop (INFO), installé seulement (INFO), outil actif (OK) ; skip_sections container |
| Autres fichiers modifiés | +143 tests | Divers fichiers de tests existants étendus pour le passage profils, listing noyaux, UX manage-logs, clés explain 76→86 |

---

### v1.17.0 — 2507/2507 (2026-04-15)

**Plateforme :** Linux Mint 22.3 — `so6desktop` — Python 3.12.3, pytest 7.4.4

```
pytest tests/ -q
2507 passed in 2.47s
```

#### Nouveaux tests / modifiés (+215)

| Fichier | Modification | Couverture |
|---------|-------------|------------|
| `tests/test_auditd.py` | Nouveau — 41 tests | Défauts `AuditdSnapshot` ; chemins `from_system()` ; `check_auditd()` — non installé (INFO), service inactif (WARN −1 pt), sans règles (WARN −1 pt), watches manquants server (WARN −1 pt) / desktop (INFO), tout OK (OK) |
| `tests/test_secure_boot.py` | Nouveau — 21 tests | Défauts `SecureBootSnapshot` ; méthodes de détection (mokutil/efivars/bootctl) ; `check_secure_boot()` — activé (OK), désactivé desktop (WARN −1 pt), désactivé server (INFO), no_uefi (INFO), inconnu (INFO) |
| `tests/test_file_integrity.py` | Nouveau — 33 tests | Défauts `FileIntegritySnapshot` ; `_check_age_days()` (date ancienne, future, invalide, vide) ; `check_file_integrity()` — non installé, BDD absente (cmds aide/tripwire), sans check, check trop ancien (date+jours dans t()), propre (ok) ; `TestCleanSystemFindingCount` ; `TestEdgeCases` (date invalide→ok, priorité no_db, repli outil inconnu) |
| `tests/test_explain.py` | +81 tests | `TestHasProfileVariants` (12 assertions) ; `TestRunExplainProfileVariants` (sections par profil pour les 17 clés avec variantes) ; `TestRunExplainUniform` (note jaune uniforme, pas de sections pour 8 clés uniformes) ; `test_known_key_shows_why_and_how_headers` mis à jour avec branchement variante/uniforme |
| Autres fichiers modifiés | +39 tests | `test_cli.py`, `test_desktop_apps.py`, `test_disk.py`, `test_fail2ban.py`, `test_hardening.py`, `test_ipv6.py`, `test_logs.py`, `test_memory.py`, `test_profiles.py`, `test_updates.py`, `test_virtualization.py` |

---

### v1.16.0 — 2292/2292 (2026-04-12)

**Plateforme :** Linux Mint 22.3 — `so6desktop` — Python 3.12.3, pytest 7.4.4

```
pytest tests/ -q
2292 passed in 2.21s
```

#### Nouveaux tests / modifiés (+153)

| Fichier | Modification | Couverture |
|---------|-------------|------------|
| `tests/test_desktop_apps.py` | Nouveau | Défauts `DesktopAppsSnapshot` ; clés `_KNOWN_APPS` en minuscules ; `from_system()` avec/sans applis en cours ; `check_desktop_apps()` — aucune appli (OK, pas de section), appli détectée (INFO par appli, clé section) ; sans déduction ; lookup nom d'affichage |
| `tests/test_ntp.py` | Nouveau | Défauts `NtpSnapshot` ; parsing `timedatectl show` ; détection service (timesyncd/chronyd/ntpd) ; `check_ntp()` — non installé (INFO), actif+synchronisé (OK), actif+non synchronisé (WARN −1 pt), inactif (WARN −1 pt) |
| `tests/test_fail2ban.py` | Nouveau — 42 tests | `_parse_jails()` — sortie vide, ligne "Jail list:", séparés par virgules ; défauts `Fail2banSnapshot` ; `from_system()` — chemin systemctl, repli ping, non installé ; `check_fail2ban()` — non installé (INFO), inactif (WARN −1 pt), sans jails (WARN −1 pt), jails actifs (OK), jail SSH détecté |
| `tests/test_rootkit.py` | Nouveau — 38 tests | Défauts `RootkitSnapshot` ; aucun outil installé (INFO) ; rkhunter installé — BDD fraîche (OK), BDD obsolète (WARN −1 pt) ; pas de scan (WARN −1 pt) ; scan trop ancien ≥30j (WARN −1 pt) ; scan récent (OK) ; repli chkrootkit |
| `tests/test_exit_codes.py` | Nouveau — 18 tests | `EXIT_OK=0`, `EXIT_WARNINGS=1`, `EXIT_ALERTS=2`, `EXIT_ERROR=3`, `EXIT_TARGET_MISSED=4` ; `_decide_exit()` — propre, avertissements seuls, alertes seules, target manquée prioritaire sur alertes/avertissements, target 0 désactivé |
| `tests/test_hardening.py` | −3 tests (fail2ban retiré) | Classe `TestFail2ban` supprimée ; tests composites mis à jour avec `log_martians=False` |
| `tests/test_explain.py` | 77→76 clés | `test_has_seventy_six_keys` ; `hardening.fail2ban_missing` retiré des assertions |

---

### v1.15.0 — 2139/2139 (2026-04-12)

**Plateforme :** Linux Mint 22.3 — `so6desktop` — Python 3.12.3, pytest 7.4.4

```
pytest tests/ -q
2139 passed in 1.98s
```

#### Nouveaux tests / modifiés (+93)

| Fichier | Modification | Couverture |
|---------|-------------|------------|
| `tests/test_smtp.py` | Nouveau — 31 tests ; passage qualité +9 | Défauts `SmtpSnapshot` ; `_LOCAL_BIND_RE` (loopback IPv4/IPv6, **`*` est exposé**, localhost, toutes interfaces, IPv6 entre crochets) ; non installé (OK, clé, sans déduction) ; installé non en écoute (INFO, clé, sans déduction, mta_name) ; localhost uniquement (INFO, clé, sans déduction) ; exposé (WARN, clé, déduction −1 pt, contexte=public, nature=improvement) ; `TestSmtpCmd` — postfix a `postconf` cmd + note redémarrage, exim/inconnu sans cmd ; `TestSmtpWildcardExposed` — `*`/`::` exposé, `::1` local |
| `tests/test_logs.py` | `TestDominantLocalSource` — 13 tests | Sous le seuil minimum → pas de détection ; que des IPs publiques → pas de détection ; seuil non atteint → pas de détection ; exactement 70% → détection ; au-dessus 70% → détection ; IP du top retournée ; count et pct retournés ; sources mixtes ; entrées vides |
| `tests/test_cli.py` | `TestApplyFlag` (12), `TestTargetFlag` (10), assertions mises à jour | `--apply` défaut False ; `--apply` sans `--fix` → erreur ; `--fix` seul = dry-run ; `--fix --apply` positionne les deux ; `--yes` requiert `--fix --apply` ; `--json --fix` dry-run OK ; `--quiet --fix` dry-run OK ; ordre indépendant ; `--target=N` valide 1–10 ; 0/11/float/non-numérique → erreur ; combiné avec `--profile` |
| `tests/test_fixes.py` | `TestDryRun` — 8 tests ; `make_config` gagne `apply=True` par défaut | Dry-run affiche le hint ; pas d'appel subprocess ; pas d'appel input ; aperçu cmd affiché ; message affiché ; éléments manuels affichés ; pas de sortie `applied` ; pas de sortie `done_summary` |
| `tests/test_explain.py` | Comptage clés 73→77 ; assertions user_accounts | `len(EXPLAIN_KEYS) == 77` ; `user_accounts.uid_zero`, `empty_password`, `expired_account`, `no_shadow` présents |

---

### v1.14.0 — 2045/2045 (2026-04-11)

**Plateforme :** Linux Mint 22.3 — `so6desktop` — Python 3.12.3, pytest 7.4.4

```
pytest tests/ -q
2045 passed in 2.46s
```

#### Nouveaux tests (+155)

| Fichier | Nb | Couverture |
|---------|-----|------------|
| `tests/test_samba.py` | 68 | Défauts snapshot ; non installé (INFO, sans déduction, clé, un seul finding) ; finding installé OK ; SMB1 détecté (ALERT, −2 pts, clé, clé déduction, protocole dans message, déduction unique pour plusieurs protocoles, nature=action, cmd) ; mots de passe nuls (ALERT, −3 pts, clé, nature=action, cmd) ; signature serveur désactivée (WARN, −1 pt, clé, nature=improvement, cmd) ; signature serveur auto (INFO, sans déduction) ; map_to_guest bad user (WARN, −1 pt, clé, nature=improvement) ; valeurs map_to_guest OK (sans finding) ; partage invité écriture (ALERT, −2 pts/partage, clé, nom partage dans message, plusieurs partages cumulatifs, nature=action, cmd) ; partage invité lecture (WARN, −1 pt/partage, cumulatif, nature=improvement) ; déductions combinées ; bind interfaces (INFO, sans déduction) ; cas limites (snapshot vide, no_t, constantes) |
| `tests/test_clamav.py` | 52 | Non installé (INFO, 0 pts, clé, un seul finding) ; finding installé OK ; freshclam absent (WARN, −1 pt) ; bd introuvable (WARN, −1 pt) ; bd très obsolète ALERT (−2 pts, seuil exact) ; bd obsolète WARN (−1 pt, seuil exact) ; bd fraîche OK ; clamd inactif (INFO, 0 pts, sans déduction) ; clamd actif (sans finding) ; pas de log scan (INFO) ; scan très ancien (WARN, −1 pt, seuil exact) ; scan ancien (WARN, −1 pt) ; scan récent OK ; cumulatif (pire cas 4 pts, parfait 0 pts) ; `_scan_age_days` (aujourd'hui=0, hier=1, 30 jours, invalide→None, vide→None) ; `_tail_lines` (n dernières lignes, moins de lignes, fichier vide) ; `_find_last_scan_date` (parse date fin, pas de logs→None, plus récent sur plusieurs logs) ; `from_system` (pas de binaire→non installé, socket→clamd actif, âge bd calculé) |
| `tests/test_explain.py` | +3 | `test_has_seventy_three_keys` — `len(EXPLAIN_KEYS) == 73` ; assertions clés ClamAV (4 clés) ; assertions clés Samba (6 clés) |
| `tests/test_compare.py` | +5 | `info_count` dans `AuditBaseline` (défaut 0, build_baseline, load_baseline rétro-compatible) ; `info_delta` dans `AuditDelta` (is_empty quand 0, info_delta calculé, affichage diminution, affichage augmentation) |

#### Nouveaux modules

- **`checks/samba.py`** — `GuestShare`, `SambaSnapshot.from_system()`, `check_samba()`, `_read_smb_conf()`, `_section_get()`, `_is_yes()`
- **`checks/clamav.py`** — `ClamAVSnapshot.from_system()`, `check_clamav()`, `_find_last_scan_date()`, `_tail_lines()`, `_scan_age_days()`

#### Modifications qualité

- `scoring.py` — propriété `info_count` ajoutée à `CheckEngine`
- `compare.py` — `AuditBaseline.info_count`, `AuditDelta.info_delta`, `build_baseline()`, `load_baseline()`, `compute_delta()`, `display_delta()` mis à jour
- `domain_scores.py` — domaine `samba` (7e) ; `_PREFIX_TO_DOMAIN["clamav"] = "hardening"`
- `explain.py` — groupe ClamAV (4 clés) + groupe Samba (6 clés) ; 63 → 73 clés

---

### v1.13.0 — 1890/1890 (2026-04-10)

**Plateforme :** Linux Mint 22.3 — `so6desktop` — Python 3.12.3, pytest 7.4.4

```
pytest tests/ -q
1890 passed in 1.75s
```

#### Nouveaux tests (+187)

| Fichier | Nb | Couverture |
|---------|-----|------------|
| `tests/test_disk.py` | 60 | Défauts snapshot ; smartctl absent (INFO, sans déduction, clé, détail) ; SMART virtuel (INFO, pas OK) ; SMART inconnu ; SMART PASSED (OK, clé, modèle dans message) ; SMART FAILED (ALERT, −3 pts, clé, cmd, nature=action) ; attributs critiques (réalloués/en attente/non corrigibles >0 → WARN −1 pt chacun) ; attributs NVMe (media_errors→uncorrectable, log_entries→pending) ; disques multiples ; partition ≥90% (WARN −1 pt), ≥80% (INFO) ; tout-correct OK ; parse_smart_attr ; cas limites |
| `tests/test_memory.py` | 37 | Défauts snapshot ; pas de swap (INFO, retour anticipé, sans déduction) ; usure SSD (WARN, −1 pt, clé, recommandé adapté au profil, cmd, server vs workstation) ; swap injustifié (WARN, sans déduction, garde 3 conditions : pas de WARN si ram<50%, swap<32Mo, swappiness≤recommandé) ; swappiness sous-optimal (INFO, cmd) ; profil-adapté (server→1, workstation→10) ; stats swap toujours affichées ; cas limites |
| `tests/test_explain.py` | +1 | `test_has_sixty_three_keys` — `len(EXPLAIN_KEYS) == 63` |

#### Nouveaux modules

- **`checks/disk.py`** — `DiskSnapshot.from_system()`, `check_disk()`, `_detect_block_devices()`, `_query_smart()`, `_parse_nvme_attrs()`, `_parse_smart_attr()`, `_read_partition_usage()`
- **`checks/memory.py`** — `MemorySnapshot.from_system()`, `check_memory()`, `_read_meminfo()`, `_read_swappiness()`, `_read_swap_devices()`, `_detect_swap_on_ssd()`
- **`display.py`** — `display_disk_partitions()`, `_disk_bar()`, `_gb_str()` ajoutés

---

### v1.11.0 — 1675/1675 (2026-04-07)

**Plateforme :** Linux Mint 22.3 — `so6desktop` — Python 3.12.3, pytest 7.4.4

```
pytest tests/ -q
1675 passed in 1.41s
```

### v1.10.0 — 1541/1541 (2026-04-07)

**Plateforme :** Linux Mint 22.3 — `so6desktop` — Python 3.12.3, pytest 7.4.4

```
pytest tests/ -q
1541 passed in 1.37s
```

#### Nouveaux tests (+209)

| Fichier | Nb | Couverture |
|---------|-----|-----------|
| `tests/test_display_explain_hint.py` | 25 | `normalize_key` ; appartenance à `EXPLAIN_KEYS` ; intégration `print_audit_summary` (hint affiché, clé normalisée, aucun hint pour clé inconnue ou vide, préfixe `?`, plusieurs findings, clé normalisée vs brute) |
| `tests/test_kernel_modules.py` | 48 | `lsmod` indisponible (INFO, retour anticipé) ; tout-correct ; modules FS risqués (WARN, −1 pt flat, clé, nature=improvement) ; modules réseau risqués (idem) ; combinés ; `_unload_cmd` (incl. guillemets injection shell) ; snapshot defaults ; ensemble `RISKY_MODULES` ; cas limites (None, doublons, guard mutation, max ≤2, normalisation majuscules) |
| `tests/test_cron_audit.py` | 47 | tout-correct ; pipe-to-shell (WARN, −2 pts flat, nature=action) ; scripts accessibles en écriture (WARN, −1 pt, cmd chmod) ; utilisateurs inattendus (INFO) ; combinés ; `_chmod_cmd` (incl. guillemets injection shell) ; regex `_PIPE_TO_SHELL_RE` paramétrée (sh, bash, zsh, /bin/sh, /usr/bin/bash ; non-correspondances) ; snapshot defaults ; cas limites |
| `tests/test_services_state.py` | 35 | `systemctl` indisponible (INFO, retour anticipé) ; tout-correct ; services inactifs (WARN, −1 pt par service) ; plafond −3 pts (findings émis même au-delà) ; ensemble `SECURITY_SERVICES` ; snapshot defaults ; cas limites (noms vides, doublons) |

#### Passage qualité — fichiers de tests étendus

| Fichier | Avant | Après | Ajouts principaux |
|---------|-------|-------|-------------------|
| `test_check_rules.py` | 19 | 29 | Assertions par clé (f.key == "rules.xxx") ; classes `TestOpenAny`/`TestDuplicates`/`TestIPv6Coverage`/`TestCombined` |
| `test_cli.py` | 25 | 63 | Tous les 25+ flags dans `TestDefaults` ; `TestWebhook`, `TestExplain`, `TestMutuallyExclusiveModes` |
| `test_compare.py` | 47 | 54 | `SimpleNamespace` pour objets de données ; `_make_delta()` au niveau module ; `skipif` Windows |
| `test_cron.py` | 52 | 62 | `TestOrdinal` paramétrisé ; jours semaine FR ; `_parse_dom("")` |
| `test_ddns.py` | 37 | 42 | Hostname entre guillemets ; valeur vide ; regex de repli ; règle malformée sans crash |
| `test_degraded.py` | 17 | 20 | Vrai `LogEntry` ; combinaisons pare-feu inactif + ports/règles vides |

#### Nouveaux modules

- **`checks/kernel_modules.py`** — `KernelModulesSnapshot.from_system()`, `check_kernel_modules()`, `RISKY_MODULES`, `_unload_cmd()`
- **`checks/cron_audit.py`** — `CronAuditSnapshot.from_system()`, `check_cron_audit()`, `_PIPE_TO_SHELL_RE`, `_chmod_cmd()`
- **`checks/services_state.py`** — `ServicesStateSnapshot.from_system()`, `check_services_state()`, `SECURITY_SERVICES`
- **`tests/test_display_explain_hint.py`** — tests d'intégration pour la Phase A1 (suggestion `--explain` dans le résumé)

---

### v1.8.0 — 1104/1104 (2026-04-06)

**Plateforme :** Linux Mint 22.3 — `so6desktop` — Python 3.12.3, pytest 7.4.4

```
pytest tests/ -v
1104 passed in 1.03s
```

#### Nouveaux tests (+138)

| Fichier | Nouveaux | Couverture |
|---------|----------|------------|
| `tests/test_ssh.py` | 93 | Audit SSH complet : non-installé (suggestion d'installation, commande distro), retour anticipé non-actif ; `_check_sshd_config` — 15 directives (incl. `AllowTcpForwarding` activé→WARN, `PubkeyAuthentication` désactivé→ALERT), Ciphers/MACs/KEX faibles, parse premier-gagne, accumulation de déductions ; `_check_private_keys` — DSA ALERT, RSA < 2048 ALERT, RSA ≥ 2048 OK, ed25519 OK, sans-passphrase WARN, illisible INFO ; `_check_authorized_keys` — vide/absent INFO, ok-supprimé-par-erreur, note from=, opts dépréciés ; `_check_ssh_dir_perms` — 700 ok, 755/777 warn ; `_check_client_config` — `StrictHostKeyChecking no` warn ; `_check_known_hosts` — ok, vide/absent info, détection de doublons sur hôtes séparés par virgule ; intégration + helpers |
| `tests/test_file_perms.py` | 45 | Tout-correct (4) ; modifiable-par-tous ALERT/déduction/clé/priorité/bit-002/multiple/sans-ok (7) ; trop-permissif WARN/plafond/4e-fichier (5) ; clés-hôtes WARN/plafond-2/3-warns (4) ; NOPASSWD-ALL WARN/déduction/clé/lignes-multiples/sans-OK (5) ; NOPASSWD-spécifique INFO/sans-déduction/constat-unique/sans-OK (4) ; combinés plafonds-indépendants/all-correct (5) ; `_is_nopasswd_all` parametrize vrai/faux (8) ; dataclass (2) |

#### Nouveaux modules

- **`checks/ssh.py`** — module d'audit SSH : `SSHSnapshot.from_system()`, `check_ssh()`, 6 sous-vérifications, parsing binaire des clés, suggestions d'installation adaptées à la distro
- **`checks/file_perms.py`** — fichiers sensibles & sudoers : `FilePermsSnapshot.from_system()`, `check_file_perms()`, détection modifiable-par-tous/trop-permissif/clés-hôtes-SSH/NOPASSWD

#### Corrections qualité

- Clé i18n `output.recommendation_label` — remplace le français codé en dur "Que faire ?" dans tous les locales
- `display.py` — les constats INFO affichent le texte `detail` en mode verbose (`-v`)
- `output.print_recommendation()` — import paresseux de `t()` pour éviter les imports circulaires
- `ssh.py` — vérifications `AllowTcpForwarding` et `PubkeyAuthentication` ajoutées ; détection de doublons dans `known_hosts` gère maintenant les champs hôtes séparés par virgule
- `file_perms.py` — fallback OSError sur stat() en `0o777` (pire cas) ; `_is_nopasswd_all` utilise une correspondance exacte stricte (`== "ALL"`) pour éviter les faux-positifs sur `NOPASSWD: ALL /bin/sh`

---

### v1.7.0 — 966/966 (2026-04-04)

**Plateforme :** Linux Mint 22.3 — `so6desktop` — Python 3.12.3, pytest 7.4.4

```
pytest tests/ -v
966 passed in Xs
```

#### Nouveaux tests (+38)

| Fichier | Nouveaux | Couverture |
|---------|----------|------------|
| `tests/test_profiles.py` | 36 | `load_profile()` : défaut/server/nom vide, repli nom inconnu, chargement depuis fichier ; `_load_from_path()` : nom/description/chaîne extends ; `[overrides]` : niveaux valides, niveau inconnu ignoré, valeur None ignorée ; `[skip_sections]` : liste de sections ; `apply_profile()` : skip supprime constat+déduction, downgrade info supprime déduction, remappage warn/alert, pas d'override passthrough, constats sans clé non modifiés ; `AuditProfile.should_skip_section()`, `override_for()` ; `_remove_deductions_for_key()` : correspondance/non-correspondance |
| `tests/test_compare.py` | 2 | `test_ephemeral_ports_excluded` (ports ≥ 32768 filtrés), `test_stable_ports_included` (32767 conservé) |
| `tests/test_ipv6.py` | 2 | `test_malformed_ss_output_returns_empty`, `test_malformed_ufw_lines_returns_empty` |

#### Nouveaux modules

- **`profiles.py`** — profils d'audit nommés, format INI, héritage `extends`, filtrage post-vérification `apply_profile()`
- **`data/profiles/`** — profils intégrés : `server.conf`, `workstation.conf`, `container.conf`

#### Corrections qualité (pas de nouveaux tests — suite existante valide)

- `Deduction.key: str = ""` — suppression déterministe de déduction par clé (remplace correspondance heuristique sur les chaînes traduites)
- `add_deduction(key=)` — toutes les déductions scorées dans `hardening.py` / `ipv6.py` portent des clés correspondantes
- `_find_profile_file()` décoré avec `@lru_cache(maxsize=32)` ; fixture de test vide le cache entre les tests
- Clés d'override normalisées `strip().lower()` dans `_load_from_path()`
- `--install-cron` : `prompt_emails()` — boucle de sélection multi-destinataires avec marqueurs ✔
- `--manage-cron` : suppression en lot `d:1,3` / `d:1-3` / `d:all` avec messages de confirmation adaptés

---

### v1.6.0 — 928/928 (2026-04-04)

**Plateforme :** Linux Mint 22.3 — `so6desktop` — Python 3.12.3, pytest 7.4.4

```
pytest tests/ -v
928 passed in Xs
```

#### Nouveaux tests (+162)

| Fichier | Nouveaux | Couverture |
|---------|----------|------------|
| `tests/test_hardening.py` | 49 | `HardeningSnapshot`, `check_hardening()` : système sain (entièrement durci), mises à jour automatiques (ok/warn/déductions), fail2ban (ok/info/pas de déduction), AppArmor (enforce/permissive/inactive/non installé/cas limites), rp_filter (1/2/0 + déductions), redirections ICMP, log_martians, broadcast ICMP ; déductions cumulatives ; `_parse_aa_count` (enforce/complain/singulier/espaces/casse) ; `_parse_apparmor_mode` (enforce/permissive/non_installé/inactive) |
| `tests/test_ipv6.py` | 33 | `IPv6Snapshot`, `check_ipv6()` : système sain, IPv6 désactivé (global/UFW/conflit), ports non couverts (warn/déduction/plafond 3), aucun non couvert ; `_extract_ipv6_listeners` (wildcard tcp/udp, pas de loopback, vide, malformé) ; `_extract_ufw_v6_covered` (règles v6, IPv4-only exclu, vide, désactivé, proto par défaut, malformé) |
| `tests/test_compare.py` | 49 | `build_baseline()` (score/alertes/warn, extraction ports/services, déduplication, timestamp) ; round-trip `save_baseline`/`load_baseline`, permissions (masque 0o077), écriture atomique (pas de .tmp), manquant/corrompu/type invalide/racine JSON incorrecte ; `compute_delta()` (deltas score/alertes/warn, ports apparus/fermés, services démarrés/arrêtés, timestamp précédent, aucun changement) ; `AuditDelta.is_empty()` (8 cas) ; `display_delta()` (12 tests de routage) |
| `tests/test_plugin_checks.py` | 31 | `load_plugin_checks()` : répertoire manquant, sans .py, valide, triés, skip invalide/syntaxe/non-.py/raise à l'import/import partiel ; `_load_one()` : valide, CHECK_NAME, repli nom fichier, pas de run_check, erreur syntaxe, surdimensionné, exactement 64 Ko, chemin stocké ; `PluginCheck.run()` : type CheckResult, findings ok/warn, exception → warn, mauvais retour → warn, propagation t, sans t, nom fichier dans le message d'erreur ; dérivation du nom (vide/espaces/non-string/ANSI/contrôle uniquement) |

#### Nouveaux modules

- **`checks/hardening.py`** — snapshot + vérification durcissement système (7 paramètres)
- **`checks/ipv6.py`** — cohérence ports IPv6 actifs / règles UFW v6
- **`compare.py`** — persistance baseline d'audit + calcul de delta + affichage
- **`plugin_checks.py`** — chargeur de plugins avec sanitisation ANSI et exécution fail-safe

---

### v1.5.0 — 766/766 (2026-04-04)

**Plateforme :** Linux Mint 22.3 — `so6desktop` — Python 3.12.3, pytest 7.4.4

```
pytest tests/ -v
766 passed in Xs
```

#### Nouveaux tests (+89)

| Fichier | Nouveaux | Couverture |
|---------|---------|------------|
| `tests/test_firewall_stack.py` | 38 | `FirewallStackSnapshot`, `check_firewall_stack()` : système propre, contournement INPUT, chaîne FORWARD avec Docker/WireGuard/libvirt, nftables (tables UFW, compat iptables, tables utilisateur), ip_forward avec tous les démons de routage ; `_parse_raw_accepts`, `_has_user_nft_rules` |
| `tests/test_network_context.py` | 51 | `NetworkContextSnapshot`, `check_network_context()` : système propre, interface tunnel (actif/inactif), port distant sensible (DB externe), suppression IP privée ; `_interface_type` (toutes catégories dont br0), `_parse_interfaces` (loopback exclu, état UP/DOWN, adresse), `_parse_connections` (extraction processus, saut en-tête), `_split_addr_port`, `_is_private_or_loopback`, `top_remote_ips` |

#### Nouveaux modules

- **`checks/firewall_stack.py`** — détecte les règles iptables ACCEPT brutes contournant UFW dans les chaînes INPUT/FORWARD, nftables en parallèle d'UFW, ip_forward sans démon de routage
- **`checks/network_context.py`** — tableau des interfaces réseau (E) + résumé des connexions TCP établies (C)

#### Bannière enrichie

- `SystemInfo` étendu avec `iptables_version` et `nftables_version`
- `print_banner()` étendu avec les lignes `kernel`, `iptables`, `nftables`
- Fixture `test_report.py` mise à jour (`iptables_version="1.8.9"`, `nftables_version=""`)

---

### v1.4.2 — 677/677 (2026-04-04)

#### Nouveaux tests (+1)

| Fichier | Test | Couverture |
|---------|------|------------|
| `tests/test_ports.py` | `test_netbios_covered_by_ufw_no_warn` | Ports NetBIOS 137/138 avec règle UFW explicite → COUVERT, aucune déduction |

**Correction :** `_categorize_port()` vérifiait la branche NetBIOS avant `_is_covered_by_ufw()` — les ports 137/138 étaient toujours classés `NETBIOS` même si une règle UFW existait. Correction : la vérification UFW est désormais effectuée en premier.

---

### v1.4.1 — 676/676 (2026-04-04)

Pas de nouveaux tests. Correctif : `--install-completion` absent de la liste `long_opts` de la complétion bash — la complétion TAB ne suggérait pas ce flag.

---

### v1.4.0 — 676/676 (2026-04-04)

**Plateforme :** Linux Mint 22.3 — `so6desktop` — Python 3.12.3, pytest 7.4.4

#### Nouveaux tests (+24)

| Fichier | Nouveaux | Couverture |
|---------|---------|------------|
| `tests/test_scoring.py` | 6 | `TestFinding` : valeurs `FindingLevel`, champ `nature`, champs optionnels `cmd`/`note`/`detail` |
| `tests/test_ports.py` | 9 | Findings process-aware : `WARN` (pas `ALERT`) pour processus identifiés ; champ `note` renseigné ; deny par défaut supprime `UNCOVERED_PUBLIC` |
| `tests/test_registry.py` | 4 | Isolation plugins : `load_plugins()` avec répertoire temporaire ; JSON invalide ignoré ; validation format port |
| `tests/test_cli.py` | 5 | Flags `--json`, `--json-full`, `--offline`, `--quiet`, `--verbose` paramétrés |

---

### v1.3.0 — 652/652 (2026-03-31)

**Plateforme :** Linux Mint 22.3 — `so6desktop` — Python 3.12.3, pytest 7.4.4

#### Nouveaux tests (+13)

| Fichier | Nouveaux | Couverture |
|---------|---------|------------|
| `tests/test_sysinfo.py` | 11 | `get_public_ip()` : repli 3 fournisseurs (ipify → ifconfig.me → icanhazip) ; flag offline ; détection IP publique IPv6 ; ULA/link-local exclus |
| `tests/test_cli.py`     | 2  | Parsing du flag `--offline`/`-o` |

---

### v1.2.0 — 639/639 (2026-03-30)

Pas de nouveaux tests. Passe qualité : 12 corrections défensives sur 8 modules (i18n, chemins, logs, registre, scoring, sysinfo, rapport_markdown, sortie). Tous les tests existants restent verts.

---

### v1.1.0 — 639/639 (2026-03-30)

**Plateforme :** Linux Mint 22.3 — `so6desktop` — Python 3.12.3, pytest 7.4.4

#### Nouveaux tests (+20)

| Fichier | Nouveaux | Couverture |
|---------|---------|------------|
| `tests/test_services.py` | 12 | `_wrap_for_box()` : cas limites de retour à la ligne ; regex `listen_port` vsftpd ; `rpc-port` JSON Transmission |
| `tests/test_output.py`   | 8  | `_visual_width()` avec Unicode large (emoji) ; formule overhead padding des boîtes |

---

### v0.21 — 619/619 (2026-03-28)

**Plateforme :** Linux Mint 22.3 — `so6minttest` — Python 3.12.3, pytest 7.4.4

```
pytest tests/ -v
619 passed in Xs
```

#### Nouveaux tests ajoutés (+78)

| Fichier | Nouveaux | Couverture |
|---------|---------|-----------|
| `tests/test_virtualization.py` | 24 | `check_virtualization()` : snapshot vide, libvirt/VirtualBox/VMware/LXD, paquets snap, préfixes interface (virbr/vboxnet/vmnet/lxdbr/lxcbr) |
| `tests/test_email_store_mgmt.py` | 24 | `_manage_email_store()` : quitter, ajout valide/invalide/doublon, supprimer tout, supprimer par numéro, liste virgule, plage, hors limites, saisie invalide |
| `tests/test_services.py` | 16 | `_classify_exposure` : CGNAT, ULA IPv6 (fc/fd), link-local (fe80), loopback (::1), régression IP publique ; `TestAutoDetectPort` (9) : directives, lignes commentées, fichier manquant, proto |
| `tests/test_cli.py` | 10 | `TestMutuallyExclusiveModes` : 6 paires invalides → `CLIError` ; 4 cas mode-unique valides |
| `tests/test_logs.py` | 7 | `_max_in_window` : frontière 60s (incluse), 61s (exclue), désordre ; `_detect_bruteforce` : frontière seuil, IPs différentes, timestamps désordonnés |

#### Corrections de bugs

- **`checks/services.py` — `_classify_exposure`** : CGNAT (`100.64/10`) et IPv6 privé (`::1`, `fe80:`, ULA `fc/fd`) classés `OPEN_WORLD` au lieu de `OPEN_LOCAL` (faux positif). Corrigé avec la constante `_PRIVATE_ADDR`.
- **`checks/services.py` — `_auto_detect_port`** : Lignes de config commentées (`# port = 2121`) matchées par le regex. Corrigé en supprimant les commentaires avant la recherche.
- **`cli.py` — `parse_args`** : `--manage-logs`, `--install-cron`, `--manage-cron` et `--fix` n'étaient pas mutuellement exclusifs. Toute combinaison invalide lève désormais `CLIError`.

#### Nouvelle fonctionnalité

- **`--manage-cron` — carnet d'adresses email** : Nouvelle commande `m` pour gérer l'`EmailStore` directement. Ajouter une adresse validée (`a`), supprimer par numéro, liste virgule (`1,3`), plage (`1-3`), ou tout effacer (`all`).

---

### v0.20 — 548/548 (2026-03-28)

**Plateforme :** Linux Mint 22.3 — `so6minttest` — Python 3.12.3, pytest 7.4.4

```
pytest tests/ -v
548 passed in Xs
```

#### Nouveaux tests ajoutés

**`tests/test_degraded.py`** — 17 tests (nouveau fichier)

| Classe | Tests | Couverture |
|--------|-------|-----------|
| `TestSSNotAvailable` | 4 | `check_ports` avec `PortsSnapshot` vide (pas de ports, pas de ss_output) → OK, zéro déductions |
| `TestCheckRulesEmptyOutput` | 5 | `check_rules` avec `""`, espaces ou entête-seul → zéro déductions, pas d'alerte |
| `TestLogFileDegraded` | 4 | `log_found=False` → INFO + zéro déductions ; entrées vides → OK + zéro déductions |
| `TestCombinedDegradation` | 4 | Les trois modules dégradés simultanément — pas de crash, zéro déductions cumulées |

---

### v0.18 — 531/531 (2026-03-28)

**Plateforme :** Linux Mint 22.3 — `so6minttest` — Python 3.12.3, pytest 7.4.4

```
pytest tests/ -v
531 passed in Xs
```

#### Nouveaux tests ajoutés

**`tests/test_fixes.py`** — 26 tests (nouveau fichier)

| Classe | Tests | Couverture |
|--------|-------|-----------|
| `TestItemClassification` | 6 | `action+cmd` → auto ; `action` sans cmd → compté mais non bouclé ; `improvement`/`structural`/`ok` → ignorés |
| `TestDeleteSortOrder` | 2 | Ordre de suppression par index décroissant ; non-delete après les deletes |
| `TestNoItems` | 2 | Engine vide et engine OK-only → `fixes.none` ; pas de subprocess/input |
| `TestSubprocessSuccess` | 2 | `returncode=0` → `fixes.applied` ; commande correctement découpée |
| `TestSubprocessFailure` | 2 | Retour non nul → `fixes.manual` ; code de sortie dans la sortie |
| `TestSubprocessTimeout` | 2 | `TimeoutExpired` → `fixes.manual` ; `OSError` → `fixes.manual` |
| `TestInteractiveNo` | 2 | `input()="n"` → subprocess ignoré ; item affiché comme manuel |
| `TestAutoMode` | 3 | `config.yes=True` → pas d'`input()` ; tous les items appliqués ; bannière auto affichée |
| `TestAutoSummary` | 3 | Résumé après run `--yes` ; pas de résumé en cas d'échec ; commandes appliquées listées |
| `TestDoneMessage` | 1 | `fixes.done` affiché en fin (non affiché sur sortie anticipée) |

---

### v0.17 — 505/505 (2026-03-28)

**Plateforme :** Linux Mint 22.3 — `so6minttest` — Python 3.12.3, pytest 7.4.4

```
pytest tests/ -v
505 passed in Xs
```

#### Nouveaux tests ajoutés (travail v0.16, inclus dans le compte v0.17)

**`tests/test_services.py`** — 52 tests (précédemment 34)
- `TestPortExposureFindings` — 5 nouveaux tests :
  - `test_loopback_no_rule_adds_info` — `Exposure.LOOPBACK_NO_RULE` émet un finding INFO
  - `test_loopback_no_rule_no_deduction` — aucune déduction de score
  - `test_not_listening_no_finding` — `Exposure.NOT_LISTENING` n'émet aucun finding
  - `test_not_listening_no_deduction` — aucune déduction
  - `test_mixed_listening_and_not_listening` — seul le port en écoute génère un finding
- `TestExposureOverrides` — 5 nouveaux tests vérifiant la logique d'override dans `ServiceSnapshot.collect()` directement
- `TestPanoramaNewVariants` — 6 nouveaux tests vérifiant l'indicateur UFW de `build_panorama_rows()` pour tous les variants d'exposition (LOOPBACK, LOOPBACK_NO_RULE, NOT_LISTENING → `ok` ; NO_RULE → `none` ; OPEN_WORLD → `warn`)

#### Échecs préexistants corrigés (15 au total)

| Fichier | Nb | Cause racine |
|---------|----|-------------|
| `test_check_rules.py` | 2 | `FindingLevel.WARNING` → `FindingLevel.WARN` (faute de frappe) |
| `test_firewall.py` | 4+1 | `TestIPv6Consistency` appelait `check_firewall()` — le check IPv6 est dans `check_rules()` ; scénario combiné corrigé pour appeler les deux fonctions |
| `test_cli.py` | 2 | `parse_args(["-y"])` lève CLIError — `--yes` requiert `--fix` |
| `test_docker.py` | 4 | `check_docker` émet `warn` et non `alert` pour bypass iptables ; déduction uniquement en contexte `public` |
| `test_ddns.py` | 1 | `_extract_duckdns_domain` matchait `www.duckdns.org` au lieu de parser `?domains=myhost` |
| `test_cron.py` | 2 | `cron_to_human("0 */6 * * 1-5")` prenait le chemin DOW — garde `dow != "*"` insuffisante pour les plages |

#### Corrections de code (comportement, pas seulement les tests)

- **`checks/ddns.py` — `_extract_duckdns_domain`** : parse désormais le paramètre `?domains=` en priorité, reconstruit `myhost.duckdns.org` ; retombe sur le regex direct pour les domaines déjà formés.
- **`cron.py` — `cron_to_human`** : le chemin DOW vérifie maintenant `re.fullmatch(r"[\d,]+", dow)` — les plages comme `1-5`, les pas comme `*/2` et les noms de jours tombent dans le fallback expression personnalisée.

---

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
| `✖ [ALERTE]` Port 22/tcp — ouvert à internet — aucune restriction source dans UFW | ✔ v0.15.1 |
| Contexte risque CRITIQUE affiché | ✔ v0.15.1 |
| Déduction score `-2` (contexte NAT/local) | ✔ v0.15.1 |
| Panorama : SSH `⚠` (OPEN_WORLD) | ✔ v0.15.1 |
| DDNS `→ 22/tcp` | ✔ v0.15.1 |
| **Remédiation :** restriction source → passe en OPEN_LOCAL (WARN non ALERTE, sans déduction) | ✔ v0.15.1 |

> **Note :** `openssh-server` doit être installé et actif (`sudo apt install openssh-server && sudo systemctl enable --now ssh`). Si inactif/désactivé, le service est en INFO uniquement sans vérification d'exposition des ports.

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
| `⚠ [AVERTISSEMENT]` Port 80/tcp — ouvert à internet — aucune restriction source dans UFW | ✔ v0.15.1 |
| Contexte risque MOYEN affiché | ✔ v0.15.1 |
| Déduction score `-1` | ✔ v0.15.1 |
| Panorama : Nginx `⚠` | ✔ v0.15.1 |
| Résultat dans *Améliorations possibles* (et non *Action requise*) | ✔ v0.15.1 |

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
| `✖ [ALERTE]` Port 445/tcp — ouvert à internet — aucune restriction source dans UFW | ✔ v0.15.1 |
| `✖ [ALERTE]` Port 139/tcp — ouvert à internet | ✔ v0.15.1 |
| Contexte risque CRITIQUE affiché (vecteur ransomware, EternalBlue) | ✔ v0.15.1 |
| Déduction `-2` × 2 ports (−4 total) | ✔ v0.15.1 |
| Panorama : Samba `⚠` (OPEN_WORLD) | ✔ v0.15.1 |
| Les deux ports dans le bloc *Action requise* | ✔ v0.15.1 |
| DDNS `→ 445/tcp`, `→ 139/tcp` | ✔ v0.15.1 |

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
| Serveur VNC | 5900/tcp | Pas d'alerte service — VNC non détecté | ✔ v0.15.1 |
| Serveur FTP | 21/tcp | Pas d'alerte service — FTP non détecté | ✔ v0.15.1 |
| PostgreSQL | 5432/tcp | Pas d'alerte service — PostgreSQL non détecté | ✔ v0.15.1 |
| Mosquitto (MQTT) | 1883/tcp | `ℹ [INFO]` 1883/tcp loopback — règle UFW sans effet ; 8883/tcp non en écoute — aucun message ; Panorama ✔ | ✔ v0.15.1 ² |
| WireGuard | 51820/udp | `ℹ [INFO]` WireGuard installé mais arrêté/désactivé — pas de vérification d'exposition (retour anticipé INACTIVE) | ✔ v0.15.1 ¹ |
| Gitea | 3000/tcp | Pas d'alerte service — Gitea non détecté | ✔ v0.15.1 |
| Jellyfin | 8096/tcp | Pas d'alerte service — Jellyfin non détecté | ✔ v0.15.1 |
| Home Assistant | 8123/tcp | Pas d'alerte service — HASS non détecté | ✔ v0.15.1 |
| Cockpit | 9090/tcp | Pas d'alerte service — Cockpit non détecté | ✔ v0.15.1 |

> Pour tous les cas ci-dessus : le port n'a pas de listener actif — aucune ALERTE dans ANALYSE DES SERVICES RÉSEAU.
> Vérification croisée DDNS : aucun de ces ports ne doit apparaître dans la liste exposée DDNS (aucun listener actif — correction v0.14.1).

> ¹ WireGuard était déjà installé (mais inactif) sur la VM de test. Le chemin « non installé » reste non testé — comportement confirmé : service INACTIVE avec une règle UFW ouverte → INFO uniquement, pas d'ALERTE, pas de déduction.

> ² Mosquitto était installé et ACTIF sur la VM de test (ne correspond pas au scénario C6 « non installé »). Le test a révélé un bug : les ports du registre non en écoute (8883/tcp) déclenchaient incorrectement `Exposure.NO_RULE` → panorama ✖. Corrigé en beta (commit `67743ca`) : `Exposure.NOT_LISTENING` pour les ports du registre non en écoute → panorama ✔.

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
| `ℹ [INFO]` Port 631/tcp — lié uniquement sur localhost — la règle UFW n'a aucun effet | ✔ v0.15.1 |
| Pas d'ALERTE, pas de déduction de score (binding loopback) | ✔ v0.15.1 |
| Panorama : CUPS `✔` (règle existe, loopback → INFO) | ✔ v0.15.1 |

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
| Test direct | ✔ v0.15.1 |

---

### D2 — Règles IPv4 et IPv6 toutes deux présentes (pas d'avertissement)

| Attendu | Résultat |
|----------|----------|
| `✔ [OK]` Règles IPv4 et IPv6 toutes deux présentes | ✔ unit test |
| Aucune déduction | ✔ unit test |
| Test direct | ✔ v0.15.1 |

---

## Observations supplémentaires

### Obs — Avahi affiche ✖ au panorama malgré message INFO (problème connu, v0.16)

Avahi écoute sur `0.0.0.0:5353/udp` (multicast mDNS). Aucune règle UFW pour 5353 → `Exposure.NO_RULE` → panorama ✖. Le check service émet correctement `ℹ [INFO]` "couvert par la politique deny par défaut", mais le symbole panorama est déterminé par la valeur enum `NO_RULE` indépendamment de la sévérité INFO.

**Cause racine :** `NO_RULE` sur un port non-loopback, non exposé publiquement (multicast/LAN uniquement en pratique) est traité identiquement à `NO_RULE` sur un port réellement exposé. Un fix futur pourrait introduire `Exposure.NO_RULE_MULTICAST` ou un mécanisme plus large pour distinguer les `NO_RULE` à portée locale des `NO_RULE` réellement exposés.

**Impact :** cosmétique uniquement — pas de fausse ALERTE, pas de déduction de score.

---



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

### C8 — SSH restreint au LAN (chemin OPEN_LOCAL)

```bash
sudo ufw delete allow 22/tcp
sudo ufw allow from 192.168.1.0/24 to any port 22 proto tcp
sudo ufw-audit
```

| Attendu | Résultat |
|---------|----------|
| `⚠ [AVERTISSEMENT]` Port 22/tcp — restreint au réseau local par règle UFW | ✔ v0.16 |
| Pas de déduction score (OPEN_LOCAL ≠ OPEN_WORLD) | ✔ v0.16 |
| Panorama : SSH `✔` (restriction LAN = config correcte) | ✔ v0.16 |
| DDNS : `ℹ` Port 22/tcp restreint au réseau local (pas d'ALERTE) | ✔ v0.16 |
| Contexte risque CRITIQUE toujours affiché | ✔ v0.16 |

> **Nettoyage :** `sudo ufw delete allow from 192.168.1.0/24 to any port 22 proto tcp && sudo ufw allow 22/tcp`

---



### E1 — Port écoutant sur localhost uniquement, sans règle UFW — INFO pas ALERTE

```bash
# Tout processus lié exclusivement à 127.0.0.1 sans règle UFW
# Redis par défaut : bind 127.0.0.1 — aucune règle UFW nécessaire
sudo ufw-audit
```

| Attendu | Résultat |
|----------|----------|
| `ℹ [INFO]` Port 6379/tcp — lié uniquement à localhost — aucune règle UFW requise (couvert par refus par défaut) | ✔ v0.15.1 |
| Pas d'ALERTE, pas de déduction de score | ✔ v0.15.1 |
| Panorama Redis ✔ | ✔ v0.15.1 |
| Message utilise la clé locale `services.exposure.loopback_no_rule` (ajoutée avec le fix `Exposure.LOOPBACK_NO_RULE`) | ✔ v0.15.1 |

> **Note :** Le message attendu initialement référençait `ports.uncovered_local`. En pratique, Redis sur loopback sans règle UFW est traité par le chemin services (`Exposure.LOOPBACK_NO_RULE`), pas le chemin ports. La clé `ports.uncovered_local` s'applique aux ports de processus non couverts par le registre de services.
