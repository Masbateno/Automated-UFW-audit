# Automatisation — UFW-AUDIT

Ce document explique comment configurer UFW-AUDIT pour s'exécuter automatiquement chaque nuit et vous notifier en cas de problème.

---

## Installation rapide

```bash
sudo ufw-audit --install-cron
```

L'assistant vous pose deux questions :

1. **Heure d'exécution** (défaut : `03:00`)
2. **Email de notification** (optionnel — laissez vide pour désactiver)

Il crée ensuite :

- `/usr/local/bin/ufw-audit-nightly` — script wrapper
- `/etc/cron.d/ufw-audit` — entrée cron système

---

## Prérequis pour l'email

La notification utilise la commande `mail` (paquet `mailutils`).

```bash
sudo apt install mailutils
```

La notification est envoyée **uniquement si l'audit détecte des alertes ou des avertissements** (code de sortie > 0). Si votre configuration est saine, vous ne recevez rien.

---

## Contenu généré

### `/usr/local/bin/ufw-audit-nightly`

```bash
#!/bin/bash
NOTIFY_EMAIL="vous@exemple.com"
LOG_DIR="/home/user/.local/share/ufw-audit/logs"

ufw-audit --quiet --detailed
RC=$?

if [ "$RC" -gt 0 ] && [ -n "$NOTIFY_EMAIL" ]; then
    LOG=$(ls -t "$LOG_DIR"/ufw_audit_*.log 2>/dev/null | head -1)
    if [ -n "$LOG" ]; then
        mail -s "UFW-AUDIT [$RC] $(hostname)" "$NOTIFY_EMAIL" < "$LOG"
    fi
fi
```

### `/etc/cron.d/ufw-audit`

```
0 3 * * *  root  /usr/local/bin/ufw-audit-nightly
```

---

## Gestion des rapports

Pour lister et supprimer les rapports générés :

```bash
sudo ufw-audit --manage-logs
```

Interface interactive :

```
  [GESTION DES RAPPORTS]

  Rapports dans : /home/user/.local/share/ufw-audit/logs

  [ 1]  ufw_audit_20260323_030012.log  (4 Ko)  2026-03-23 03:00
  [ 2]  ufw_audit_20260322_030011.log  (3 Ko)  2026-03-22 03:00

  Numéro pour supprimer, 'all' pour tout supprimer, Entrée pour quitter
  >
```

---

## Modifier la configuration

Pour changer l'heure ou l'email :

```bash
sudo ufw-audit --install-cron
```

Répond « oui » à la question de remplacement — les fichiers sont régénérés.

---

## Désinstaller

```bash
sudo rm /etc/cron.d/ufw-audit
sudo rm /usr/local/bin/ufw-audit-nightly
```

L'emplacement des logs reste configuré dans `~/.config/ufw-audit/config.conf`.
Pour le réinitialiser : `sudo ufw-audit --reconfigure`.
