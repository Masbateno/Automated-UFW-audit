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

---

## Configuration Postfix pour v0.12+ (Emails HTML)

À partir de **v0.12.0b**, les rapports cron sont envoyés au format HTML (MIME multipart/alternative) plutôt que texte brut. Pour une livraison fiable, Postfix doit être correctement configuré avec :

1. **Réécriture d'adresse d'expéditeur**
2. **Authentification SASL** (si utilisation d'un relais SMTP)

### Problèmes courants

#### 1. Erreur : « 553 bad address format »

Si vous voyez cette erreur dans `/var/log/mail.log` :

```
550 5.5.1 bad address format (in reply to MAIL FROM command)
```

**Cause :** Postfix envoie l'email avec l'adresse système `root@hostname.local` (domaine non valide).

**Solution :** Configurer `sender_canonical_maps` pour réécrire les adresses système :

```bash
sudo bash -c 'cat > /etc/postfix/sender_canonical << EOF'
/^root@/ votre.email@exemple.com
EOF

sudo postmap /etc/postfix/sender_canonical
sudo postconf -e "sender_canonical_maps = regexp:/etc/postfix/sender_canonical"
sudo systemctl restart postfix
```

#### 2. Erreur : « 530 Authentication required »

Si votre serveur SMTP requiert une authentification :

```bash
# Créer le fichier de credentials
sudo bash -c 'cat > /etc/postfix/sasl_passwd << EOF'
smtp.exemple.com utilisateur@exemple.com:MOTDEPASSE
EOF

# Protéger le fichier
sudo chmod 600 /etc/postfix/sasl_passwd

# Créer la base de données
sudo postmap /etc/postfix/sasl_passwd

# Configurer Postfix
sudo postconf -e "smtp_sasl_auth_enable = yes"
sudo postconf -e "smtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd"
sudo postconf -e "smtp_use_tls = yes"

# Redémarrer
sudo systemctl restart postfix
```

### Format des emails v0.12+

Les emails contiennent maintenant :

- **Version texte** : contenu brut (compatible avec tous les clients)
- **Version HTML** : rendu stylisé (clients modernes uniquement)

Postfix envoie un message MIME `multipart/alternative` que le client de messagerie affiche selon ses capacités.

### Vérifier la configuration

```bash
# Inspecter un email dans mail.log
sudo grep "UFW-AUDIT" /var/log/mail.log | tail -10

# Format attendu avec succès
status=sent (250 Message to be delivered)
```

### Tester manuellement

```bash
# Générer un rapport HTML test
sudo ufw-audit --quiet --detailed

# Obtenir le dernier fichier log
LOG=$(ls -t ~/.local/share/ufw-audit/logs/ufw_audit_*.log 2>/dev/null | head -1)

# Envoyer via le script v0.12
sudo python3 << 'PYTHON_EOF'
from ufw_audit.report_markdown import send_audit_log_as_html_email
send_audit_log_as_html_email(
    log_file="$LOG",
    recipient="votre.email@exemple.com",
    subject="[TEST] UFW-AUDIT Email HTML"
)
PYTHON_EOF
```

### Notes techniques

- Le script nightly généré exporte automatiquement `PYTHONPATH` pour les imports Python
- L'enveloppe SMTP utilise `sendmail -t -f` pour contrôler l'adresse d'expéditeur
- Pas de dépendances externes (HTML généré en pur Python)
