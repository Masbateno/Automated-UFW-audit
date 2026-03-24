# Automatisation — UFW-AUDIT

Ce document explique comment configurer UFW-AUDIT pour s'exécuter automatiquement selon un planning et vous notifier en cas de problème.

---

## Configuration rapide

```bash
sudo ufw-audit --install-cron
```

Le wizard vous guide en 4 étapes :

1. **Nom** — un court libellé pour ce cron (ex : `nightly`, `weekly`). Appuyez sur Entrée pour utiliser le nom suggéré.
2. **Planification** — choisissez parmi :
   - Tous les jours
   - Certains jours de la semaine (ex : `1 3 5` pour Lun/Mer/Ven)
   - Certains jours du mois (ex : `1 15` pour le 1er et le 15)
   - Expression cron personnalisée (ex : `0 3 * * 1`)
3. **Heure** — heure d'exécution au format `HH:MM` (défaut : `03:00`). Non affichée pour les expressions personnalisées.
4. **Email** — adresse de notification optionnelle. Laissez vide pour désactiver.

Un aperçu en langage naturel est affiché avant confirmation :
```
  → Planification : tous les lundi, mercredi, vendredi à 02:30
```

### Fichiers créés

- `/usr/local/bin/ufw-audit-{nom}` — script wrapper
- `/etc/cron.d/ufw-audit-{nom}` — entrée cron système

---

## Gestion des crons

```bash
sudo ufw-audit --manage-cron
```

Liste tous les crons installés avec leur planning et leur email de notification :

```
  1. nightly              tous les jours à 03:00
     → email: vous@exemple.com
  2. weekly-monday        tous les lundi à 02:00

  Numéro pour modifier le planning, 'd:N' pour supprimer, Entrée pour quitter
  >
```

- Entrez un **numéro** pour modifier le planning de ce cron (relance le wizard de planification)
- Entrez **`d:N`** pour supprimer le cron N et son script associé
- Appuyez sur **Entrée** pour quitter

---

## Supprimer un cron

```bash
sudo ufw-audit --remove-cron
```

Liste tous les crons installés et demande lequel supprimer :

```
  1. nightly              tous les jours à 03:00

  Numéro à supprimer, Entrée pour quitter
  > 1
  ✔ Cron supprimé : /etc/cron.d/ufw-audit-nightly
  ✔ Script supprimé : /usr/local/bin/ufw-audit-nightly
```

---

## Prérequis pour l'email

La notification utilise la commande `mail` (paquet `mailutils`) :

```bash
sudo apt install mailutils
```

La notification est envoyée **uniquement si l'audit détecte des alertes ou des avertissements** (code de sortie > 0). Si votre configuration est saine, vous ne recevez rien.

---

## Format des fichiers cron (v0.13+)

Chaque fichier cron inclut des métadonnées en commentaires pour l'identification :

```
# UFW-AUDIT cron — generated 2026-03-24 by ufw-audit --install-cron
# name: nightly
# email: vous@exemple.com
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

0 3 * * *  root  /usr/local/bin/ufw-audit-nightly
```

---

## Gestion des rapports

Pour lister et supprimer les rapports générés :

```bash
sudo ufw-audit --manage-logs
```

---

## Configuration Postfix pour les emails HTML (v0.12+)

À partir de **v0.12**, les rapports cron sont envoyés au format HTML (MIME multipart/alternative) plutôt que texte brut. Pour une livraison fiable, Postfix doit être correctement configuré avec :

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
sudo bash -c 'cat > /etc/postfix/sender_canonical << EOF
/^root@/ votre.email@exemple.com
EOF'

sudo postmap /etc/postfix/sender_canonical
sudo postconf -e "sender_canonical_maps = regexp:/etc/postfix/sender_canonical"
sudo systemctl restart postfix
```

#### 2. Erreur : « 530 Authentication required »

Si votre serveur SMTP requiert une authentification :

```bash
# Créer le fichier de credentials
sudo bash -c 'cat > /etc/postfix/sasl_passwd << EOF
smtp.exemple.com utilisateur@exemple.com:MOTDEPASSE
EOF'

sudo chmod 600 /etc/postfix/sasl_passwd
sudo postmap /etc/postfix/sasl_passwd

sudo postconf -e "smtp_sasl_auth_enable = yes"
sudo postconf -e "smtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd"
sudo postconf -e "smtp_use_tls = yes"

sudo systemctl restart postfix
```

### Vérifier la configuration

```bash
sudo grep "UFW-AUDIT" /var/log/mail.log | tail -10
# Attendu : status=sent (250 Message to be delivered)
```

### Notes techniques

- Le script généré exporte automatiquement `PYTHONPATH` pour les imports Python
- L'enveloppe SMTP utilise `sendmail -t -f` pour contrôler l'adresse d'expéditeur
- Pas de dépendances externes (HTML généré en pur Python)
