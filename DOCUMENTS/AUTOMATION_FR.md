*[Read in English](AUTOMATION.md)*

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

Liste tous les crons installés avec leur planning et leur email de notification. Le menu boucle jusqu'à ce que vous quittiez explicitement :

```
  1. nightly              tous les jours à 03:00
     → email: vous@exemple.com
  2. weekly-monday        tous les lundi à 02:00

  Numéro pour modifier, 'e:N' pour l'email, 'd:N' pour supprimer, 'm' pour le carnet d'adresses, Entrée pour quitter
  >
```

| Commande | Action |
|----------|--------|
| `N` | Modifier le cron N — choisir entre planning ou email de notification |
| `e:N` | Modifier directement l'email de notification du cron N |
| `d:N` | Supprimer le cron N et son script associé |
| `m` | Ouvrir le carnet d'adresses email (voir ci-dessous) |
| Entrée / `q` | Quitter |

Après chaque action, le menu se réaffiche pour enchaîner plusieurs opérations.

---

## Supprimer un cron

Entrez `d:N` pour supprimer le cron numéro N :

```
  1. nightly              tous les jours à 03:00

  Numéro pour modifier, 'e:N' pour l'email, 'd:N' pour supprimer, 'm' pour le carnet d'adresses, Entrée pour quitter
  > d:1
  Supprimer le cron 'nightly' ? [y/N] y
  ✔ Cron 'nightly' supprimé
```

---

## Carnet d'adresses email

Le carnet d'adresses (`m`) permet de gérer les adresses de notification enregistrées indépendamment des crons. Il est accessible même sans cron installé :

```
  ╔════════════════════════════════════════════════════════════╗
  ║  CARNET D'ADRESSES EMAIL                                     ║
  ╚════════════════════════════════════════════════════════════╝

  1. vous@exemple.com
  2. admin@exemple.com

  Numéro à supprimer, '1,3' ou '1-3' pour une sélection, 'all' pour tout supprimer, 'a' pour ajouter, Entrée pour quitter
  >
```

| Commande | Action |
|----------|--------|
| `a` | Ajouter une nouvelle adresse validée |
| `N` | Supprimer l'adresse N |
| `1,3` | Supprimer les adresses 1 et 3 |
| `1-3` | Supprimer les adresses 1, 2 et 3 |
| `all` | Supprimer toutes les adresses enregistrées |
| Entrée / `q` | Revenir au menu de gestion des crons |

Les adresses enregistrées ici sont proposées comme suggestions à chaque fois que `--install-cron` ou `--manage-cron` demande un email de notification.

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
