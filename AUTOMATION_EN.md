# Automation — UFW-AUDIT

This document explains how to configure UFW-AUDIT to run automatically on a schedule and notify you of any issues.

---

## Quick setup

```bash
sudo ufw-audit --install-cron
```

The wizard guides you through 4 steps:

1. **Name** — a short label for this cron job (e.g. `nightly`, `weekly`). Press Enter to use the suggested name.
2. **Schedule** — choose from:
   - Every day
   - Certain days of the week (e.g. `1 3 5` for Mon/Wed/Fri)
   - Certain days of the month (e.g. `1 15` for the 1st and 15th)
   - Custom cron expression (e.g. `0 3 * * 1`)
3. **Time** — execution time in `HH:MM` format (default: `03:00`). Not shown for custom expressions.
4. **Email** — optional notification address. Leave empty to disable.

A plain-language preview is shown before confirmation:
```
  → Schedule: every Monday, Wednesday, Friday at 02:30
```

### Files created

- `/usr/local/bin/ufw-audit-{name}` — wrapper script
- `/etc/cron.d/ufw-audit-{name}` — system cron entry

---

## Managing cron jobs

```bash
sudo ufw-audit --manage-cron
```

Lists all installed cron jobs with their schedule and notification email:

```
  1. nightly              every day at 03:00
     → email: you@example.com
  2. weekly-monday        every Monday at 02:00

  Number to edit schedule, 'd:N' to delete, Enter to quit
  >
```

- Enter a **number** to edit the schedule of that job (re-runs the schedule wizard)
- Enter **`d:N`** to delete job N and its associated script
- Press **Enter** to quit

---

## Removing a cron job

```bash
sudo ufw-audit --remove-cron
```

Lists all installed cron jobs and asks which one to remove:

```
  1. nightly              every day at 03:00

  Number to remove, Enter to quit
  > 1
  ✔ Cron removed: /etc/cron.d/ufw-audit-nightly
  ✔ Script removed: /usr/local/bin/ufw-audit-nightly
```

---

## Email requirements

Notifications use the `mail` command (from `mailutils` package):

```bash
sudo apt install mailutils
```

Email is sent **only if the audit detects alerts or warnings** (exit code > 0). If your configuration is healthy, you receive nothing.

---

## Cron file format (v0.13+)

Each cron file includes metadata comments for identification:

```
# UFW-AUDIT cron — generated 2026-03-24 by ufw-audit --install-cron
# name: nightly
# email: you@example.com
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

0 3 * * *  root  /usr/local/bin/ufw-audit-nightly
```

---

## Report management

To list and delete generated reports:

```bash
sudo ufw-audit --manage-logs
```

---

## Postfix configuration for HTML emails (v0.12+)

From **v0.12**, cron reports are sent as HTML (MIME multipart/alternative) rather than plain text. For reliable delivery, Postfix must be configured with:

1. **Sender address rewriting**
2. **SASL authentication** (if using an SMTP relay)

### Common issues

#### 1. Error: "553 bad address format"

If you see this in `/var/log/mail.log`:
```
550 5.5.1 bad address format (in reply to MAIL FROM command)
```

**Cause:** Postfix sends the email with the system address `root@hostname.local` (invalid domain).

**Fix:** Configure `sender_canonical_maps` to rewrite system addresses:

```bash
sudo bash -c 'cat > /etc/postfix/sender_canonical << EOF
/^root@/ your.email@example.com
EOF'

sudo postmap /etc/postfix/sender_canonical
sudo postconf -e "sender_canonical_maps = regexp:/etc/postfix/sender_canonical"
sudo systemctl restart postfix
```

#### 2. Error: "530 Authentication required"

If your SMTP server requires authentication:

```bash
# Create credentials file
sudo bash -c 'cat > /etc/postfix/sasl_passwd << EOF
smtp.example.com user@example.com:PASSWORD
EOF'

sudo chmod 600 /etc/postfix/sasl_passwd
sudo postmap /etc/postfix/sasl_passwd

sudo postconf -e "smtp_sasl_auth_enable = yes"
sudo postconf -e "smtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd"
sudo postconf -e "smtp_use_tls = yes"

sudo systemctl restart postfix
```

### Verify configuration

```bash
sudo grep "UFW-AUDIT" /var/log/mail.log | tail -10
# Expected: status=sent (250 Message to be delivered)
```

### Technical notes

- The generated script automatically exports `PYTHONPATH` for Python imports
- SMTP envelope uses `sendmail -t -f` for sender address control
- No external dependencies (HTML generated in pure Python)
