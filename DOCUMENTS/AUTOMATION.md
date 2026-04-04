*[Lire en français](AUTOMATION_FR.md)*

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

Lists all installed cron jobs with their schedule and notification email. The menu loops until you explicitly quit:

```
  1. nightly              every day at 03:00
     → email: you@example.com
  2. weekly-monday        every Monday at 02:00

  Number to edit, 'e:N' to edit email, 'd:N' / 'd:1,3' / 'd:1-3' / 'd:all' to delete, 'm' for email book, Enter to quit
  >
```

| Command | Action |
|---------|--------|
| `N` | Edit cron N — choose between schedule or notification email |
| `e:N` | Edit the notification email of cron N directly |
| `d:N` | Delete cron N and its associated script |
| `d:1,3` | Delete cron jobs 1 and 3 (comma list) |
| `d:1-3` | Delete cron jobs 1 through 3 (range) |
| `d:all` | Delete all installed cron jobs |
| `m` | Open the email address book (see below) |
| Enter / `q` | Quit |

After each action the menu redisplays so you can chain multiple operations.

---

## Removing a cron job

Enter `d:N` to delete a single job, or use a comma list, range, or `all` for bulk deletion:

```
  1. nightly              every day at 03:00
  2. weekly               every Monday at 02:00

  Number to edit, 'e:N' to edit email, 'd:N' / 'd:1,3' / 'd:1-3' / 'd:all' to delete, 'm' for email book, Enter to quit
  > d:1
  Delete cron 'nightly'? [y/N] y
  ✔ Cron 'nightly' deleted

  > d:1,2
  Delete 2 cron jobs (nightly, weekly)? [y/N] y
  ✔ 2 cron jobs deleted

  > d:all
  Delete ALL 2 cron jobs? [y/N] y
  ✔ 2 cron jobs deleted
```

---

## Email address book

The email address book (`m`) lets you manage saved notification addresses independently of any cron job. It is available even when no cron jobs are installed:

```
  ╔════════════════════════════════════════════════════════════╗
  ║  EMAIL ADDRESS BOOK                                        ║
  ╚════════════════════════════════════════════════════════════╝

  1. you@example.com
  2. admin@example.com

  Number to delete, '1,3' or '1-3' for a selection, 'all' to delete all, 'a' to add, Enter to quit
  >
```

| Command | Action |
|---------|--------|
| `a` | Add a new validated email address |
| `N` | Delete address N |
| `1,3` | Delete addresses 1 and 3 |
| `1-3` | Delete addresses 1, 2 and 3 |
| `all` | Delete all saved addresses |
| Enter / `q` | Return to the cron management menu |

Addresses saved here are offered as suggestions whenever `--install-cron` or `--manage-cron` asks for a notification email.

---

## Multiple notification emails (v1.7.0+)

`--install-cron` supports multiple recipients. After each selection, you are asked whether to add another:

```
  Notification email(s):
    → Selected so far: admin@example.com
    0. (none / done)
    1. admin@example.com ✔
    2. security@example.com
    3. Enter a new address...
  > 2
  Add another email address? [y/N] n
```

All selected addresses are stored comma-separated and each receives an individual email when the audit detects issues.

---

## Email requirements

Notifications use the `mail` command (from `mailutils` package):

```bash
sudo apt install mailutils
```

Email is sent **only if the audit detects alerts or warnings** (exit code > 0). If your configuration is healthy, you receive nothing.

---

## Cron file format (v0.13+)

Each cron file includes metadata comments for identification. Multiple emails are stored comma-separated:

```
# UFW-AUDIT cron — generated 2026-03-24 by ufw-audit --install-cron
# name: nightly
# email: admin@example.com,security@example.com
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
