# Automation — UFW-AUDIT

This document explains how to configure UFW-AUDIT to run automatically each night and notify you of any issues.

---

## Quick Installation

```bash
sudo ufw-audit --install-cron
```

The wizard asks two questions:

1. **Execution time** (default: `03:00`)
2. **Notification email** (optional — leave empty to disable)

It then creates:

- `/usr/local/bin/ufw-audit-nightly` — wrapper script
- `/etc/cron.d/ufw-audit` — system cron entry

---

## Email Requirements

Notifications use the `mail` command (from `mailutils` package).

```bash
sudo apt install mailutils
```

Email is sent **only if the audit detects alerts or warnings** (exit code > 0). If your configuration is healthy, you receive nothing.

---

## Generated Content

### `/usr/local/bin/ufw-audit-nightly`

```bash
#!/bin/bash
NOTIFY_EMAIL="you@example.com"
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

## Report Management

To list and delete generated reports:

```bash
sudo ufw-audit --manage-logs
```

Interactive interface:

```
  [REPORT MANAGEMENT]

  Reports in: /home/user/.local/share/ufw-audit/logs

  [ 1]  ufw_audit_20260323_030012.log  (4 KB)  2026-03-23 03:00
  [ 2]  ufw_audit_20260322_030011.log  (3 KB)  2026-03-22 03:00

  Enter number to delete, 'all' to delete all, Enter to quit
  >
```

---

## Modify Configuration

To change the time or email:

```bash
sudo ufw-audit --install-cron
```

Answer "yes" to the replacement question — files are regenerated.

---

## Uninstall

```bash
sudo rm /etc/cron.d/ufw-audit
sudo rm /usr/local/bin/ufw-audit-nightly
```

Log location remains configured in `~/.config/ufw-audit/config.conf`.
To reset it: `sudo ufw-audit --reconfigure`.

---

## Postfix Configuration for v0.12+ (HTML Emails)

Starting with **v0.12.0**, cron reports are sent in HTML format (MIME multipart/alternative) instead of plain text. For reliable delivery, Postfix must be properly configured with:

1. **Sender address rewriting**
2. **SASL authentication** (if using an SMTP relay)

### Common Issues

#### 1. Error: "553 bad address format"

If you see this error in `/var/log/mail.log`:

```
550 5.5.1 bad address format (in reply to MAIL FROM command)
```

**Cause:** Postfix sends email with system address `root@hostname.local` (invalid domain).

**Solution:** Configure `sender_canonical_maps` to rewrite system addresses:

```bash
sudo bash -c 'cat > /etc/postfix/sender_canonical << EOF'
/^root@/ your.email@example.com
EOF

sudo postmap /etc/postfix/sender_canonical
sudo postconf -e "sender_canonical_maps = regexp:/etc/postfix/sender_canonical"
sudo systemctl restart postfix
```

#### 2. Error: "530 Authentication required"

If your SMTP server requires authentication:

```bash
# Create credentials file
sudo bash -c 'cat > /etc/postfix/sasl_passwd << EOF'
smtp.example.com user@example.com:PASSWORD
EOF

# Protect the file
sudo chmod 600 /etc/postfix/sasl_passwd

# Create database
sudo postmap /etc/postfix/sasl_passwd

# Configure Postfix
sudo postconf -e "smtp_sasl_auth_enable = yes"
sudo postconf -e "smtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd"
sudo postconf -e "smtp_use_tls = yes"

# Restart
sudo systemctl restart postfix
```

### Email Format in v0.12+

Emails now contain:

- **Plain text version**: raw content (compatible with all clients)
- **HTML version**: styled rendering (modern clients only)

Postfix sends a MIME `multipart/alternative` message that the mail client displays based on its capabilities.

### Verify Configuration

```bash
# Inspect emails in mail.log
sudo grep "UFW-AUDIT" /var/log/mail.log | tail -10

# Expected format with success
status=sent (250 Message to be delivered)
```

### Manual Testing

```bash
# Generate a test HTML report
sudo ufw-audit --quiet --detailed

# Get the latest log file
LOG=$(ls -t ~/.local/share/ufw-audit/logs/ufw_audit_*.log 2>/dev/null | head -1)

# Send via v0.12 script
sudo python3 << 'PYTHON_EOF'
from ufw_audit.report_markdown import send_audit_log_as_html_email
send_audit_log_as_html_email(
    log_file="$LOG",
    recipient="your.email@example.com",
    subject="[TEST] UFW-AUDIT HTML Email"
)
PYTHON_EOF
```

### Technical Notes

- The generated nightly script automatically exports `PYTHONPATH` for Python imports
- SMTP envelope uses `sendmail -t -f` to control sender address
- No external dependencies (HTML generated in pure Python)
