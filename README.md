# 💀 Deadmanswitch

Jump to: [🇬🇧 English](#-english) | [🇩🇪 Deutsch](#-deutsch)

---

## 🇬🇧 English

Deadmanswitch is a dead man's switch implemented as a **single, self-contained PHP file** with no database. If you fail to check in within a defined interval via a PIN-protected check-in link, the system automatically sends a predefined message to designated trusted contacts.

### Table of Contents

- [How It Works](#how-it-works)
- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Initial Setup](#initial-setup)
- [Check-in](#check-in)
- [Cron / Automatic Checks](#cron--automatic-checks)
- [Admin Dashboard](#admin-dashboard)
- [Data Storage & Security](#data-storage--security)
- [Security Notes](#security-notes)

### How It Works

1. During initial setup you define an admin password, a 4-digit check-in PIN, a check-in interval, and recipients for the emergency case.
2. A personal `/checkin` link lets you regularly confirm that everything is fine. Every check-in **rolls the interval forward**, resetting the due time from the moment you click.
3. At roughly 20% of the remaining time before expiry, the system sends a reminder email to a separately configurable address.
4. If the interval is missed entirely, a cron call triggers the dispatch of the Deadmanswitch message to all configured recipients.

### Features

- Single PHP file, no database, no external dependencies
- Guided setup wizard on first install
- Admin login with hashed password (`password_hash`)
- PIN-protected check-in link, separate from the admin login
- Rolling interval — every check-in resets the due time
- Automatic reminder email at 20% remaining time to a separate address
- Automatic dispatch of the DMS message when the interval is missed
- Subject/message for the DMS mail and welcome mail editable after setup
- Welcome mail on installation to all recipients + reminder address
- SMTP sending (self-contained, dependency-free SMTP implementation with STARTTLS/SSL) with `mail()` fallback
- CSRF protection, hardened session configuration, rate limiting with exponential backoff
- Captcha (self-rendered SVG) for login and check-in
- Web cron (`?cron_token=...`) and CLI cron (`php deadman_switch.php cron`) with plain-text status output
- Admin dashboard with live countdown, logs (filterable/searchable), test mail sending, themes (light/dark/happy/cat), and a full "reset everything" option

### Requirements

- PHP **8.1+** (uses `declare(strict_types=1)`, `match`, typed properties/parameters)
- PHP **OpenSSL** extension (mandatory — the script aborts with HTTP 500 without it)
- Write permissions for the PHP process/web server account in the project directory (to create the data folder)
- For email sending: either a reachable SMTP server (recommended) or a working `mail()` configuration on the server
- HTTPS strongly recommended (secure cookies and HSTS headers are set automatically once HTTPS is detected)

### Installation

1. Copy `deadman_switch.php` to a PHP-capable web server.
2. Open the file in a browser, e.g. `https://your-domain.tld/deadman_switch.php`.
3. On first run, the script automatically creates a data directory `data/` next to the file (see [Data Storage & Security](#data-storage--security)).
4. The setup wizard guides you through the initial configuration.

### Initial Setup

The setup wizard asks for:

1. **Security** — admin password (min. 12 characters, upper/lowercase, digit, special character) and a 4-digit check-in PIN.
2. **Interval** — days/hours/minutes until the next check-in (minimum 1 minute).
3. **Addresses and Content** — trusted contacts/recipients (comma- or newline-separated), reminder address, DMS subject/message, and welcome mail subject/text. Available placeholders: `{{installed_at}}`, `{{system_url}}`, `{{interval}}`, `{{reminder_email}}`, `{{recipient_email}}`.
4. **Mail Delivery** — SMTP or PHP `mail()`, including host, port, credentials, security mode (TLS/SSL), and sender address.

Once completed, an encrypted configuration payload is stored and a welcome mail is sent to all recipients plus the reminder address.

### Check-in

The check-in link is:

```
https://your-domain.tld/deadman_switch.php/checkin
```

Flow:

- If there is no active/expired session, admin password authentication (with captcha) is required first.
- After that, the 4-digit PIN (with captcha) is enough to confirm the check-in.
- Failed attempts are logged, delayed with exponential backoff, and temporarily blocked after repeated failures (rate limiting).
- A successful check-in resets the interval, clears any already-sent reminder, and clears any triggered alarm state.

### Cron / Automatic Checks

For the system to actually trigger, one of the following calls must run regularly (e.g. every 5–15 minutes):

**Web cron** (token is generated during initial setup and shown in the admin dashboard):

```
https://your-domain.tld/deadman_switch.php?cron_token=YOUR_TOKEN
```

**CLI cron** (e.g. via crontab):

```
php /path/to/deadman_switch.php cron
```

The cron run checks the remaining time, sends the reminder email at roughly 20% remaining time, and dispatches the DMS message to all recipients once the interval expires. Both variants return a plain-text status message.

### Admin Dashboard

After logging in, the following actions are available, among others:

- Manual check-in / interval restart
- Adjust interval, theme (light/dark/happy/cat), and rate-limit settings
- Change admin password and check-in PIN
- Edit recipients, reminder address, DMS message, and welcome mail content
- Edit SMTP/mail settings
- Send test mails (DMS message, welcome mail, reminder mail)
- Run a cron preview without actually sending mail
- View, filter, search, and clear the event log
- Perform a complete system reset

### Data Storage & Security

All sensitive data lives in a local `data/` directory next to the script (a fallback migration from an alternative folder `../dms_data/` is detected automatically at startup):

| File | Purpose |
|---|---|
| `config.json` | Public configuration (timestamps, interval, password/PIN hash, encrypted payload) |
| `master.key` | AES-256 key used to encrypt sensitive content (mail texts, SMTP credentials) |
| `rate_limit.json` | Rate-limiting state for login/check-in |
| `pin_state.json` | Failure counter and lockout time for the check-in PIN |
| `events.log` | Event log (logins, check-ins, alarms, system events) |
| `.htaccess` | Blocks direct web access to the data directory (Apache) |

Recipient email addresses, message texts, and SMTP credentials are stored AES-256-CBC encrypted with HMAC integrity verification inside `config.json` (`master.key` is the corresponding key). Files are created with restrictive permissions (`0600`/`0700`).

> ⚠️ **Important:** If you run a web server without Apache/`.htaccess` support (e.g. nginx), access to the `data/` directory must be blocked at the server level as well, since `.htaccess` is not evaluated there. Ideally, place `data/` outside the web root (`../dms_data/`).

### Security Notes

- Use HTTPS — session cookies are set to `secure` and HSTS is enabled automatically once HTTPS is detected.
- Rate limiting with exponential backoff protects login and check-in against brute-force attacks; after too many failed attempts, the admin is notified by email about blocked access attempts.
- CSRF tokens are validated for all state-changing forms.
- Security headers (CSP, X-Frame-Options, Referrer-Policy, Permissions-Policy, etc.) are set on every response.
- The master key (`master.key`) and the configuration file should be backed up regularly — without them, stored content cannot be recovered.
- Never commit `master.key`, `config.json`, or the entire `data/` directory to a public repository.

---

## 🇩🇪 Deutsch

Deadmanswitch ist ein Dead Man's Switch als **einzelne, autarke PHP-Datei** ohne Datenbank. Meldest du dich nicht innerhalb eines festgelegten Intervalls über einen PIN-geschützten Check-in-Link zurück, verschickt das System automatisch eine vorab definierte Nachricht an hinterlegte Vertrauenspersonen.

### Inhaltsverzeichnis

- [Funktionsweise](#funktionsweise)
- [Features (DE)](#features-de)
- [Voraussetzungen](#voraussetzungen)
- [Installation](#installation-de)
- [Ersteinrichtung](#ersteinrichtung)
- [Check-in (DE)](#check-in-de)
- [Cron / automatische Prüfung](#cron--automatische-prüfung)
- [Admin-Dashboard (DE)](#admin-dashboard-de)
- [Datenablage & Sicherheit](#datenablage--sicherheit)
- [Sicherheitshinweise](#sicherheitshinweise)

### Funktionsweise

1. Bei der Ersteinrichtung werden ein Admin-Passwort, eine 4-stellige Check-in-PIN, ein Check-in-Intervall sowie Empfänger für den Ernstfall festgelegt.
2. Über einen persönlichen `/checkin`-Link bestätigst du in regelmäßigen Abständen, dass alles in Ordnung ist. Jeder Check-in setzt das Intervall **rollierend** ab dem Klick-Zeitpunkt neu.
3. Bei ca. 20 % Restzeit vor Ablauf verschickt das System eine Erinnerungsmail an eine separat konfigurierbare Adresse.
4. Wird das Intervall komplett verpasst, löst ein Cron-Aufruf den Versand der Deadmanswitch-Nachricht an alle hinterlegten Empfänger aus.

### Features (DE)

- Single-PHP-File, keine Datenbank, keine externen Abhängigkeiten
- Geführter Setup-Assistent bei der Erstinstallation
- Admin-Login mit gehashtem Passwort (`password_hash`)
- PIN-geschützter Check-in-Link, getrennt vom Admin-Login
- Rollierendes Intervall — jeder Check-in setzt die Fälligkeit neu
- Automatische Erinnerungsmail bei 20 % Restzeit an eine separate Adresse
- Automatischer Versand der DMS-Nachricht bei verpasstem Intervall
- Betreff/Nachricht für DMS-Mail und Willkommensmail nach dem Setup editierbar
- Willkommensmail bei Installation an alle Empfänger + Erinnerungsadresse
- SMTP-Versand (eigene, abhängigkeitsfreie SMTP-Implementierung mit STARTTLS/SSL) mit `mail()`-Fallback
- CSRF-Schutz, abgesicherte Session-Konfiguration, Rate-Limiting mit exponentiellem Backoff
- Captcha (selbstgerendertes SVG) für Login und Check-in
- Web-Cron (`?cron_token=...`) und CLI-Cron (`php deadman_switch.php cron`) mit Klartext-Statusausgabe
- Admin-Dashboard mit Live-Countdown, Logs (filterbar/durchsuchbar), Testmail-Versand, Themes (light/dark/happy/cat) und "Alles zurücksetzen"

### Voraussetzungen

- PHP **8.1+** (nutzt `declare(strict_types=1)`, `match`, typisierte Properties/Parameter)
- PHP-Erweiterung **OpenSSL** (zwingend erforderlich, das Skript bricht sonst mit HTTP 500 ab)
- Schreibrechte für das PHP-Prozess-/Webserver-Benutzerkonto im Projektverzeichnis (zur Anlage des Datenordners)
- Für E-Mail-Versand: entweder ein erreichbarer SMTP-Server (empfohlen) oder eine funktionierende `mail()`-Konfiguration auf dem Server
- HTTPS wird dringend empfohlen (Secure-Cookies, HSTS-Header werden automatisch gesetzt, sobald HTTPS erkannt wird)

### Installation (DE)

1. `deadman_switch.php` auf einen PHP-fähigen Webserver kopieren.
2. Datei im Browser aufrufen, z. B. `https://deine-domain.tld/deadman_switch.php`.
3. Das Skript legt beim ersten Aufruf automatisch ein Datenverzeichnis `data/` neben der Datei an (siehe [Datenablage & Sicherheit](#datenablage--sicherheit)).
4. Der Setup-Assistent führt durch die Ersteinrichtung.

### Ersteinrichtung

Im Setup-Assistenten werden folgende Angaben verlangt:

1. **Sicherheit** — Admin-Passwort (mind. 12 Zeichen, Groß-/Kleinbuchstaben, Zahl, Sonderzeichen) und 4-stellige Check-in-PIN.
2. **Intervall** — Tage/Stunden/Minuten bis zum nächsten Check-in (mind. 1 Minute).
3. **Adressen und Inhalte** — Vertrauenspersonen/Empfänger (Komma- oder zeilengetrennt), Erinnerungsadresse, DMS-Betreff/-Nachricht sowie Willkommensmail-Betreff/-Text. Verfügbare Platzhalter: `{{installed_at}}`, `{{system_url}}`, `{{interval}}`, `{{reminder_email}}`, `{{recipient_email}}`.
4. **Mailversand** — SMTP oder PHP `mail()`, inkl. Host, Port, Zugangsdaten, Sicherheitsmodus (TLS/SSL) und Absenderadresse.

Nach Abschluss wird ein verschlüsselter Konfigurations-Payload gespeichert und eine Willkommensmail an alle Empfänger sowie die Erinnerungsadresse verschickt.

### Check-in (DE)

Der Check-in-Link lautet:

```
https://deine-domain.tld/deadman_switch.php/checkin
```

Ablauf:

- Bei fehlender/abgelaufener Session ist zunächst eine Admin-Passwort-Authentifizierung (inkl. Captcha) erforderlich.
- Danach reicht die 4-stellige PIN (inkl. Captcha), um den Check-in zu bestätigen.
- Fehlversuche werden geloggt, mit exponentiellem Warte-Delay belegt und nach mehreren Fehlversuchen temporär gesperrt (Rate-Limiting).
- Ein erfolgreicher Check-in setzt das Intervall zurück, löscht eine bereits ausgelöste Erinnerung und setzt einen eventuellen Alarmstatus zurück.

### Cron / automatische Prüfung

Damit das System tatsächlich auslöst, muss regelmäßig (z. B. alle 5–15 Minuten) einer der folgenden Aufrufe erfolgen:

**Web-Cron** (Token wird bei der Ersteinrichtung generiert und im Admin-Dashboard angezeigt):

```
https://deine-domain.tld/deadman_switch.php?cron_token=DEIN_TOKEN
```

**CLI-Cron** (z. B. per Crontab):

```
php /pfad/zu/deadman_switch.php cron
```

Der Cron-Lauf prüft die Restzeit, verschickt bei ca. 20 % Restzeit die Erinnerungsmail und löst bei Ablauf des Intervalls den Versand der DMS-Nachricht an alle Empfänger aus. Beide Varianten geben eine Klartext-Statusmeldung zurück.

### Admin-Dashboard (DE)

Nach dem Login stehen u. a. folgende Aktionen zur Verfügung:

- Manueller Check-in / Intervall-Neustart
- Intervall, Theme (light/dark/happy/cat) und Rate-Limit-Einstellungen anpassen
- Admin-Passwort und Check-in-PIN ändern
- Empfänger, Erinnerungsadresse, DMS- und Willkommensmail-Inhalte bearbeiten
- SMTP-/Mail-Einstellungen bearbeiten
- Test-Mails versenden (DMS-Nachricht, Willkommensmail, Erinnerungsmail)
- Cron-Vorschau ausführen, ohne tatsächlich Mails zu versenden
- Event-Log einsehen, filtern, durchsuchen und leeren
- Kompletten Reset des Systems durchführen

### Datenablage & Sicherheit

Alle sensiblen Daten liegen in einem lokalen Verzeichnis `data/` neben dem Skript (Fallback-Migration von einem alternativen Ordner `../dms_data/` wird beim Start automatisch erkannt):

| Datei | Zweck |
|---|---|
| `config.json` | Öffentliche Konfiguration (Zeitstempel, Intervall, Passwort-/PIN-Hash, verschlüsselter Payload) |
| `master.key` | AES-256-Schlüssel zur Verschlüsselung sensibler Inhalte (E-Mail-Texte, SMTP-Zugangsdaten) |
| `rate_limit.json` | Zustand des Rate-Limitings für Login/Check-in |
| `pin_state.json` | Fehlversuchszähler und Sperrzeit für die Check-in-PIN |
| `events.log` | Ereignisprotokoll (Logins, Check-ins, Alarme, Systemereignisse) |
| `.htaccess` | Blockiert den direkten Web-Zugriff auf das Datenverzeichnis (Apache) |

Empfänger-E-Mail-Adressen, Nachrichtentexte und SMTP-Zugangsdaten werden AES-256-CBC-verschlüsselt mit HMAC-Integritätsprüfung in `config.json` abgelegt (`master.key` ist der Schlüssel dazu). Dateien werden mit restriktiven Rechten (`0600`/`0700`) angelegt.

> ⚠️ **Wichtig:** Wird ein Webserver ohne Apache/`.htaccess`-Unterstützung eingesetzt (z. B. nginx), muss der Zugriff auf das `data/`-Verzeichnis zusätzlich serverseitig gesperrt werden, da `.htaccess` dort nicht ausgewertet wird. Idealerweise `data/` außerhalb des Web-Roots platzieren (`../dms_data/`).

### Sicherheitshinweise

- HTTPS verwenden — Session-Cookies sind auf `secure` gesetzt und HSTS wird bei erkanntem HTTPS automatisch aktiviert.
- Rate-Limiting mit exponentiellem Backoff schützt Login und Check-in vor Brute-Force-Angriffen; bei zu vielen Fehlversuchen wird der Admin per Mail über gesperrte Zugriffsversuche informiert.
- CSRF-Token werden für alle zustandsändernden Formulare geprüft.
- Sicherheits-Header (CSP, X-Frame-Options, Referrer-Policy, Permissions-Policy u. a.) werden bei jeder Antwort gesetzt.
- Der Master-Schlüssel (`master.key`) und die Konfigurationsdatei sollten regelmäßig gesichert werden — ohne sie sind hinterlegte Inhalte nicht wiederherstellbar.
- `master.key`, `config.json` sowie das gesamte `data/`-Verzeichnis niemals in ein öffentliches Repository einchecken.
