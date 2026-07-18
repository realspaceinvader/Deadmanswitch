# 💀 Deadmanswitch

Deadmanswitch ist ein Dead Man's Switch als **einzelne, autarke PHP-Datei** ohne Datenbank. Meldest du dich nicht innerhalb eines festgelegten Intervalls über einen PIN-geschützten Check-in-Link zurück, verschickt das System automatisch eine vorab definierte Nachricht an hinterlegte Vertrauenspersonen.

## Inhaltsverzeichnis

- [Funktionsweise](#funktionsweise)
- [Features](#features)
- [Voraussetzungen](#voraussetzungen)
- [Installation](#installation)
- [Ersteinrichtung](#ersteinrichtung)
- [Check-in](#check-in)
- [Cron / automatische Prüfung](#cron--automatische-prüfung)
- [Admin-Dashboard](#admin-dashboard)
- [Datenablage & Sicherheit](#datenablage--sicherheit)
- [Konfigurationsdateien](#konfigurationsdateien)
- [Sicherheitshinweise](#sicherheitshinweise)

## Funktionsweise

1. Bei der Ersteinrichtung werden ein Admin-Passwort, eine 4-stellige Check-in-PIN, ein Check-in-Intervall sowie Empfänger für den Ernstfall festgelegt.
2. Über einen persönlichen `/checkin`-Link bestätigst du in regelmäßigen Abständen, dass alles in Ordnung ist. Jeder Check-in setzt das Intervall **rollierend** ab dem Klick-Zeitpunkt neu.
3. Bei ca. 20 % Restzeit vor Ablauf verschickt das System eine Erinnerungsmail an eine separat konfigurierbare Adresse.
4. Wird das Intervall komplett verpasst, löst ein Cron-Aufruf den Versand der Deadmanswitch-Nachricht an alle hinterlegten Empfänger aus.

## Features

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

## Voraussetzungen

- PHP **8.1+** (nutzt `declare(strict_types=1)`, `match`, typisierte Properties/Parameter)
- PHP-Erweiterung **OpenSSL** (zwingend erforderlich, das Skript bricht sonst mit HTTP 500 ab)
- Schreibrechte für das PHP-Prozess-/Webserver-Benutzerkonto im Projektverzeichnis (zur Anlage des Datenordners)
- Für E-Mail-Versand: entweder ein erreichbarer SMTP-Server (empfohlen) oder eine funktionierende `mail()`-Konfiguration auf dem Server
- HTTPS wird dringend empfohlen (Secure-Cookies, HSTS-Header werden automatisch gesetzt, sobald HTTPS erkannt wird)

## Installation

1. `deadman_switch.php` auf einen PHP-fähigen Webserver kopieren.
2. Datei im Browser aufrufen, z. B. `https://deine-domain.tld/deadman_switch.php`.
3. Das Skript legt beim ersten Aufruf automatisch ein Datenverzeichnis `data/` neben der Datei an (siehe [Datenablage & Sicherheit](#datenablage--sicherheit)).
4. Der Setup-Assistent führt durch die Ersteinrichtung.

## Ersteinrichtung

Im Setup-Assistenten werden folgende Angaben verlangt:

1. **Sicherheit** — Admin-Passwort (mind. 12 Zeichen, Groß-/Kleinbuchstaben, Zahl, Sonderzeichen) und 4-stellige Check-in-PIN.
2. **Intervall** — Tage/Stunden/Minuten bis zum nächsten Check-in (mind. 1 Minute).
3. **Adressen und Inhalte** — Vertrauenspersonen/Empfänger (Komma- oder zeilengetrennt), Erinnerungsadresse, DMS-Betreff/-Nachricht sowie Willkommensmail-Betreff/-Text. Verfügbare Platzhalter: `{{installed_at}}`, `{{system_url}}`, `{{interval}}`, `{{reminder_email}}`, `{{recipient_email}}`.
4. **Mailversand** — SMTP oder PHP `mail()`, inkl. Host, Port, Zugangsdaten, Sicherheitsmodus (TLS/SSL) und Absenderadresse.

Nach Abschluss wird ein verschlüsselter Konfigurations-Payload gespeichert und eine Willkommensmail an alle Empfänger sowie die Erinnerungsadresse verschickt.

## Check-in

Der Check-in-Link lautet:

```
https://deine-domain.tld/deadman_switch.php/checkin
```

Ablauf:

- Bei fehlender/abgelaufener Session ist zunächst eine Admin-Passwort-Authentifizierung (inkl. Captcha) erforderlich.
- Danach reicht die 4-stellige PIN (inkl. Captcha), um den Check-in zu bestätigen.
- Fehlversuche werden geloggt, mit exponentiellem Warte-Delay belegt und nach mehreren Fehlversuchen temporär gesperrt (Rate-Limiting).
- Ein erfolgreicher Check-in setzt das Intervall zurück, löscht eine bereits ausgelöste Erinnerung und setzt einen eventuellen Alarmstatus zurück.

## Cron / automatische Prüfung

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

## Admin-Dashboard

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

## Datenablage & Sicherheit

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

## Sicherheitshinweise

- HTTPS verwenden — Session-Cookies sind auf `secure` gesetzt und HSTS wird bei erkanntem HTTPS automatisch aktiviert.
- Rate-Limiting mit exponentiellem Backoff schützt Login und Check-in vor Brute-Force-Angriffen; bei zu vielen Fehlversuchen wird der Admin per Mail über gesperrte Zugriffsversuche informiert.
- CSRF-Token werden für alle zustandsändernden Formulare geprüft.
- Sicherheits-Header (CSP, X-Frame-Options, Referrer-Policy, Permissions-Policy u. a.) werden bei jeder Antwort gesetzt.
- Der Master-Schlüssel (`master.key`) und die Konfigurationsdatei sollten regelmäßig gesichert werden — ohne sie sind hinterlegte Inhalte nicht wiederherstellbar.
- `master.key`, `config.json` sowie das gesamte `data/`-Verzeichnis niemals in ein öffentliches Repository einchecken.
