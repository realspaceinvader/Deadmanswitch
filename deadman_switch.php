<?php
/**
 * Dead Man's Switch - Single File Edition
 *
 * Features
 * - Single PHP file, no database
 * - Setup wizard
 * - Admin login with password hash
 * - PIN-protected check-in link
 * - Rolling interval: every check-in resets due time from NOW
 * - 20% remaining reminder mail to separate reminder address
 * - One missed interval triggers DMS mail dispatch
 * - Editable DMS subject/message/recipients after setup
 * - Editable welcome subject/message after setup
 * - Welcome mail on installation to all recipients + reminder address
 * - SMTP support (raw SMTP) with mail() fallback
 * - CSRF, secure session settings, basic rate limiting
 * - Web cron and CLI cron with clear status output
 */

declare(strict_types=1);
error_reporting(E_ALL);
ini_set('display_errors', '0');
ini_set('log_errors', '1');
date_default_timezone_set(date_default_timezone_get() ?: 'UTC');

const SESSION_TTL_SECONDS = 86400;
const CHECKIN_SESSION_TTL_SECONDS = 259200;
const SESSION_COOKIE_TTL_SECONDS = CHECKIN_SESSION_TTL_SECONDS;
const PIN_MAX_FAILURES = 5;
const RATE_LIMIT_BLOCK_SECONDS = 900;

// -------------------- Session / security --------------------
ini_set('session.use_only_cookies', '1');
ini_set('session.use_strict_mode', '1');
ini_set('session.cookie_lifetime', (string)SESSION_COOKIE_TTL_SECONDS);
ini_set('session.gc_maxlifetime', (string)SESSION_COOKIE_TTL_SECONDS);
session_name('DMSSESSID');
session_set_cookie_params([
    'lifetime' => SESSION_COOKIE_TTL_SECONDS,
    'path' => '/',
    'domain' => '',
    'secure' => true,
    'httponly' => true,
    // Firefox Mobile can drop Strict cookies on direct reopen/top-level navigation to /checkin.
    'samesite' => 'Lax',
]);
session_start();

if (!extension_loaded('openssl')) {
    http_response_code(500);
    die('OpenSSL extension is required.');
}

// -------------------- Paths --------------------
define('LEGACY_DATA_DIR', __DIR__ . '/data');
define('ALT_DATA_DIR', dirname(__DIR__) . '/dms_data');
define('DATA_DIR', LEGACY_DATA_DIR);
define('CONFIG_FILE', DATA_DIR . '/config.json');
define('KEY_FILE', DATA_DIR . '/master.key');
define('RATE_LIMIT_FILE', DATA_DIR . '/rate_limit.json');
define('PIN_STATE_FILE', DATA_DIR . '/pin_state.json');
define('LOG_FILE', DATA_DIR . '/events.log');
define('HTACCESS_FILE', DATA_DIR . '/.htaccess');

bootstrap_files();

// -------------------- Helpers --------------------
function bootstrap_files(): void
{
    if (!is_dir(DATA_DIR) && is_dir(ALT_DATA_DIR)) {
        if (!mkdir(DATA_DIR, 0700, true) && !is_dir(DATA_DIR)) {
            throw new RuntimeException('Datenverzeichnis konnte nicht erstellt werden: ' . DATA_DIR);
        }
        foreach (['config.json', 'master.key', 'rate_limit.json', 'pin_state.json', 'events.log', '.htaccess'] as $file) {
            $old = ALT_DATA_DIR . '/' . $file;
            $new = DATA_DIR . '/' . $file;
            if (file_exists($old) && !file_exists($new)) {
                rename($old, $new);
            }
        }
    }
    if (!is_dir(DATA_DIR) && !mkdir(DATA_DIR, 0700, true) && !is_dir(DATA_DIR)) {
        throw new RuntimeException('Datenverzeichnis konnte nicht erstellt werden: ' . DATA_DIR);
    }
    if (!file_exists(HTACCESS_FILE)) {
        write_file_strict(HTACCESS_FILE, "Deny from all\n");
    }
    safe_chmod(DATA_DIR, 0700);
    safe_chmod(HTACCESS_FILE, 0600);
}

function add_diag(string $message): void
{
    $GLOBALS['dms_diag'] ??= [];
    $GLOBALS['dms_diag'][] = $message;
}

function get_diags(): array
{
    $diags = $GLOBALS['dms_diag'] ?? [];
    return is_array($diags) ? $diags : [];
}

function require_data_dir_ready(): void
{
    if (!is_dir(DATA_DIR)) {
        throw new RuntimeException('Datenverzeichnis fehlt: ' . DATA_DIR);
    }
    if (!is_readable(DATA_DIR)) {
        throw new RuntimeException('Datenverzeichnis ist nicht lesbar: ' . DATA_DIR);
    }
    if (!is_writable(DATA_DIR)) {
        throw new RuntimeException('Datenverzeichnis ist nicht schreibbar: ' . DATA_DIR);
    }
}

function safe_chmod(string $path, int $mode): void
{
    if (file_exists($path)) {
        chmod($path, $mode);
    }
}

function safe_unlink(string $path): void
{
    if (file_exists($path)) {
        unlink($path);
    }
}

function write_file_strict(string $path, string $content, int $flags = 0): void
{
    $dir = dirname($path);
    $append = (bool)($flags & FILE_APPEND);
    $fp = fopen($path, $append ? 'ab' : 'c+b');
    if ($fp === false) {
        throw new RuntimeException('Schreiben fehlgeschlagen: ' . $path . ' (Ordner: ' . $dir . ')');
    }

    $locked = false;
    try {
        if (!flock($fp, LOCK_EX)) {
            throw new RuntimeException('Dateisperre fehlgeschlagen: ' . $path);
        }
        $locked = true;

        if ($append) {
            if (fseek($fp, 0, SEEK_END) !== 0) {
                throw new RuntimeException('Dateiende konnte nicht erreicht werden: ' . $path);
            }
        } else {
            if (!ftruncate($fp, 0) || rewind($fp) === false) {
                throw new RuntimeException('Datei konnte nicht geleert werden: ' . $path);
            }
        }

        $length = strlen($content);
        $written = 0;
        while ($written < $length) {
            $result = fwrite($fp, substr($content, $written));
            if ($result === false || $result === 0) {
                throw new RuntimeException('Schreiben fehlgeschlagen: ' . $path);
            }
            $written += $result;
        }

        if (!fflush($fp)) {
            throw new RuntimeException('Schreibpuffer konnte nicht gespeichert werden: ' . $path);
        }
    } finally {
        if ($locked) {
            flock($fp, LOCK_UN);
        }
        fclose($fp);
    }
}

function read_file_strict(string $path): string
{
    $fp = fopen($path, 'rb');
    if ($fp === false) {
        throw new RuntimeException('Lesen fehlgeschlagen: ' . $path);
    }

    $locked = false;
    try {
        if (!flock($fp, LOCK_SH)) {
            throw new RuntimeException('Lesesperre fehlgeschlagen: ' . $path);
        }
        $locked = true;
        $content = stream_get_contents($fp);
        if ($content === false) {
            throw new RuntimeException('Lesen fehlgeschlagen: ' . $path);
        }
        return $content;
    } finally {
        if ($locked) {
            flock($fp, LOCK_UN);
        }
        fclose($fp);
    }
}

function safe_read_json(string $path, array $fallback = []): array
{
    try {
        $content = read_file_strict($path);
    } catch (Throwable $e) {
        return $fallback;
    }

    $data = json_decode($content, true);
    return is_array($data) ? $data : $fallback;
}

function safe_write_json(string $path, array $data, int $jsonFlags = 0): void
{
    $json = json_encode($data, $jsonFlags);
    if ($json === false) {
        throw new RuntimeException('JSON encode failed: ' . $path);
    }
    write_file_strict($path, $json, 0);
}

function normalized_user_agent(): string
{
    $userAgent = (string)($_SERVER['HTTP_USER_AGENT'] ?? '');
    $userAgent = preg_replace('/\s+/', ' ', trim($userAgent)) ?? '';
    return substr($userAgent, 0, 512);
}

function session_user_agent_fingerprint(): string
{
    return hash('sha256', 'dms-session-user-agent|' . normalized_user_agent());
}

function session_user_agent_matches(?string $fingerprint): bool
{
    return is_string($fingerprint) && hash_equals($fingerprint, session_user_agent_fingerprint());
}

function h(?string $s): string
{
    return htmlspecialchars((string)$s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function normalize_ip_candidate(string $value): ?string
{
    $value = trim($value);
    if ($value === '') {
        return null;
    }
    if (str_contains($value, ',')) {
        $parts = array_map('trim', explode(',', $value));
        foreach ($parts as $part) {
            $candidate = normalize_ip_candidate($part);
            if ($candidate !== null) {
                return $candidate;
            }
        }
        return null;
    }
    if (str_contains($value, ';')) {
        foreach (preg_split('/[;]+/', $value) ?: [] as $part) {
            if (str_starts_with(strtolower(trim($part)), 'for=')) {
                $candidate = normalize_ip_candidate(substr(trim($part), 4));
                if ($candidate !== null) {
                    return $candidate;
                }
            }
        }
        return null;
    }
    $value = trim($value, " \t\n\r\0\x0B\"'[]");
    if (preg_match('/^(.+):\d+$/', $value, $m) && filter_var($m[1], FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
        $value = $m[1];
    }
    return filter_var($value, FILTER_VALIDATE_IP) ? $value : null;
}

function public_client_ip(): ?string
{
    $sources = [
        $_SERVER['HTTP_CF_CONNECTING_IP'] ?? '',
        $_SERVER['HTTP_TRUE_CLIENT_IP'] ?? '',
        $_SERVER['HTTP_X_FORWARDED_FOR'] ?? '',
        $_SERVER['HTTP_X_REAL_IP'] ?? '',
        $_SERVER['HTTP_FORWARDED'] ?? '',
    ];
    foreach ($sources as $source) {
        $candidate = normalize_ip_candidate((string)$source);
        if ($candidate !== null && filter_var($candidate, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
            return $candidate;
        }
    }
    return null;
}

function client_ip(): string
{
    $publicIp = public_client_ip();
    if ($publicIp !== null) {
        return $publicIp;
    }
    $remote = normalize_ip_candidate((string)($_SERVER['REMOTE_ADDR'] ?? ''));
    return $remote ?? 'cli';
}

function apply_security_headers(bool $forImage = false): void
{
    header('X-Frame-Options: DENY');
    header('X-Content-Type-Options: nosniff');
    header('Referrer-Policy: no-referrer');
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');
    header('Permissions-Policy: accelerometer=(), camera=(), geolocation=(), gyroscope=(), microphone=(), payment=(), usb=()');
    header('Cross-Origin-Opener-Policy: same-origin');
    header('Cross-Origin-Resource-Policy: same-origin');
    if ((!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') || strtolower((string)($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '')) === 'https') {
        header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
    }
    if ($forImage) {
        header("Content-Security-Policy: default-src 'none'; img-src 'self' data:; style-src 'unsafe-inline'; sandbox");
        return;
    }
    header("Content-Security-Policy: default-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; img-src 'self' data:; object-src 'none'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'");
}

function safe_self_path(): string
{
    $path = $_SERVER['SCRIPT_NAME'] ?? ('/' . basename(__FILE__));
    if (!is_string($path) || $path === '') {
        $path = $_SERVER['PHP_SELF'] ?? ('/' . basename(__FILE__));
    }
    if ($path === '' || $path[0] !== '/') {
        $path = '/' . ltrim($path, '/');
    }
    return preg_replace('/[\r\n]+/', '', $path) ?: '/' . basename(__FILE__);
}

function request_path(): string
{
    $path = parse_url((string)($_SERVER['REQUEST_URI'] ?? ''), PHP_URL_PATH);
    if (!is_string($path) || $path === '') {
        return safe_self_path();
    }
    if ($path[0] !== '/') {
        $path = '/' . ltrim($path, '/');
    }
    return preg_replace('/[\r\n]+/', '', $path) ?: safe_self_path();
}

function route_suffix(): string
{
    $self = safe_self_path();
    $path = request_path();
    if ($path === $self) {
        return '';
    }
    if (str_starts_with($path, $self . '/')) {
        return substr($path, strlen($self));
    }
    return '';
}

function checkin_path(): string
{
    return safe_self_path() . '/checkin';
}

function runtime_base_url(): string
{
    $scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
    $host = strtolower(trim((string)($_SERVER['HTTP_HOST'] ?? 'localhost')));
    if ($host === '' || !preg_match('/^(?:[a-z0-9.-]+|\[[a-f0-9:]+\])(?::\d{1,5})?$/i', $host)) {
        $host = 'localhost';
    }
    $path = safe_self_path();
    return $scheme . '://' . $host . $path;
}

function normalize_app_url(?string $url): ?string
{
    if (!is_string($url)) {
        return null;
    }
    $url = trim($url);
    if ($url === '' || preg_match('/[\r\n]/', $url)) {
        return null;
    }
    $parts = parse_url($url);
    if (!is_array($parts)) {
        return null;
    }
    $scheme = strtolower((string)($parts['scheme'] ?? ''));
    $host = strtolower((string)($parts['host'] ?? ''));
    if (!in_array($scheme, ['http', 'https'], true) || $host === '') {
        return null;
    }
    if (!preg_match('/^(?:[a-z0-9.-]+|\[[a-f0-9:]+\])$/i', $host)) {
        return null;
    }
    $port = isset($parts['port']) ? ':' . (int)$parts['port'] : '';
    $path = (string)($parts['path'] ?? '');
    if ($path === '' || $path[0] !== '/') {
        $path = '/' . ltrim($path, '/');
    }
    return $scheme . '://' . $host . $port . $path;
}

function base_url(?array $config = null): string
{
    $stored = normalize_app_url($config['app_url'] ?? null);
    return $stored ?? runtime_base_url();
}

function log_event(string $message): void
{
    try {
        require_data_dir_ready();
        write_file_strict(LOG_FILE, '[' . date('Y-m-d H:i:s') . '] ' . $message . PHP_EOL, FILE_APPEND);
        safe_chmod(LOG_FILE, 0600);
    } catch (Throwable $e) {
        add_diag($e->getMessage());
    }
}

function get_master_key(): string
{
    if (!file_exists(KEY_FILE)) {
        require_data_dir_ready();
        $key = random_bytes(32);
        write_file_strict(KEY_FILE, base64_encode($key), LOCK_EX);
        safe_chmod(KEY_FILE, 0600);
        return $key;
    }
    try {
        $raw = read_file_strict(KEY_FILE);
    } catch (Throwable $e) {
        throw new RuntimeException('Master-Key konnte nicht gelesen werden: ' . KEY_FILE);
    }
    $raw = trim((string)$raw);
    $decoded = base64_decode($raw, true);
    if ($decoded === false || strlen($decoded) < 32) {
        throw new RuntimeException('Invalid master key file');
    }
    return $decoded;
}

function encrypt_payload(array $data): string
{
    $json = json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    if ($json === false) {
        throw new RuntimeException('JSON encode failed');
    }
    $key = get_master_key();
    $iv = random_bytes(16);
    $cipher = openssl_encrypt($json, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv);
    if ($cipher === false) {
        throw new RuntimeException('Encryption failed');
    }
    $mac = hash_hmac('sha256', $iv . $cipher, $key, true);
    return base64_encode($iv . $mac . $cipher);
}

function decrypt_payload(string $blob): array
{
    $raw = base64_decode($blob, true);
    if ($raw === false || strlen($raw) < 48) {
        return [];
    }
    $iv = substr($raw, 0, 16);
    $mac = substr($raw, 16, 32);
    $cipher = substr($raw, 48);
    $key = get_master_key();
    $calc = hash_hmac('sha256', $iv . $cipher, $key, true);
    if (!hash_equals($mac, $calc)) {
        return [];
    }
    $plain = openssl_decrypt($cipher, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv);
    if ($plain === false) {
        return [];
    }
    $data = json_decode($plain, true);
    return is_array($data) ? $data : [];
}

function read_config(): ?array
{
    if (!file_exists(CONFIG_FILE)) {
        return null;
    }
    $cfg = safe_read_json(CONFIG_FILE, []);
    if ($cfg === []) {
        add_diag('Konfigurationsdatei ist ungültig oder leer: ' . CONFIG_FILE);
    }
    return $cfg;
}

function write_config(array $cfg): void
{
    require_data_dir_ready();
    safe_write_json(CONFIG_FILE, $cfg, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    safe_chmod(CONFIG_FILE, 0600);
}

function csrf_token(): string
{
    if (empty($_SESSION['csrf'])) {
        $_SESSION['csrf'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf'];
}

function reset_csrf_token(): void
{
    unset($_SESSION['csrf']);
}

function require_csrf(): void
{
    $token = $_POST['csrf_token'] ?? '';
    if (!is_string($token) || empty($_SESSION['csrf']) || !hash_equals($_SESSION['csrf'], $token)) {
        http_response_code(400);
        die('Ungültiger CSRF-Token.');
    }
}

function apply_failure_delay_for_attempt(int $attempt): void
{
    sleep(failure_delay_seconds($attempt));
}

function failure_delay_seconds(int $attempt): int
{
    $attempt = max(1, min(10, $attempt));
    return 2 ** ($attempt - 1);
}

function delay_message(int $attempt): string
{
    $seconds = failure_delay_seconds($attempt);
    return 'Fehlgeschlagen. Bitte ' . $seconds . ' Sekunde' . ($seconds === 1 ? '' : 'n') . ' warten.';
}

function refresh_session_cookie(int $ttlSeconds = SESSION_COOKIE_TTL_SECONDS): void
{
    if (!ini_get('session.use_cookies')) {
        return;
    }
    $params = session_get_cookie_params();
    setcookie(
        session_name(),
        session_id(),
        [
            'expires' => time() + $ttlSeconds,
            'path' => $params['path'] ?? '/',
            'domain' => $params['domain'] ?? '',
            'secure' => (bool)($params['secure'] ?? true),
            'httponly' => (bool)($params['httponly'] ?? true),
            'samesite' => (string)($params['samesite'] ?? 'Strict'),
        ]
    );
}

function destroy_session_cookie(): void
{
    if (ini_get('session.use_cookies')) {
        $params = session_get_cookie_params();
        setcookie(
            session_name(),
            '',
            [
                'expires' => time() - 42000,
                'path' => $params['path'] ?? '/',
                'domain' => $params['domain'] ?? '',
                'secure' => (bool)($params['secure'] ?? false),
                'httponly' => (bool)($params['httponly'] ?? true),
                'samesite' => (string)($params['samesite'] ?? 'Strict'),
            ]
        );
    }
}

function invalidate_admin_session(): void
{
    $_SESSION = [];
    destroy_session_cookie();
    session_destroy();
}

function clear_admin_auth_state(bool $regenerateSessionId = true): void
{
    if ($regenerateSessionId && session_status() === PHP_SESSION_ACTIVE) {
        session_regenerate_id(true);
    }
    unset($_SESSION['logged_in'], $_SESSION['auth_expires_at'], $_SESSION['auth_fingerprint']);
    reset_csrf_token();
}

function clear_checkin_auth_state(): void
{
    unset($_SESSION['checkin_auth_expires_at'], $_SESSION['checkin_auth_fingerprint']);
}

function mark_admin_authenticated(): void
{
    session_regenerate_id(true);
    $_SESSION['logged_in'] = true;
    $_SESSION['auth_expires_at'] = time() + SESSION_TTL_SECONDS;
    $_SESSION['auth_fingerprint'] = session_user_agent_fingerprint();
    unset($_SESSION['checkin_reauth_required']);
    refresh_session_cookie();
    reset_csrf_token();
}

function mark_checkin_authenticated(): void
{
    $_SESSION['checkin_auth_expires_at'] = time() + CHECKIN_SESSION_TTL_SECONDS;
    $_SESSION['checkin_auth_fingerprint'] = session_user_agent_fingerprint();
    unset($_SESSION['checkin_reauth_required']);
    refresh_session_cookie(CHECKIN_SESSION_TTL_SECONDS);
}

function is_admin_authenticated(): bool
{
    $loggedIn = $_SESSION['logged_in'] ?? false;
    $expiresAt = (int)($_SESSION['auth_expires_at'] ?? 0);

    if ($loggedIn !== true) {
        return false;
    }

    if (!session_user_agent_matches($_SESSION['auth_fingerprint'] ?? null)) {
        clear_admin_auth_state();
        clear_checkin_auth_state();
        return false;
    }

    if ($expiresAt < time()) {
        clear_admin_auth_state();
        return false;
    }

    $_SESSION['auth_expires_at'] = time() + SESSION_TTL_SECONDS;
    refresh_session_cookie();
    return true;
}

function is_checkin_authenticated(): bool
{
    $expiresAt = (int)($_SESSION['checkin_auth_expires_at'] ?? 0);

    if ($expiresAt >= time()) {
        if (!session_user_agent_matches($_SESSION['checkin_auth_fingerprint'] ?? null)) {
            clear_checkin_auth_state();
            clear_admin_auth_state();
            return false;
        }
        $_SESSION['checkin_auth_expires_at'] = time() + CHECKIN_SESSION_TTL_SECONDS;
        refresh_session_cookie(CHECKIN_SESSION_TTL_SECONDS);
        return true;
    }

    clear_checkin_auth_state();

    if (is_admin_authenticated()) {
        mark_checkin_authenticated();
        return true;
    }

    return false;
}

function load_pin_state(): array
{
    $fallback = ['failures' => 0, 'blocked_until' => 0];
    if (!file_exists(PIN_STATE_FILE)) {
        return $fallback;
    }
    $data = safe_read_json(PIN_STATE_FILE, $fallback);
    return [
        'failures' => max(0, (int)($data['failures'] ?? 0)),
        'blocked_until' => max(0, (int)($data['blocked_until'] ?? 0)),
    ];
}

function save_pin_state(array $state): void
{
    safe_write_json(PIN_STATE_FILE, [
        'failures' => max(0, (int)($state['failures'] ?? 0)),
        'blocked_until' => max(0, (int)($state['blocked_until'] ?? 0)),
    ]);
    safe_chmod(PIN_STATE_FILE, 0600);
}

function reset_pin_state(): void
{
    save_pin_state(['failures' => 0, 'blocked_until' => 0]);
}

function is_pin_locked(): bool
{
    $state = load_pin_state();
    $blockedUntil = (int)($state['blocked_until'] ?? 0);
    if ($blockedUntil > 0 && $blockedUntil <= time()) {
        if ((int)$state['failures'] !== 0 || $blockedUntil !== 0) {
            reset_pin_state();
        }
        return false;
    }
    return $blockedUntil > time();
}

function record_pin_failure(array $config): array
{
    $state = load_pin_state();
    $failures = (int)$state['failures'] + 1;
    $blockedUntil = (int)$state['blocked_until'];
    if ($failures >= rate_limit_max_failures($config)) {
        $blockedUntil = time() + rate_limit_seconds($config);
    }
    $state = [
        'failures' => $failures,
        'blocked_until' => $blockedUntil,
    ];
    save_pin_state($state);
    return $state;
}

function force_checkin_reauthentication(): void
{
    clear_admin_auth_state();
    clear_checkin_auth_state();
    $_SESSION['checkin_reauth_required'] = true;
}

function complete_manual_checkin(array &$config): void
{
    $config['last_checkin_at'] = time();
    $config['next_due_at'] = time() + (int)$config['interval_seconds'];
    $config['reminder_sent_this_cycle'] = false;
    $config['last_reminder_sent_at'] = null;
    $config['triggered'] = false;
    $config['triggered_at'] = null;
    $config['last_dispatch_result'] = ['ok' => [], 'fail' => []];
    write_config($config);
}

function handle_admin_login_attempt(array $config, string $ip): array
{
    if ($_SERVER['REQUEST_METHOD'] !== 'POST' || (string)($_POST['form_name'] ?? '') !== 'admin_login') {
        return ['success' => false, 'error' => ''];
    }

    if (!login_allowed($ip)) {
        apply_failure_delay_for_attempt(rate_limit_max_failures($config));
        log_event('Admin login failure');
        return ['success' => false, 'error' => 'Unberechtigter Zugriffsversuch wurde protokolliert und der Admin per E-Mail informiert.'];
    }

    require_csrf();
    $captcha = (string)($_POST['captcha_response'] ?? '');
    $password = (string)($_POST['password'] ?? '');

    if (!verify_captcha('admin_login', $captcha) || !password_verify($password, (string)($config['password_hash'] ?? ''))) {
        $rateState = record_login_failure($ip, $config);
        $attempt = max(1, (int)($rateState['failures'] ?? 1));
        if (($rateState['triggered'] ?? false) === true) {
            send_admin_lockout_notification($config, $ip);
            apply_failure_delay_for_attempt(rate_limit_max_failures($config));
            log_event('Admin login failure');
            return ['success' => false, 'error' => 'Unberechtigter Zugriffsversuch wurde protokolliert und der Admin per E-Mail informiert.'];
        }
        apply_failure_delay_for_attempt($attempt);
        log_event('Admin login failure');
        return ['success' => false, 'error' => delay_message($attempt)];
    }

    mark_admin_authenticated();
    clear_login_failures($ip);
    clear_checkin_failures($ip);
    reset_pin_state();
    log_event('Admin login success');
    return ['success' => true, 'error' => ''];
}

function validate_admin_password(string $password): ?string
{
    if (strlen($password) < 12) {
        return 'Admin-Passwort muss mindestens 12 Zeichen lang sein.';
    }
    if (!preg_match('/[a-z]/', $password) || !preg_match('/[A-Z]/', $password) || !preg_match('/\d/', $password) || !preg_match('/[^a-zA-Z0-9]/', $password)) {
        return 'Admin-Passwort muss Gross-/Kleinbuchstaben, Zahl und Sonderzeichen enthalten.';
    }
    return null;
}

function rate_limit_minutes(?array $config = null): int
{
    return max(1, intdiv(RATE_LIMIT_BLOCK_SECONDS, 60));
}

function rate_limit_max_failures(?array $config = null): int
{
    $max = (int)($config['rate_limit_max_failures'] ?? PIN_MAX_FAILURES);
    return max(1, min(50, $max));
}

function rate_limit_seconds(?array $config = null): int
{
    return RATE_LIMIT_BLOCK_SECONDS;
}

function rate_limit_wait_text(?array $config = null): string
{
    $minutes = rate_limit_minutes($config);
    return $minutes === 1 ? '1 Minute' : $minutes . ' Minuten';
}

function log_filter_options(): array
{
    return [
        'all' => 'Alle',
        'rate_limiter' => 'Rate-Limiter',
        'checkin' => 'Check-in',
        'security' => 'Sicherheit',
        'system' => 'System',
        'mail' => 'Mail',
        'alarm' => 'Alarm/DMS',
    ];
}

function normalize_log_filter(?string $filter): string
{
    $filter = (string)$filter;
    return array_key_exists($filter, log_filter_options()) ? $filter : 'all';
}

function log_filter_matches(string $line, string $filter): bool
{
    $line = strtolower($line);
    return match ($filter) {
        'rate_limiter' => str_contains($line, 'rate limiter'),
        'checkin' => str_contains($line, 'check-in'),
        'security' => str_contains($line, 'security') || str_contains($line, 'passwort') || str_contains($line, 'pin'),
        'system' => str_contains($line, 'system installed') || str_contains($line, 'logs cleared') || str_contains($line, 'reset'),
        'mail' => str_contains($line, 'mail'),
        'alarm' => str_contains($line, 'dms triggered') || str_contains($line, 'alarm'),
        default => true,
    };
}

function normalize_log_query(?string $query): string
{
    $query = trim((string)$query);
    return mb_substr($query, 0, 100);
}

function read_events_log(int $maxLines = 300, string $filter = 'all', string $query = ''): string
{
    $filter = normalize_log_filter($filter);
    $query = normalize_log_query($query);
    if (!file_exists(LOG_FILE)) {
        return "Noch keine Logs vorhanden.";
    }
    try {
        $logContent = rtrim(read_file_strict(LOG_FILE));
        $raw = $logContent === '' ? [] : preg_split('/\r\n|\r|\n/', $logContent);
    } catch (Throwable $e) {
        return "events.log konnte nicht gelesen werden.";
    }
    if (!is_array($raw)) {
        return "events.log konnte nicht gelesen werden.";
    }
    if ($filter !== 'all') {
        $raw = array_values(array_filter($raw, fn($line) => is_string($line) && log_filter_matches($line, $filter)));
    }
    if ($query !== '') {
        $raw = array_values(array_filter($raw, fn($line) => is_string($line) && mb_stripos($line, $query) !== false));
    }
    $lines = array_slice($raw, -$maxLines);
    if (empty($lines)) {
        return "Keine Logeinträge für den gewählten Filter/Suchbegriff.";
    }
    return implode("\n", $lines);
}

function load_rate_limit(): array
{
    if (!file_exists(RATE_LIMIT_FILE)) {
        return [];
    }
    return safe_read_json(RATE_LIMIT_FILE, []);
}

function save_rate_limit(array $data): void
{
    try {
        require_data_dir_ready();
        safe_write_json(RATE_LIMIT_FILE, $data);
    } catch (Throwable $e) {
        add_diag($e->getMessage());
    }
    safe_chmod(RATE_LIMIT_FILE, 0600);
}

function rate_limit_key(string $scope, string $ip): string
{
    return $scope . ':' . $ip;
}

function rate_limit_allowed(string $scope, string $ip): bool
{
    $data = load_rate_limit();
    $entry = $data[rate_limit_key($scope, $ip)] ?? ['failures' => [], 'blocked_until' => 0];
    if (($entry['blocked_until'] ?? 0) > time()) {
        return false;
    }
    return true;
}

function record_rate_limit_failure(string $scope, string $ip, int $windowSeconds = 900, int $maxFailures = 5, int $blockSeconds = 900): array
{
    $data = load_rate_limit();
    $key = rate_limit_key($scope, $ip);
    $entry = $data[$key] ?? ['failures' => [], 'blocked_until' => 0];
    $now = time();
    $triggered = false;
    $entry['failures'] = array_values(array_filter($entry['failures'] ?? [], fn($t) => is_int($t) && $t > $now - $windowSeconds));
    $entry['failures'][] = $now;
    if (count($entry['failures']) >= $maxFailures) {
        $entry['blocked_until'] = $now + $blockSeconds;
        $entry['failures'] = [];
        $triggered = true;
        log_event('Rate limiter triggered. scope=' . $scope . ' ip=' . $ip . ' blocked_until=' . date('Y-m-d H:i:s', $entry['blocked_until']));
    }
    $data[$key] = $entry;
    save_rate_limit($data);
    return [
        'failures' => count($entry['failures']),
        'blocked_until' => (int)($entry['blocked_until'] ?? 0),
        'triggered' => $triggered,
    ];
}

function clear_rate_limit(string $scope, string $ip): void
{
    $data = load_rate_limit();
    unset($data[rate_limit_key($scope, $ip)]);
    save_rate_limit($data);
}

function login_allowed(string $ip): bool
{
    return rate_limit_allowed('login', $ip);
}

function record_login_failure(string $ip, ?array $config = null): array
{
    return record_rate_limit_failure(
        'login',
        $ip,
        rate_limit_seconds($config),
        rate_limit_max_failures($config),
        rate_limit_seconds($config)
    );
}

function clear_login_failures(string $ip): void
{
    clear_rate_limit('login', $ip);
}

function checkin_allowed(string $ip): bool
{
    return rate_limit_allowed('checkin', $ip);
}

function record_checkin_failure(string $ip, ?array $config = null): array
{
    return record_rate_limit_failure(
        'checkin',
        $ip,
        rate_limit_seconds($config),
        rate_limit_max_failures($config),
        rate_limit_seconds($config)
    );
}

function clear_checkin_failures(string $ip): void
{
    clear_rate_limit('checkin', $ip);
}

function captcha_session_key(string $context): string
{
    return 'captcha_' . preg_replace('/[^a-z0-9_]/i', '_', $context);
}

function captcha_settings(string $context): array
{
    if ($context === 'checkin') {
        return [
            'alphabet' => '0123456789',
            'length' => 4,
            'inputmode' => 'numeric',
            'maxlength' => 4,
            'pattern' => '[0-9]{4}',
        ];
    }
    return [
        'alphabet' => 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789',
        'length' => 6,
        'inputmode' => 'text',
        'maxlength' => 6,
        'pattern' => '',
    ];
}

function new_captcha_code(string $context): string
{
    $settings = captcha_settings($context);
    $alphabet = $settings['alphabet'];
    $length = (int)$settings['length'];
    $max = strlen($alphabet) - 1;
    $code = '';
    for ($i = 0; $i < $length; $i++) {
        $code .= $alphabet[random_int(0, $max)];
    }
    return $code;
}

function refresh_captcha(string $context): string
{
    $code = new_captcha_code($context);
    $_SESSION[captcha_session_key($context)] = [
        'code' => $code,
        'expires_at' => time() + 300,
    ];
    return $code;
}

function require_captcha_ready(string $context): void
{
    $key = captcha_session_key($context);
    $entry = $_SESSION[$key] ?? null;
    if (!is_array($entry) || empty($entry['code']) || (int)($entry['expires_at'] ?? 0) < time()) {
        refresh_captcha($context);
    }
}

function verify_captcha(string $context, string $input): bool
{
    $key = captcha_session_key($context);
    $entry = $_SESSION[$key] ?? null;
    unset($_SESSION[$key]);
    if (!is_array($entry) || empty($entry['code']) || (int)($entry['expires_at'] ?? 0) < time()) {
        return false;
    }
    $expected = strtoupper((string)$entry['code']);
    $provided = strtoupper(trim($input));
    return $provided !== '' && hash_equals($expected, $provided);
}

function render_captcha_svg(string $code): string
{
    $chars = preg_split('//u', $code, -1, PREG_SPLIT_NO_EMPTY) ?: [];
    $pieces = [];
    $palette = ['#1f4fa3', '#0f7f5f', '#9a3b8f', '#b85b16', '#8b2e45', '#2a6ba5'];
    $noise = [];

    for ($i = 0; $i < 6; $i++) {
        $x1 = random_int(0, 220);
        $y1 = random_int(8, 56);
        $x2 = random_int(0, 220);
        $y2 = random_int(8, 56);
        $stroke = $palette[$i % count($palette)];
        $noise[] = '<line x1="' . $x1 . '" y1="' . $y1 . '" x2="' . $x2 . '" y2="' . $y2 . '" stroke="' . $stroke . '" stroke-opacity="0.18" stroke-width="' . random_int(1, 2) . '"/>';
    }

    for ($i = 0; $i < 10; $i++) {
        $cx = random_int(10, 210);
        $cy = random_int(10, 54);
        $r = random_int(1, 2);
        $fill = $palette[array_rand($palette)];
        $noise[] = '<circle cx="' . $cx . '" cy="' . $cy . '" r="' . $r . '" fill="' . $fill . '" fill-opacity="0.16"/>';
    }

    for ($i = 0; $i < 18; $i++) {
        $cx = random_int(8, 212);
        $cy = random_int(8, 56);
        $r = random_int(1, 2);
        $fill = $palette[array_rand($palette)];
        $noise[] = '<circle cx="' . $cx . '" cy="' . $cy . '" r="' . $r . '" fill="' . $fill . '" fill-opacity="0.24"/>';
    }

    $baseCenters = [24, 56, 88, 120, 152, 184];
    foreach ($chars as $i => $char) {
        $x = ($baseCenters[$i] ?? (24 + ($i * 32))) + random_int(-3, 3);
        $y = random_int(30, 38);
        $rotate = random_int(-12, 12);
        $fontSize = random_int(24, 28);
        $fill = $palette[$i % count($palette)];
        $pieces[] = '<text x="' . $x . '" y="' . $y . '" text-anchor="middle" transform="rotate(' . $rotate . ' ' . $x . ' ' . $y . ')" font-size="' . $fontSize . '" font-family="monospace" font-weight="700" fill="' . $fill . '">' . h($char) . '</text>';
    }
    return '<svg xmlns="http://www.w3.org/2000/svg" width="220" height="64" viewBox="0 0 220 64" role="img" aria-label="Captcha">'
        . '<rect width="220" height="64" rx="16" fill="#eef7fb" stroke="#8bb6ca"/>'
        . implode('', $noise)
        . '<path d="M8 48 C34 18, 70 58, 104 26 S174 12, 212 38" fill="none" stroke="#7cc7e8" stroke-width="3"/>'
        . '<path d="M14 18 C42 46, 74 6, 112 36 S168 56, 206 18" fill="none" stroke="#f0c15d" stroke-width="2.5"/>'
        . implode('', $pieces)
        . '</svg>';
}

function render_captcha_html(string $context, string $label = 'Sicherheitscode', bool $showLabel = true, string $wrapperClass = ''): string
{
    require_captcha_ready($context);
    $settings = captcha_settings($context);
    $nonce = bin2hex(random_bytes(6));
    $imgId = 'captcha-img-' . preg_replace('/[^a-z0-9_]/i', '-', $context);
    $classAttr = trim($wrapperClass);
    $classHtml = $classAttr !== '' ? ' class="' . h($classAttr) . '"' : '';
    $patternAttr = $settings['pattern'] !== '' ? ' pattern="' . h((string)$settings['pattern']) . '"' : '';
    return '<div' . $classHtml . '>'
        . ($showLabel ? '<label>' . h($label) . '</label>' : '')
        . '<div class="captcha-box">'
        . '<img id="' . h($imgId) . '" src="' . h(safe_self_path() . '?captcha=' . rawurlencode($context) . '&v=' . $nonce) . '" alt="Captcha" width="220" height="64" loading="eager" decoding="sync">'
        . '</div><button type="button" class="captcha-refresh" aria-label="Captcha aktualisieren" title="Captcha aktualisieren" onclick="var i=document.getElementById(\'' . h($imgId) . '\'); if(i){i.src=\'' . h(safe_self_path() . '?captcha=' . rawurlencode($context) . '&v=') . '\'+Date.now();}">🔄</button><input type="text" name="captcha_response" maxlength="' . h((string)$settings['maxlength']) . '" autocomplete="off" spellcheck="false" inputmode="' . h((string)$settings['inputmode']) . '"' . $patternAttr . ' required></div>';
}

function sanitize_header_value(string $value): string
{
    $value = trim(preg_replace('/[\r\n]+/', ' ', $value) ?? '');
    return preg_replace('/[^\P{C}\t]/u', '', $value) ?? '';
}

function validate_smtp_settings(string $mode, string $host, int $port, string $user, string $pass, string $from, string $secure, bool $allowExistingPassword = false): array
{
    $errors = [];
    if (!in_array($mode, ['smtp', 'mail'], true)) {
        $errors[] = 'Ungültiger Versandmodus.';
    }
    if (!in_array($secure, ['tls', 'ssl'], true)) {
        $errors[] = 'Ungültiger SMTP-Sicherheitsmodus.';
    }
    if ($from !== '' && !filter_var($from, FILTER_VALIDATE_EMAIL)) {
        $errors[] = 'Absenderadresse ist ungültig.';
    }
    if ($mode === 'smtp') {
        if ($host === '' || !preg_match('/^(?:[a-z0-9.-]+|\[[a-f0-9:]+\])$/i', $host)) {
            $errors[] = 'SMTP-Host ist ungültig.';
        }
        if ($port < 1 || $port > 65535) {
            $errors[] = 'SMTP-Port ist ungültig.';
        }
        if ($user === '' || !filter_var($user, FILTER_VALIDATE_EMAIL)) {
            $errors[] = 'SMTP-Benutzer muss eine gültige E-Mail-Adresse sein.';
        }
        if ($pass === '' && !$allowExistingPassword) {
            $errors[] = 'SMTP-Passwort fehlt.';
        }
    }
    return $errors;
}

function diagnostics_html(): string
{
    $items = [];
    $items[] = 'Aktives Datenverzeichnis: ' . DATA_DIR;
    $items[] = 'Alternatives Datenverzeichnis: ' . ALT_DATA_DIR;
    $items[] = 'Datenverzeichnis vorhanden: ' . (is_dir(DATA_DIR) ? 'ja' : 'nein');
    $items[] = 'Datenverzeichnis lesbar: ' . (is_readable(DATA_DIR) ? 'ja' : 'nein');
    $items[] = 'Datenverzeichnis schreibbar: ' . (is_writable(DATA_DIR) ? 'ja' : 'nein');
    $items[] = 'Config vorhanden: ' . (file_exists(CONFIG_FILE) ? 'ja' : 'nein');
    $items[] = 'Key vorhanden: ' . (file_exists(KEY_FILE) ? 'ja' : 'nein');
    foreach (get_diags() as $diag) {
        $items[] = 'Hinweis: ' . $diag;
    }
    $html = '<div class="alert alert-bad"><strong>Systemdiagnose</strong><br>';
    $html .= implode('<br>', array_map('h', $items));
    $html .= '</div>';
    return $html;
}

function redirect_self(): void
{
    header('Location: ' . safe_self_path());
    exit;
}

function format_interval(int $seconds): string
{
    $seconds = max(0, $seconds);
    $days = intdiv($seconds, 86400);
    $seconds %= 86400;
    $hours = intdiv($seconds, 3600);
    $seconds %= 3600;
    $minutes = intdiv($seconds, 60);
    $parts = [];
    if ($days) $parts[] = $days . ' Tag(e)';
    if ($hours) $parts[] = $hours . ' Stunde(n)';
    if ($minutes || !$parts) $parts[] = $minutes . ' Minute(n)';
    return implode(', ', $parts);
}

function format_remaining(int $seconds): string
{
    if ($seconds <= 0) {
        return '0 Minuten';
    }
    return format_interval($seconds);
}

function parse_emails(string $csv): array
{
    $items = preg_split('/[,;\n\r]+/', $csv) ?: [];
    $valid = [];
    foreach ($items as $item) {
        $email = trim($item);
        if ($email !== '' && filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $valid[strtolower($email)] = $email;
        }
    }
    return array_values($valid);
}

function render_template_vars(string $text, array $vars): string
{
    return strtr($text, [
        '{{installed_at}}' => $vars['installed_at'] ?? '',
        '{{system_url}}' => $vars['system_url'] ?? '',
        '{{interval}}' => $vars['interval'] ?? '',
        '{{reminder_email}}' => $vars['reminder_email'] ?? '',
        '{{recipient_email}}' => $vars['recipient_email'] ?? '',
    ]);
}

function default_welcome_subject(): string
{
    return 'Du wurdest als Vertrauensperson hinterlegt';
}

function default_welcome_body(): string
{
    return "Hallo,\n\n"
        . "diese E-Mail informiert dich darüber, dass deine Adresse in einem Dead Man's Switch als Vertrauensperson oder Benachrichtigungsadresse hinterlegt wurde.\n\n"
        . "System-URL: {{system_url}}\n"
        . "Installiert am: {{installed_at}}\n"
        . "Check-in-Intervall: {{interval}}\n"
        . "Erinnerungsadresse: {{reminder_email}}\n\n"
        . "Das bedeutet nicht, dass jetzt etwas passiert ist. Diese Mail dient nur zur Information.\n";
}

function default_dms_subject(): string
{
    return 'Dead Man\'s Switch Nachricht';
}

function default_dms_message(): string
{
    return "Diese Nachricht wurde automatisch ausgelöst, weil das Check-in-Intervall verpasst wurde.\n";
}

// -------------------- Mail transport --------------------
function smtp_read($fp): string
{
    $data = '';
    while (!feof($fp)) {
        $line = fgets($fp, 515);
        if ($line === false) break;
        $data .= $line;
        if (preg_match('/^\d{3} /', $line)) break;
    }
    return $data;
}

function smtp_expect($fp, array $codes): string
{
    $resp = smtp_read($fp);
    $code = (int)substr(trim($resp), 0, 3);
    if (!in_array($code, $codes, true)) {
        throw new RuntimeException('SMTP unexpected response: ' . trim($resp));
    }
    return $resp;
}

function smtp_cmd($fp, string $cmd, array $codes): string
{
    fwrite($fp, $cmd . "\r\n");
    return smtp_expect($fp, $codes);
}

function send_via_smtp(string $to, string $subject, string $body, array $smtp): bool|string
{
    $host = trim((string)($smtp['host'] ?? ''));
    $port = (int)($smtp['port'] ?? 0);
    $user = trim((string)($smtp['user'] ?? ''));
    $pass = (string)($smtp['pass'] ?? '');
    $from = trim((string)($smtp['from'] ?? $user));
    $secure = strtolower(trim((string)($smtp['secure'] ?? 'tls')));
    $subject = sanitize_header_value($subject);
    $from = sanitize_header_value($from);

    if ($host === '' || $port <= 0 || $user === '' || $pass === '' || !filter_var($to, FILTER_VALIDATE_EMAIL) || !filter_var($from, FILTER_VALIDATE_EMAIL)) {
        return 'SMTP unvollständig konfiguriert';
    }
    if (!preg_match('/^(?:[a-z0-9.-]+|\[[a-f0-9:]+\])$/i', $host)) {
        return 'SMTP Host ist ungültig';
    }
    if (!in_array($secure, ['tls', 'ssl', 'smtps'], true)) {
        return 'SMTP Sicherheitsmodus ist ungültig';
    }

    $remote = ($secure === 'ssl' || $secure === 'smtps') ? 'ssl://' . $host : $host;
    $errno = 0;
    $errstr = '';
    $fp = fsockopen($remote, $port, $errno, $errstr, 15);
    if (!$fp) {
        return 'SMTP Verbindung fehlgeschlagen: ' . $errstr;
    }
    stream_set_timeout($fp, 15);

    try {
        smtp_expect($fp, [220]);
        smtp_cmd($fp, 'EHLO localhost', [250]);
        if ($secure === 'tls') {
            smtp_cmd($fp, 'STARTTLS', [220]);
            if (!stream_socket_enable_crypto($fp, true, STREAM_CRYPTO_METHOD_TLS_CLIENT)) {
                throw new RuntimeException('STARTTLS fehlgeschlagen');
            }
            smtp_cmd($fp, 'EHLO localhost', [250]);
        }
        smtp_cmd($fp, 'AUTH LOGIN', [334]);
        smtp_cmd($fp, base64_encode($user), [334]);
        smtp_cmd($fp, base64_encode($pass), [235]);
        smtp_cmd($fp, 'MAIL FROM:<' . $from . '>', [250]);
        smtp_cmd($fp, 'RCPT TO:<' . $to . '>', [250, 251]);
        smtp_cmd($fp, 'DATA', [354]);

        $headers = [
            'Date: ' . date(DATE_RFC2822),
            'From: ' . $from,
            'To: ' . $to,
            'Subject: =?UTF-8?B?' . base64_encode($subject) . '?=',
            'MIME-Version: 1.0',
            'Content-Type: text/plain; charset=UTF-8',
            'Content-Transfer-Encoding: 8bit',
        ];
        $msg = implode("\r\n", $headers) . "\r\n\r\n" . str_replace(["\r\n.", "\n."], ["\r\n..", "\n.."], $body) . "\r\n.";
        fwrite($fp, $msg . "\r\n");
        smtp_expect($fp, [250]);
        smtp_cmd($fp, 'QUIT', [221]);
        fclose($fp);
        return true;
    } catch (Throwable $e) {
        fclose($fp);
        return $e->getMessage();
    }
}

function send_mail_any(string $to, string $subject, string $body, array $payload): bool|string
{
    $smtp = $payload['smtp'] ?? [];
    $mode = strtolower(trim((string)($smtp['mode'] ?? 'smtp')));
    if ($mode === 'mail') {
        $from = sanitize_header_value(trim((string)($smtp['from'] ?? '')));
        $subject = sanitize_header_value($subject);
        $headers = [];
        if ($from !== '') {
            if (!filter_var($from, FILTER_VALIDATE_EMAIL)) {
                return 'Absenderadresse ist ungültig';
            }
            $headers[] = 'From: ' . $from;
        }
        $headers[] = 'Content-Type: text/plain; charset=UTF-8';
        $ok = mail($to, '=?UTF-8?B?' . base64_encode($subject) . '?=', $body, implode("\r\n", $headers));
        return $ok ? true : 'mail() fehlgeschlagen';
    }
    return send_via_smtp($to, $subject, $body, $smtp);
}

function send_bulk(array $recipients, string $subject, string $body, array $payload): array
{
    $ok = [];
    $fail = [];
    foreach ($recipients as $recipient) {
        $res = send_mail_any($recipient, $subject, $body, $payload);
        if ($res === true) {
            $ok[] = $recipient;
        } else {
            $fail[$recipient] = $res;
        }
    }
    return ['ok' => $ok, 'fail' => $fail];
}

function system_vars(array $config, array $payload): array
{
    return [
        'installed_at' => !empty($config['installed_at']) ? date('d.m.Y H:i:s', (int)$config['installed_at']) : date('d.m.Y H:i:s'),
        'system_url' => base_url($config),
        'interval' => format_interval((int)($config['interval_seconds'] ?? 0)),
        'reminder_email' => (string)($payload['reminder_email'] ?? ''),
    ];
}

function send_admin_lockout_notification(array $config, string $ip): void
{
    $payload = decrypt_payload((string)($config['encrypted_payload'] ?? ''));
    $recipient = trim((string)($payload['reminder_email'] ?? ''));
    if ($recipient === '' || !filter_var($recipient, FILTER_VALIDATE_EMAIL)) {
        log_event('Admin login lockout notification skipped');
        return;
    }

    $subject = 'Sicherheitswarnung: Admin-Login gesperrt';
    $body = "Ein unberechtigter Zugriffsversuch wurde erkannt.\n\n"
        . 'Zeit: ' . date('d.m.Y H:i:s') . "\n"
        . 'IP: ' . $ip . "\n"
        . 'System: ' . base_url($config) . "\n\n"
        . 'Der Admin-Login wurde wegen zu vieler Fehlversuche vorübergehend gesperrt.';

    $result = send_mail_any($recipient, $subject, $body, $payload);
    if ($result === true) {
        log_event('Admin login lockout notification sent');
        return;
    }
    log_event('Admin login lockout notification failed');
}

function send_welcome_mails(array $config, array $payload): array
{
    $recipients = parse_emails((string)($payload['recipients_csv'] ?? ''));
    if (!empty($payload['reminder_email']) && filter_var($payload['reminder_email'], FILTER_VALIDATE_EMAIL)) {
        $recipients[] = $payload['reminder_email'];
    }
    $recipients = array_values(array_unique(array_map('strtolower', $recipients)));
    if (empty($recipients)) {
        return ['ok' => [], 'fail' => []];
    }

    $ok = [];
    $fail = [];
    $vars = system_vars($config, $payload);
    $subjectTpl = (string)($payload['welcome_subject'] ?? default_welcome_subject());
    $bodyTpl = (string)($payload['welcome_body'] ?? default_welcome_body());
    foreach ($recipients as $recipient) {
        $subject = render_template_vars($subjectTpl, $vars + ['recipient_email' => $recipient]);
        $body = render_template_vars($bodyTpl, $vars + ['recipient_email' => $recipient]);
        $res = send_mail_any($recipient, $subject, $body, $payload);
        if ($res === true) $ok[] = $recipient; else $fail[$recipient] = $res;
    }
    return ['ok' => $ok, 'fail' => $fail];
}

function trigger_dms(array &$config, array $payload): array
{
    $recipients = parse_emails((string)($payload['recipients_csv'] ?? ''));
    if (empty($recipients)) {
        $config['triggered'] = true;
        $config['triggered_at'] = time();
        $config['last_dispatch_result'] = ['ok' => [], 'fail' => ['__system__' => 'Keine gültigen Empfänger konfiguriert']];
        write_config($config);
        return $config['last_dispatch_result'];
    }
    $subject = (string)($payload['dms_subject'] ?? default_dms_subject());
    $body = (string)($payload['dms_message'] ?? default_dms_message());
    $result = send_bulk($recipients, $subject, $body, $payload);
    $config['triggered'] = true;
    $config['triggered_at'] = time();
    $config['last_dispatch_result'] = $result;
    write_config($config);
    log_event('DMS triggered. ok=' . count($result['ok']) . ' fail=' . count($result['fail']));
    return $result;
}

function process_cron(array &$config, bool $allowMail = true): string
{
    $payload = decrypt_payload((string)($config['encrypted_payload'] ?? ''));
    if (empty($payload)) {
        return "Config broken: encrypted payload unreadable.";
    }

    $now = time();
    $interval = (int)($config['interval_seconds'] ?? 0);
    if ($interval <= 0) {
        return "Setup incomplete: invalid interval.";
    }

    $lines = [];
    $lines[] = 'Now: ' . date('d.m.Y H:i:s', $now);
    $lines[] = 'Next due: ' . date('d.m.Y H:i:s', (int)$config['next_due_at']);
    $lines[] = 'Remaining seconds: ' . max(0, (int)$config['next_due_at'] - $now);

    if (!empty($config['triggered'])) {
        $lines[] = 'Alarm already triggered.';
        if (!empty($config['triggered_at'])) {
            $lines[] = 'Triggered at: ' . date('d.m.Y H:i:s', (int)$config['triggered_at']);
        }
        $res = $config['last_dispatch_result'] ?? ['ok' => [], 'fail' => []];
        $lines[] = 'Successful deliveries: ' . count($res['ok'] ?? []);
        $lines[] = 'Failed deliveries: ' . count($res['fail'] ?? []);
        return implode("\n", $lines);
    }

    $reminderThreshold = (int)floor($interval * 0.2);
    $reminderAt = (int)$config['next_due_at'] - $reminderThreshold;
    $reminderEmail = trim((string)($payload['reminder_email'] ?? ''));
    $reminderSentThisCycle = !empty($config['reminder_sent_this_cycle']);

    if ($allowMail && !$reminderSentThisCycle && $reminderEmail !== '' && filter_var($reminderEmail, FILTER_VALIDATE_EMAIL) && $now >= $reminderAt && $now < (int)$config['next_due_at']) {
        $subject = 'Erinnerung: Dead Man\'s Switch Check-in bald fällig';
        $body = "Dies ist eine automatische Erinnerung.\n\n"
            . "Bitte führe bald deinen Dead Man's Switch Check-in aus.\n"
            . "Nächste Fälligkeit: " . date('d.m.Y H:i:s', (int)$config['next_due_at']) . "\n"
            . "Restzeit: " . format_remaining((int)$config['next_due_at'] - $now) . "\n"
            . "Check-in-Link: " . base_url($config) . "/checkin\n";
        $res = send_mail_any($reminderEmail, $subject, $body, $payload);
        if ($res === true) {
            $config['reminder_sent_this_cycle'] = true;
            $config['last_reminder_sent_at'] = $now;
            write_config($config);
            $lines[] = 'Reminder sent.';
        } else {
            $lines[] = 'Reminder failed: ' . $res;
        }
    }

    if ($now >= (int)$config['next_due_at']) {
        if ($allowMail) {
            $result = trigger_dms($config, $payload);
            $lines[] = 'Alarm triggered. Messages dispatched.';
            $lines[] = 'Successful deliveries: ' . count($result['ok']);
            $lines[] = 'Failed deliveries: ' . count($result['fail']);
            if (!empty($result['fail'])) {
                foreach ($result['fail'] as $mail => $err) {
                    $lines[] = 'FAIL ' . $mail . ': ' . $err;
                }
            }
        } else {
            $lines[] = 'Alarm would trigger now.';
        }
        return implode("\n", $lines);
    }

    if (count($lines) === 3) {
        $lines[] = 'All good.';
    }
    return implode("\n", $lines);
}

function require_login(): void
{
    if (!is_admin_authenticated()) {
        redirect_self();
    }
}

function normalize_theme(?string $theme): string
{
    return in_array($theme, ['dark', 'happy', 'cat'], true) ? $theme : 'light';
}

function theme_mascot(string $theme, string $format = 'text'): string
{
    $theme = normalize_theme($theme);
    $mascot = match ($theme) {
        'cat' => '😻',
        'happy' => '🌞',
        default => '💀',
    };
    if ($format === 'html') {
        return h($mascot);
    }
    return $mascot;
}

function render_header(string $title, string $theme = 'light'): void
{
    apply_security_headers();
    $theme = normalize_theme($theme);
    echo '<!doctype html><html lang="de"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">';
    echo '<title>' . theme_mascot($theme, 'html') . ' Deadman-Switch 2.0</title>';
    echo '<style>
        :root{--bg:#f4fbff;--bg-soft:#eef7fb;--surface:rgba(255,255,255,.68);--surface-strong:rgba(255,255,255,.82);--border:rgba(148,163,184,.32);--border-strong:rgba(148,163,184,.5);--shadow:0 24px 60px rgba(110,140,170,.22);--text:#16324a;--heading:#12314b;--muted:#5f7890;--accent:#3ca6d8;--accent-2:#7cc7e8;--accent-deep:#1f78a7;--ok:#dff7e8;--oktxt:#1f6b45;--bad:#ffe4e6;--badtxt:#a63f54;--warn:#fff1c7;--warntxt:#9b6a10;--field-bg:rgba(255,255,255,.9);--field-bg-focus:#fff;--field-text:#16324a;--field-placeholder:#6f879b}
        body.theme-dark{--bg:#0f1724;--bg-soft:#162235;--surface:rgba(18,29,44,.82);--surface-strong:rgba(22,35,53,.92);--border:rgba(118,143,173,.22);--border-strong:rgba(128,154,184,.34);--shadow:0 24px 60px rgba(0,0,0,.38);--text:#dbe8f5;--heading:#f3f8fd;--muted:#9eb2c7;--accent:#56b4e8;--accent-2:#8fd6ff;--accent-deep:#2977a5;--ok:#173729;--oktxt:#93e2b5;--bad:#3d1d25;--badtxt:#ffb8c2;--warn:#3f3518;--warntxt:#ffe19a;--field-bg:rgba(10,18,29,.92);--field-bg-focus:rgba(14,24,38,.98);--field-text:#f2f7fc;--field-placeholder:#8ea4ba}
        body.theme-happy{--bg:#fff9e8;--bg-soft:#fff3c8;--surface:rgba(255,255,255,.78);--surface-strong:rgba(255,255,255,.9);--border:rgba(240,176,76,.34);--border-strong:rgba(232,128,86,.42);--shadow:0 24px 60px rgba(233,164,88,.24);--text:#5b3b2a;--heading:#7a2f52;--muted:#8f6a52;--accent:#ff9f68;--accent-2:#ffd166;--accent-deep:#e46f8c;--ok:#e5f8d6;--oktxt:#3f7a34;--bad:#ffe0e6;--badtxt:#b54f6d;--warn:#fff0b8;--warntxt:#8d6500;--field-bg:rgba(255,255,255,.94);--field-bg-focus:#fffdf7;--field-text:#5b3b2a;--field-placeholder:#b08a73}
        body.theme-cat{--bg:#fff7f7;--bg-soft:#ffeef4;--surface:rgba(255,255,255,.82);--surface-strong:rgba(255,255,255,.94);--border:rgba(239,141,181,.30);--border-strong:rgba(199,120,164,.38);--shadow:0 24px 60px rgba(201,125,156,.24);--text:#5d3346;--heading:#8a315d;--muted:#95667d;--accent:#f08ab2;--accent-2:#ffc7a5;--accent-deep:#cf5f92;--ok:#e7f8e8;--oktxt:#3e7a49;--bad:#ffe0ea;--badtxt:#ad476f;--warn:#fff1c8;--warntxt:#8d6500;--field-bg:rgba(255,255,255,.96);--field-bg-focus:#fffafd;--field-text:#5d3346;--field-placeholder:#b08498}
        *{box-sizing:border-box}
        html{min-height:100%}
        body{margin:0;min-height:100vh;font-family:"Trebuchet MS","Segoe UI",sans-serif;color:var(--text);background:
            radial-gradient(circle at top left,rgba(124,199,232,.5),transparent 28%),
            radial-gradient(circle at top right,rgba(252,211,77,.28),transparent 24%),
            linear-gradient(180deg,#f8fdff 0%,#f2f8fc 44%,#edf5fa 100%);position:relative}
        body.theme-dark{background:
            radial-gradient(circle at top left,rgba(86,180,232,.2),transparent 28%),
            radial-gradient(circle at top right,rgba(242,201,76,.12),transparent 22%),
            linear-gradient(180deg,#0c1420 0%,#111b2a 44%,#0c1623 100%)}
        body.theme-happy{background:
            radial-gradient(circle at top left,rgba(255,207,128,.55),transparent 28%),
            radial-gradient(circle at top right,rgba(255,154,162,.32),transparent 24%),
            linear-gradient(180deg,#fffdf4 0%,#fff7df 44%,#fff1d4 100%)}
        body.theme-cat{background:
            radial-gradient(circle at top left,rgba(255,186,214,.45),transparent 28%),
            radial-gradient(circle at top right,rgba(255,211,170,.32),transparent 24%),
            linear-gradient(180deg,#fffdfd 0%,#fff4f8 44%,#fff0f2 100%)}
        body::before,body::after{content:"";position:fixed;inset:auto;pointer-events:none;border-radius:999px;filter:blur(10px);opacity:.65}
        body::before{width:280px;height:280px;top:72px;left:-90px;background:rgba(164,228,255,.5)}
        body::after{width:320px;height:320px;right:-110px;bottom:40px;background:rgba(255,230,179,.55)}
        body.theme-dark::before{background:rgba(75,143,188,.22)}
        body.theme-dark::after{background:rgba(209,174,84,.18)}
        body.theme-happy::before{background:rgba(255,190,120,.34)}
        body.theme-happy::after{background:rgba(255,145,166,.26)}
        body.theme-cat::before{background:rgba(255,176,206,.30)}
        body.theme-cat::after{background:rgba(255,208,164,.24)}
        .wrap{width:min(1180px,100%);margin:0 auto;padding:32px 18px 42px;position:relative;z-index:1}
        .page-shell{width:min(100%,1080px);margin:0 auto}
        .page-shell.narrow{width:min(100%,720px)}
        .viewport-center{min-height:calc(100vh - 74px);display:flex;align-items:center;justify-content:center}
        .top{display:flex;justify-content:space-between;align-items:center;gap:16px;flex-wrap:wrap;margin-bottom:18px}
        .card{background:var(--surface);backdrop-filter:blur(22px);-webkit-backdrop-filter:blur(22px);border:1px solid var(--border);border-radius:28px;padding:24px;margin:18px 0;box-shadow:var(--shadow)}
        .hero{padding:30px}
        .center-card{text-align:center}
        .section-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:20px;align-items:start}
        .span-2{grid-column:1 / -1}
        .grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:16px}
        .grid3{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:14px}
        .grid4{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:14px}
        .btn-row{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:14px;margin-top:14px}
        @media(max-width:920px){.section-grid,.grid,.grid3,.grid4,.btn-row{grid-template-columns:1fr}.wrap{padding:22px 14px 34px}.card{padding:20px;border-radius:24px}.hero{padding:24px}.viewport-center{min-height:calc(100vh - 56px)}}
        h1,h2,h3{margin:0 0 14px;color:var(--heading);line-height:1.15}
        h1{font-size:clamp(2rem,4vw,3.2rem)}
        h2{font-size:clamp(1.55rem,3vw,2.2rem)}
        h3{font-size:1.12rem}
        p{margin:0 0 14px;line-height:1.6}
        label{display:block;font-weight:700;margin:4px 0 7px;color:var(--heading)}
        input,textarea,select{width:100%;background:var(--field-bg);border:1px solid rgba(163,184,204,.62);color:var(--field-text);border-radius:16px;padding:13px 14px;outline:none;transition:border-color .2s ease,box-shadow .2s ease,background .2s ease,color .2s ease}
        input:focus,textarea:focus,select:focus{border-color:rgba(60,166,216,.9);box-shadow:0 0 0 4px rgba(60,166,216,.14);background:var(--field-bg-focus)}
        input::placeholder,textarea::placeholder{color:var(--field-placeholder);opacity:1}
        textarea{min-height:140px;resize:vertical}
        button,.btn{display:inline-flex;align-items:center;justify-content:center;width:100%;min-height:50px;text-align:center;background:linear-gradient(135deg,var(--accent),var(--accent-deep));color:#fff;border:0;border-radius:16px;padding:12px 16px;font-weight:700;text-decoration:none;cursor:pointer;box-shadow:0 14px 28px rgba(60,166,216,.18)}
        .btn-secondary{background:linear-gradient(135deg,#8bb6ca,#628ea8)}
        .btn-danger{background:linear-gradient(135deg,#ef8f9b,#d95d74)}
        .btn-success{background:linear-gradient(135deg,#5bcaa0,#2b9f7c)}
        .btn-logout{width:auto;min-height:auto;padding:12px 18px;background:rgba(255,255,255,.5);border:1px solid rgba(217,93,116,.34);color:#b33d56;box-shadow:none}
        .badge{display:inline-flex;align-items:center;gap:8px;padding:8px 14px;border-radius:999px;font-weight:700}
        .ok{background:var(--ok);color:var(--oktxt)}
        .bad{background:var(--bad);color:var(--badtxt)}
        .warn{background:var(--warn);color:var(--warntxt)}
        table{width:100%;border-collapse:collapse}
        th,td{padding:14px 0;border-bottom:1px solid rgba(148,163,184,.2);vertical-align:top;text-align:left}
        th{width:35%;color:var(--heading)}
        code,.code{display:block;word-break:break-word;background:rgba(255,255,255,.74);border:1px solid rgba(148,163,184,.3);padding:14px 16px;border-radius:18px;color:#23506b}
        .alert{padding:13px 15px;border-radius:16px;margin:14px 0}
        .alert-ok{background:rgba(223,247,232,.95);border:1px solid rgba(78,176,127,.35);color:#1f6b45}
        .alert-bad{background:rgba(255,228,230,.96);border:1px solid rgba(217,93,116,.35);color:#9a334b}
        .muted{color:var(--muted)}
        .small{font-size:.94rem}
        .intro{max-width:62ch;color:var(--muted)}
        .auth-form{width:min(100%,360px);margin:0 auto}
        .auth-field{width:100%}
        .auth-row{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px;align-items:end}
        .auth-row > div{min-width:0}
        .pin-input{width:100%;font-size:2rem;text-align:center;letter-spacing:10px;-webkit-text-security:disc}
        .pin-button{width:100%}
        .captcha-box{display:flex;justify-content:center;margin:0 0 12px}
        .captcha-box img{display:block;width:100%;height:52px;object-fit:cover;border-radius:16px;border:1px solid rgba(148,163,184,.28);background:rgba(255,255,255,.72)}
        .captcha-compact{display:grid;grid-template-columns:minmax(0,1fr) auto minmax(0,1fr);gap:12px;align-items:end}
        .captcha-compact .captcha-box{margin:0}
        .captcha-compact input{height:52px}
        .captcha-refresh{width:52px;min-width:52px;min-height:52px;padding:0;border:0;background:transparent;box-shadow:none;color:var(--heading);font-size:2rem;line-height:1;display:flex;align-items:center;justify-content:center}
        .captcha-refresh:hover,.captcha-refresh:focus{background:transparent;box-shadow:none;color:var(--accent-deep)}
        .form-submit-gap{margin-top:24px}
        .logs-toolbar{display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap;margin-bottom:14px}
        .logs-toolbar .filter-wrap{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
        .logs-toolbar select{width:auto;min-width:180px}
        .logs-toolbar .search-input{width:min(260px,100%)}
        .status-meta{display:flex;justify-content:center;gap:12px;flex-wrap:wrap;margin-bottom:14px}
        .stack > * + *{margin-top:16px}
        .danger-card{border-color:rgba(217,93,116,.32)}
        .tabs{display:flex;flex-wrap:wrap;gap:10px;margin:0 0 20px}
        .tab-button{width:auto;min-height:auto;padding:11px 16px;border-radius:999px;background:rgba(255,255,255,.72);color:var(--heading);border:1px solid rgba(148,163,184,.28);box-shadow:none}
        .tab-button.active{background:linear-gradient(135deg,var(--accent),var(--accent-deep));color:#fff;border-color:transparent;box-shadow:0 14px 28px rgba(60,166,216,.18)}
        .tab-panel{display:none}
        .tab-panel.active{display:block}
        .stats-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:20px}
        .stat-card{padding:18px 20px;border-radius:22px;background:rgba(255,255,255,.6);border:1px solid rgba(148,163,184,.22)}
        .stat-label{display:block;font-size:.88rem;color:var(--muted);margin-bottom:8px}
        .stat-value{font-size:clamp(1.25rem,2.4vw,2rem);font-weight:700;color:var(--heading);line-height:1.2}
        .clock-value{font-variant-numeric:tabular-nums}
        @media(max-width:920px){.stats-grid{grid-template-columns:1fr}}
        @media(max-width:520px){.auth-row{grid-template-columns:1fr}.captcha-box img{height:auto}}
        pre{font:inherit}
    </style>';
    echo '</head><body class="theme-' . h($theme) . '"><div class="wrap">';
}

function render_footer(): void
{
    echo '<script>
    document.querySelectorAll("[data-logs-refresh]").forEach(function(button){
        button.addEventListener("click", function(){
            var targetId = button.getAttribute("data-logs-refresh");
            var target = targetId ? document.getElementById(targetId) : null;
            var filterId = button.getAttribute("data-logs-filter");
            var filter = filterId ? document.getElementById(filterId) : null;
            var queryId = button.getAttribute("data-logs-query");
            var query = queryId ? document.getElementById(queryId) : null;
            var filterValue = filter ? encodeURIComponent(filter.value || "all") : "all";
            var queryValue = query ? encodeURIComponent(query.value || "") : "";
            if (!target) return;
            var original = button.textContent;
            button.disabled = true;
            button.textContent = "…";
            fetch(location.pathname + "?logs_fragment=1&filter=" + filterValue + "&query=" + queryValue + "&t=" + Date.now(), { credentials: "same-origin" })
                .then(function(response){
                    if (!response.ok) throw new Error("HTTP " + response.status);
                    return response.text();
                })
                .then(function(text){
                    target.textContent = text;
                })
                .catch(function(){
                    target.textContent = "Logs konnten nicht neu geladen werden.";
                })
                .finally(function(){
                    button.disabled = false;
                    button.textContent = original;
                });
        });
    });
    document.querySelectorAll("[data-logs-filter-select]").forEach(function(select){
        select.addEventListener("change", function(){
            var buttonId = select.getAttribute("data-logs-refresh-button");
            var button = buttonId ? document.getElementById(buttonId) : null;
            if (button) button.click();
        });
    });
    document.querySelectorAll("[data-logs-query-input]").forEach(function(input){
        var timer = null;
        input.addEventListener("input", function(){
            var buttonId = input.getAttribute("data-logs-refresh-button");
            var button = buttonId ? document.getElementById(buttonId) : null;
            if (!button) return;
            if (timer) clearTimeout(timer);
            timer = setTimeout(function(){ button.click(); }, 250);
        });
    });
    document.querySelectorAll("[data-tabs]").forEach(function(group){
        var storageKey = "activeTab:" + location.pathname + ":" + (group.getAttribute("data-tabs") || "default");
        var buttons = group.querySelectorAll("[data-tab-target]");
        var panels = group.querySelectorAll("[data-tab-panel]");
        function activate(id){
            if (!id) return;
            buttons.forEach(function(button){
                var active = button.getAttribute("data-tab-target") === id;
                button.classList.toggle("active", active);
                button.setAttribute("aria-selected", active ? "true" : "false");
            });
            panels.forEach(function(panel){
                panel.classList.toggle("active", panel.getAttribute("data-tab-panel") === id);
            });
            try { sessionStorage.setItem(storageKey, id); } catch (e) {}
        }
        buttons.forEach(function(button){
            button.addEventListener("click", function(){
                activate(button.getAttribute("data-tab-target"));
            });
        });
        var initial = null;
        try { initial = sessionStorage.getItem(storageKey); } catch (e) {}
        var hasStoredPanel = initial && group.querySelector("[data-tab-panel=\'" + initial + "\']");
        if (buttons.length) {
            activate(hasStoredPanel ? initial : buttons[0].getAttribute("data-tab-target"));
        }
    });
    var clock = document.getElementById("dashboard-clock");
    if (clock) {
        var updateClock = function(){
            var now = new Date();
            var datePart = now.toLocaleDateString("de-AT", {
                day: "2-digit",
                month: "2-digit",
                year: "numeric"
            });
            var timePart = now.toLocaleTimeString("de-AT", {
                hour: "2-digit",
                minute: "2-digit",
                second: "2-digit"
            });
            clock.textContent = datePart + " " + timePart;
        };
        updateClock();
        setInterval(updateClock, 1000);
    }
    </script></div></body></html>';
}

// -------------------- Routing: logout / cron / checkin --------------------
if (isset($_GET['logout'])) {
    invalidate_admin_session();
    header('Location: ' . safe_self_path() . '?logged_out=1');
    exit;
}

$config = read_config();
$isCli = PHP_SAPI === 'cli';

if (!$isCli && isset($_GET['captcha'])) {
    $context = (string)$_GET['captcha'];
    if (!in_array($context, ['admin_login', 'checkin'], true)) {
        http_response_code(404);
        exit;
    }
    refresh_captcha($context);
    $entry = $_SESSION[captcha_session_key($context)] ?? null;
    if (!is_array($entry) || empty($entry['code'])) {
        http_response_code(404);
        exit;
    }
    apply_security_headers(true);
    header('Content-Type: image/svg+xml; charset=UTF-8');
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    echo render_captcha_svg((string)$entry['code']);
    exit;
}

if (!$isCli && isset($_GET['logs_fragment'])) {
    if (!is_admin_authenticated()) {
        http_response_code(403);
        exit;
    }
    header('Content-Type: text/plain; charset=UTF-8');
    echo read_events_log(300, normalize_log_filter((string)($_GET['filter'] ?? 'all')), normalize_log_query((string)($_GET['query'] ?? '')));
    exit;
}

if ($isCli && isset($argv[1]) && $argv[1] === 'cron') {
    if (!$config) {
        echo "Setup incomplete.\n";
        exit;
    }
    echo process_cron($config, true) . "\n";
    exit;
}

if (!$isCli && isset($_GET['cron_token'])) {
    header('Content-Type: text/plain; charset=UTF-8');
    if (!$config) {
        http_response_code(503);
        echo "Setup incomplete.\n";
        exit;
    }
    if (!hash_equals((string)($config['cron_token'] ?? ''), (string)$_GET['cron_token'])) {
        http_response_code(403);
        echo "Invalid cron token.\n";
        exit;
    }
    echo process_cron($config, true) . "\n";
    exit;
}

if (!$isCli && isset($_GET['checkin'])) {
    header('Location: ' . checkin_path(), true, 302);
    exit;
}

if (!$isCli && route_suffix() === '/checkin') {
    if (!$config) {
        http_response_code(503);
        die('Setup unvollständig.');
    }

    $error = '';
    $success = false;
    $ip = client_ip();
    $isAdminLoginPost = $_SERVER['REQUEST_METHOD'] === 'POST' && (string)($_POST['form_name'] ?? '') === 'admin_login';
    $authRequired = !is_checkin_authenticated() || is_pin_locked() || !checkin_allowed($ip);

    if ($authRequired && !$isAdminLoginPost && ($_SESSION['checkin_reauth_required'] ?? false) !== true) {
        force_checkin_reauthentication();
        $_SESSION['checkin_reauth_required'] = true;
        $authRequired = true;
    }

    $loginResult = handle_admin_login_attempt($config, $ip);
    if ($loginResult['success'] === true) {
        mark_checkin_authenticated();
        header('Location: ' . checkin_path());
        exit;
    }
    if ($loginResult['error'] !== '') {
        $error = $loginResult['error'];
    }

    if ($_SERVER['REQUEST_METHOD'] === 'POST' && (string)($_POST['form_name'] ?? '') === 'pin_checkin') {
        require_csrf();
        $pin = trim((string)($_POST['pin'] ?? ''));
        $captcha = (string)($_POST['captcha_response'] ?? '');

        if (!is_checkin_authenticated() || is_pin_locked() || !checkin_allowed($ip)) {
            force_checkin_reauthentication();
            $_SESSION['checkin_reauth_required'] = true;
            $error = 'Zusätzliche Authentifizierung erforderlich.';
            log_event('Check-in failure');
        } elseif (!verify_captcha('checkin', $captcha)) {
            record_checkin_failure($ip, $config);
            $pinState = record_pin_failure($config);
            $attempt = max(1, (int)($pinState['failures'] ?? 1));
            apply_failure_delay_for_attempt($attempt);
            if ((int)($pinState['failures'] ?? 0) >= rate_limit_max_failures($config) || !checkin_allowed($ip)) {
                force_checkin_reauthentication();
                $_SESSION['checkin_reauth_required'] = true;
                $error = 'PIN-Eingabe gesperrt. Bitte erneut mit dem Admin-Passwort authentifizieren.';
            } else {
                $error = delay_message($attempt);
            }
            log_event('Check-in failure');
        } elseif (!preg_match('/^\d{4}$/', $pin)) {
            record_checkin_failure($ip, $config);
            $pinState = record_pin_failure($config);
            $attempt = max(1, (int)($pinState['failures'] ?? 1));
            apply_failure_delay_for_attempt($attempt);
            if ((int)($pinState['failures'] ?? 0) >= rate_limit_max_failures($config) || !checkin_allowed($ip)) {
                force_checkin_reauthentication();
                $_SESSION['checkin_reauth_required'] = true;
                $error = 'PIN-Eingabe gesperrt. Bitte erneut mit dem Admin-Passwort authentifizieren.';
            } else {
                $error = delay_message($attempt);
            }
            log_event('Check-in failure');
        } elseif (password_verify($pin, (string)$config['pin_hash'])) {
            reset_pin_state();
            clear_checkin_failures($ip);
            unset($_SESSION['checkin_reauth_required']);
            complete_manual_checkin($config);
            log_event('Check-in success');
            $success = true;
        } else {
            record_checkin_failure($ip, $config);
            $pinState = record_pin_failure($config);
            $attempt = max(1, (int)($pinState['failures'] ?? 1));
            apply_failure_delay_for_attempt($attempt);
            log_event('Check-in failure');
            if ((int)$pinState['failures'] >= rate_limit_max_failures($config) || !checkin_allowed($ip)) {
                force_checkin_reauthentication();
                $_SESSION['checkin_reauth_required'] = true;
                $error = 'PIN-Eingabe gesperrt. Bitte erneut mit dem Admin-Passwort authentifizieren.';
            } else {
                $error = delay_message($attempt);
            }
        }
    }

    $authRequired = !is_checkin_authenticated() || is_pin_locked();
    if (!checkin_allowed($ip)) {
        $authRequired = true;
    }

    render_header("Check-in", normalize_theme((string)($config['theme'] ?? 'light')));
    echo '<div class="page-shell narrow viewport-center"><div class="card hero center-card" style="width:min(100%,560px)">';
    if ($success) {
        echo '<div style="font-size: 4rem; margin-bottom: 10px;">' . theme_mascot((string)($config['theme'] ?? 'light'), 'html') . '</div>';
        echo '<h2>Check-in erfolgreich</h2>';
        echo '<p>N&auml;chste F&auml;lligkeit: <strong><span style="white-space:nowrap;">' . h(date('d.m.Y H:i', (int)$config['next_due_at'])) . '</span></strong></p>';
        echo '<script>setTimeout(function(){ try { window.close(); } catch (e) {} setTimeout(function(){ try { window.open("", "_self"); window.close(); } catch (e) {} setTimeout(function(){ try { location.replace("about:blank"); } catch (e) {} }, 300); }, 300); }, 2500);</script>';
    } else {
        echo '<h2>' . theme_mascot((string)($config['theme'] ?? 'light'), 'html') . '</h2>';
        if ($error !== '') {
            echo '<div class="alert alert-bad">' . h($error) . '</div>';
        }
        if ($authRequired) {
            echo '<form method="post" class="auth-form" autocomplete="on">';
            echo '<input type="hidden" name="csrf_token" value="' . h(csrf_token()) . '">';
            echo '<input type="hidden" name="form_name" value="admin_login">';
            echo '<div class="auth-field"><input type="password" name="password" autocomplete="current-password" required></div>';
            echo '<div style="margin-top:16px">' . render_captcha_html('admin_login', 'Captcha', false, 'captcha-compact') . '</div>';
            echo '<div style="margin-top:16px"><button type="submit">Admin-Login</button></div>';
            echo '</form>';
        } else {
            echo '<form method="POST" class="stack auth-form" autocomplete="off" data-bwignore="true">';
            echo '<input type="hidden" name="csrf_token" value="' . h(csrf_token()) . '">';
            echo '<input type="hidden" name="form_name" value="pin_checkin">';
            echo '<div class="auth-field"><input class="pin-input" type="tel" name="pin" inputmode="numeric" pattern="[0-9]{4}" maxlength="4" placeholder="****" autocomplete="off" data-bwignore="true" enterkeyhint="done" required oninput="this.value=this.value.replace(/\\D/g, \'\').slice(0,4)"></div>';
            echo render_captcha_html('checkin', 'Captcha', false, 'captcha-compact');
            echo '<button class="pin-button" type="submit">Best&auml;tigen</button>';
            echo '</form>';
        }
    }
    echo '</div></div>';
    render_footer();
    exit;
}

// -------------------- Setup --------------------
if (!$config) {
    $msg = '';
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        require_csrf();
        $password = (string)($_POST['password'] ?? '');
        $pin = trim((string)($_POST['pin'] ?? ''));
        $days = max(0, (int)($_POST['days'] ?? 0));
        $hours = max(0, (int)($_POST['hours'] ?? 0));
        $minutes = max(0, (int)($_POST['minutes'] ?? 0));
        $interval = $days * 86400 + $hours * 3600 + $minutes * 60;
        $recipientsCsv = trim((string)($_POST['recipients_csv'] ?? ''));
        $reminderEmail = trim((string)($_POST['reminder_email'] ?? ''));
        $dmsSubject = trim((string)($_POST['dms_subject'] ?? default_dms_subject()));
        $dmsMessage = trim((string)($_POST['dms_message'] ?? default_dms_message()));
        $welcomeSubject = trim((string)($_POST['welcome_subject'] ?? default_welcome_subject()));
        $welcomeBody = trim((string)($_POST['welcome_body'] ?? default_welcome_body()));
        $smtpMode = trim((string)($_POST['smtp_mode'] ?? 'smtp'));
        $smtpHost = trim((string)($_POST['smtp_host'] ?? ''));
        $smtpPort = (int)($_POST['smtp_port'] ?? 587);
        $smtpUser = trim((string)($_POST['smtp_user'] ?? ''));
        $smtpPass = (string)($_POST['smtp_pass'] ?? '');
        $smtpFrom = trim((string)($_POST['smtp_from'] ?? $smtpUser));
        $smtpSecure = trim((string)($_POST['smtp_secure'] ?? 'tls'));

        $errors = [];
        $passwordError = validate_admin_password($password);
        if ($passwordError !== null) $errors[] = $passwordError;
        if (!preg_match('/^\d{4}$/', $pin)) $errors[] = 'PIN muss genau 4 Ziffern haben.';
        if ($interval < 60) $errors[] = 'Intervall mindestens 1 Minute.';
        if (empty(parse_emails($recipientsCsv))) $errors[] = 'Mindestens eine gültige Empfängeradresse erforderlich.';
        if ($reminderEmail === '' || !filter_var($reminderEmail, FILTER_VALIDATE_EMAIL)) $errors[] = 'Gültige Erinnerungs-Mailadresse erforderlich.';
        if ($dmsSubject === '' || $dmsMessage === '') $errors[] = 'DMS-Betreff und Nachricht sind erforderlich.';
        if ($welcomeSubject === '' || $welcomeBody === '') $errors[] = 'Willkommens-Betreff und -Text sind erforderlich.';
        $errors = array_merge($errors, validate_smtp_settings($smtpMode, $smtpHost, $smtpPort, $smtpUser, $smtpPass, $smtpFrom, $smtpSecure));

        if (!$errors) {
            try {
                $payload = [
                    'recipients_csv' => $recipientsCsv,
                    'reminder_email' => $reminderEmail,
                    'dms_subject' => $dmsSubject,
                    'dms_message' => $dmsMessage,
                    'welcome_subject' => $welcomeSubject,
                    'welcome_body' => $welcomeBody,
                    'smtp' => [
                        'mode' => $smtpMode,
                        'host' => $smtpHost,
                        'port' => $smtpPort,
                        'user' => $smtpUser,
                        'pass' => $smtpPass,
                        'from' => $smtpFrom,
                        'secure' => $smtpSecure,
                    ],
                ];
                $cfg = [
                    'password_hash' => password_hash($password, PASSWORD_DEFAULT),
                    'pin_hash' => password_hash($pin, PASSWORD_DEFAULT),
                    'app_url' => base_url(),
                    'rate_limit_minutes' => 15,
                    'rate_limit_max_failures' => PIN_MAX_FAILURES,
                    'installed_at' => time(),
                    'interval_seconds' => $interval,
                    'last_checkin_at' => time(),
                    'next_due_at' => time() + $interval,
                    'cron_token' => bin2hex(random_bytes(20)),
                    'triggered' => false,
                    'triggered_at' => null,
                    'reminder_sent_this_cycle' => false,
                    'last_reminder_sent_at' => null,
                    'last_dispatch_result' => ['ok' => [], 'fail' => []],
                    'encrypted_payload' => encrypt_payload($payload),
                ];
                write_config($cfg);
                reset_pin_state();
                clearstatcache(true, CONFIG_FILE);
                if (!file_exists(CONFIG_FILE)) {
                    throw new RuntimeException('Konfigurationsdatei wurde nach dem Schreiben nicht gefunden: ' . CONFIG_FILE);
                }
                $welcomeResult = send_welcome_mails($cfg, $payload);
                log_event('System installed. Welcome mails ok=' . count($welcomeResult['ok']) . ' fail=' . count($welcomeResult['fail']));
                $_SESSION['setup_notice'] = 'Setup abgeschlossen. Willkommensmails erfolgreich: ' . count($welcomeResult['ok']) . ', fehlgeschlagen: ' . count($welcomeResult['fail']);
                header('Location: ' . safe_self_path());
                exit;
            } catch (Throwable $e) {
                add_diag($e->getMessage());
                $errors[] = 'Setup konnte nicht gespeichert werden.';
            }
        }
        $msg = '<div class="alert alert-bad">' . implode('<br>', array_map('h', $errors)) . '</div>';
    }

    render_header('Ersteinrichtung', 'light');
    echo '<div class="page-shell">';
    echo '<div class="card hero">';
    echo '<h1>Dead Man\'s Switch - Ersteinrichtung</h1>';
    echo '<p class="intro">Das System wird in einem hellen, klar strukturierten Setup eingerichtet. Alle Eingaben bleiben funktional unverändert, damit die Auslieferung und Check-ins danach wie gewohnt laufen.</p>';
    echo $msg;
    if ($msg !== '' || !empty(get_diags())) echo diagnostics_html();
    echo '<form method="post" autocomplete="off" data-bwignore="true">';
    echo '<input type="hidden" name="csrf_token" value="' . h(csrf_token()) . '">';
    echo '<h3>1. Sicherheit</h3><div class="grid">';
    echo '<div><label>Admin-Passwort</label><input type="password" name="password" autocomplete="new-password" data-bwignore="true" required></div>';
    echo '<div><label>Check-in PIN (4-stellig)</label><input type="text" name="pin" pattern="\d{4}" maxlength="4" inputmode="numeric" autocomplete="off" data-bwignore="true" required></div>';
    echo '</div>';
    echo '<p class="small muted">Das Admin-Passwort muss mindestens 12 Zeichen sowie Gross-/Kleinbuchstaben, Zahl und Sonderzeichen enthalten.</p>';

    echo '<h3>2. Intervall</h3><div class="grid3">';
    echo '<div><label>Tage</label><input type="number" name="days" min="0" value="1" autocomplete="off" data-bwignore="true"></div>';
    echo '<div><label>Stunden</label><input type="number" name="hours" min="0" value="0" autocomplete="off" data-bwignore="true"></div>';
    echo '<div><label>Minuten</label><input type="number" name="minutes" min="0" value="0" autocomplete="off" data-bwignore="true"></div>';
    echo '</div><p class="small muted">Jeder Check-in startet dieses Intervall neu ab genau dem Klick-Zeitpunkt.</p>';

    echo '<h3>3. Adressen und Inhalte</h3>';
    echo '<label>Vertrauenspersonen / Empfänger (Komma oder Zeilenumbruch getrennt)</label><textarea name="recipients_csv" autocomplete="off" data-bwignore="true" required></textarea>';
    echo '<label>Erinnerungs-Mailadresse (bekommt bei ca. 20% Restzeit die Erinnerung)</label><input type="email" name="reminder_email" autocomplete="off" data-bwignore="true" required>';
    echo '<label>DMS-Betreff</label><input type="text" name="dms_subject" value="' . h(default_dms_subject()) . '" autocomplete="off" data-bwignore="true" required>';
    echo '<label>DMS-Nachricht</label><textarea name="dms_message" autocomplete="off" data-bwignore="true" required>' . h(default_dms_message()) . '</textarea>';
    echo '<label>Willkommensmail Betreff</label><input type="text" name="welcome_subject" value="' . h(default_welcome_subject()) . '" autocomplete="off" data-bwignore="true" required>';
    echo '<label>Willkommensmail Text</label><textarea name="welcome_body" autocomplete="off" data-bwignore="true" required>' . h(default_welcome_body()) . '</textarea>';
    echo '<p class="small muted">Platzhalter: {{installed_at}}, {{system_url}}, {{interval}}, {{reminder_email}}, {{recipient_email}}</p>';

    echo '<h3>4. Mailversand</h3><div class="grid">';
    echo '<div><label>Versandmodus</label><select name="smtp_mode" autocomplete="off" data-bwignore="true"><option value="smtp">SMTP</option><option value="mail">PHP mail()</option></select></div>';
    echo '<div><label>Sicherheit</label><select name="smtp_secure" autocomplete="off" data-bwignore="true"><option value="tls">TLS / STARTTLS</option><option value="ssl">SSL</option></select></div>';
    echo '</div><div class="grid">';
    echo '<div><label>SMTP Host</label><input type="text" name="smtp_host" value="mail.gmx.net" autocomplete="off" data-bwignore="true"></div>';
    echo '<div><label>SMTP Port</label><input type="number" name="smtp_port" value="587" autocomplete="off" data-bwignore="true"></div>';
    echo '</div><div class="grid">';
    echo '<div><label>SMTP Benutzer</label><input type="email" name="smtp_user" autocomplete="off" data-bwignore="true"></div>';
    echo '<div><label>SMTP Passwort / App-Passwort</label><input type="password" name="smtp_pass" autocomplete="new-password" data-bwignore="true"></div>';
    echo '</div><label>Absenderadresse</label><input type="email" name="smtp_from" autocomplete="off" data-bwignore="true">';

    echo '<button type="submit">Setup abschließen</button>';
    echo '</form></div></div>';
    render_footer();
    exit;
}

// -------------------- Login --------------------
$ip = client_ip();
if (!is_admin_authenticated()) {
    $notice = $_SESSION['setup_notice'] ?? '';
    unset($_SESSION['setup_notice']);
    $error = '';

    $loginResult = handle_admin_login_attempt($config, $ip);
    if ($loginResult['success'] === true) {
        redirect_self();
    }
    if ($loginResult['error'] !== '') {
        $error = $loginResult['error'];
    }

    render_header('Login', normalize_theme((string)($config['theme'] ?? 'light')));
    echo '<div class="page-shell narrow viewport-center"><div class="card hero" style="width:min(100%,460px)">';
    echo '<center><h2>' . theme_mascot((string)($config['theme'] ?? 'light'), 'html') . '</h2></center>';
    if ($notice !== '') echo '<div class="alert alert-ok">' . h($notice) . '</div>';
    if ($error !== '') echo '<div class="alert alert-bad">' . h($error) . '</div>';
    if (isset($_GET['logged_out'])) {
        echo '<script>try { sessionStorage.removeItem("activeTab:" + location.pathname + ":dashboard-tabs"); } catch (e) {}</script>';
    }
    echo '<form method="post" class="auth-form" autocomplete="on">';
    echo '<input type="hidden" name="csrf_token" value="' . h(csrf_token()) . '">';
    echo '<input type="hidden" name="form_name" value="admin_login">';
    echo '<div class="auth-field"><input id="admin-login-password" type="password" name="password" autocomplete="current-password" required></div>';
    echo '<div style="margin-top:16px">' . render_captcha_html('admin_login', 'Captcha', false, 'captcha-compact') . '</div>';
    echo '<div style="margin-top:16px"><button type="submit">Einloggen</button></div>';
    echo '</form></div></div>';
    render_footer();
    exit;
}

// -------------------- Dashboard actions --------------------
$config = read_config();
$payload = decrypt_payload((string)$config['encrypted_payload']);
$flash = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action'])) {
    require_csrf();
    $action = (string)$_POST['action'];

    if ($action === 'manual_checkin') {
        complete_manual_checkin($config);
        $flash = '<div class="alert alert-ok">Intervall manuell neu gestartet.</div>';
    }

    if ($action === 'save_interval') {
        $days = max(0, (int)($_POST['days'] ?? 0));
        $hours = max(0, (int)($_POST['hours'] ?? 0));
        $minutes = max(0, (int)($_POST['minutes'] ?? 0));
        $interval = $days * 86400 + $hours * 3600 + $minutes * 60;
        if ($interval < 60) {
            $flash = '<div class="alert alert-bad">Intervall mindestens 1 Minute.</div>';
        } else {
            $config['interval_seconds'] = $interval;
            complete_manual_checkin($config);
            $flash = '<div class="alert alert-ok">Intervall gespeichert und neu gestartet.</div>';
        }
    }

    if ($action === 'save_theme') {
        $theme = normalize_theme((string)($_POST['theme'] ?? 'light'));
        $config['theme'] = $theme;
        write_config($config);
        $flash = '<div class="alert alert-ok">Theme gespeichert.</div>';
    }

    if ($action === 'save_rate_limit') {
        $maxFailures = max(1, min(50, (int)($_POST['rate_limit_max_failures'] ?? PIN_MAX_FAILURES)));
        $config['rate_limit_max_failures'] = $maxFailures;
        write_config($config);
        $flash = '<div class="alert alert-ok">Rate-Limiter-Einstellungen gespeichert.</div>';
    }

    if ($action === 'save_security') {
        $currentPassword = (string)($_POST['current_admin_password'] ?? '');
        $newAdminPassword = (string)($_POST['new_admin_password'] ?? '');
        $newAdminPasswordConfirm = (string)($_POST['new_admin_password_confirm'] ?? '');
        $newPin = trim((string)($_POST['new_pin'] ?? ''));
        $newPinConfirm = trim((string)($_POST['new_pin_confirm'] ?? ''));

        $errors = [];
        if ($currentPassword === '' || !password_verify($currentPassword, (string)$config['password_hash'])) {
            $errors[] = 'Aktuelles Admin-Passwort ist falsch.';
        }

        $changeAdminPassword = ($newAdminPassword !== '' || $newAdminPasswordConfirm !== '');
        $changePin = ($newPin !== '' || $newPinConfirm !== '');

        if (!$changeAdminPassword && !$changePin) {
            $errors[] = 'Bitte gib ein neues Admin-Passwort und/oder eine neue PIN ein.';
        }

        if ($changeAdminPassword) {
            $passwordError = validate_admin_password($newAdminPassword);
            if ($passwordError !== null) {
                $errors[] = str_replace('Admin-Passwort', 'Neues Admin-Passwort', $passwordError);
            }
            if (!hash_equals($newAdminPassword, $newAdminPasswordConfirm)) {
                $errors[] = 'Die Bestätigung des neuen Admin-Passworts stimmt nicht überein.';
            }
        }

        if ($changePin) {
            if (!preg_match('/^\d{4}$/', $newPin)) {
                $errors[] = 'Die neue PIN muss genau 4 Ziffern haben.';
            }
            if (!hash_equals($newPin, $newPinConfirm)) {
                $errors[] = 'Die Bestätigung der neuen PIN stimmt nicht überein.';
            }
        }

        if ($errors) {
            $flash = '<div class="alert alert-bad">' . implode('<br>', array_map('h', $errors)) . '</div>';
        } else {
            if ($changeAdminPassword) {
                $config['password_hash'] = password_hash($newAdminPassword, PASSWORD_DEFAULT);
            }
            if ($changePin) {
                $config['pin_hash'] = password_hash($newPin, PASSWORD_DEFAULT);
                reset_pin_state();
            }
            write_config($config);
            log_event('Security credentials updated via dashboard');
            $parts = [];
            if ($changeAdminPassword) $parts[] = 'Admin-Passwort';
            if ($changePin) $parts[] = 'PIN';
            $flash = '<div class="alert alert-ok">' . h(implode(' und ', $parts) . ' erfolgreich aktualisiert.') . '</div>';
        }
    }

    if ($action === 'save_payload') {
        $recipientsCsv = trim((string)($_POST['recipients_csv'] ?? ''));
        $reminderEmail = trim((string)($_POST['reminder_email'] ?? ''));
        $dmsSubject = trim((string)($_POST['dms_subject'] ?? ''));
        $dmsMessage = trim((string)($_POST['dms_message'] ?? ''));
        $welcomeSubject = trim((string)($_POST['welcome_subject'] ?? ''));
        $welcomeBody = trim((string)($_POST['welcome_body'] ?? ''));
        $smtpMode = trim((string)($_POST['smtp_mode'] ?? 'smtp'));
        $smtpHost = trim((string)($_POST['smtp_host'] ?? ''));
        $smtpPort = (int)($_POST['smtp_port'] ?? 587);
        $smtpUser = trim((string)($_POST['smtp_user'] ?? ''));
        $smtpPass = (string)($_POST['smtp_pass'] ?? '');
        $smtpFrom = trim((string)($_POST['smtp_from'] ?? ''));
        $smtpSecure = trim((string)($_POST['smtp_secure'] ?? 'tls'));

        $errors = [];
        if (empty(parse_emails($recipientsCsv))) $errors[] = 'Mindestens eine gültige Empfängeradresse erforderlich.';
        if ($reminderEmail === '' || !filter_var($reminderEmail, FILTER_VALIDATE_EMAIL)) $errors[] = 'Gültige Erinnerungs-Mailadresse erforderlich.';
        if ($dmsSubject === '' || $dmsMessage === '') $errors[] = 'DMS-Betreff und Text dürfen nicht leer sein.';
        if ($welcomeSubject === '' || $welcomeBody === '') $errors[] = 'Willkommens-Betreff und Text dürfen nicht leer sein.';
        $errors = array_merge($errors, validate_smtp_settings($smtpMode, $smtpHost, $smtpPort, $smtpUser, $smtpPass, $smtpFrom, $smtpSecure, !empty(($payload['smtp']['pass'] ?? ''))));

        if ($errors) {
            $flash = '<div class="alert alert-bad">' . implode('<br>', array_map('h', $errors)) . '</div>';
        } else {
            $payload['recipients_csv'] = $recipientsCsv;
            $payload['reminder_email'] = $reminderEmail;
            $payload['dms_subject'] = $dmsSubject;
            $payload['dms_message'] = $dmsMessage;
            $payload['welcome_subject'] = $welcomeSubject;
            $payload['welcome_body'] = $welcomeBody;
            $payload['smtp'] = [
                'mode' => $smtpMode,
                'host' => $smtpHost,
                'port' => $smtpPort,
                'user' => $smtpUser,
                'pass' => $smtpPass !== '' ? $smtpPass : (string)($payload['smtp']['pass'] ?? ''),
                'from' => $smtpFrom,
                'secure' => $smtpSecure,
            ];
            $config['encrypted_payload'] = encrypt_payload($payload);
            write_config($config);
            $flash = '<div class="alert alert-ok">Adressen, DMS-Nachricht, Willkommensmail und Mailversand gespeichert.</div>';
        }
    }

    if ($action === 'save_mail_settings') {
        $smtpMode = trim((string)($_POST['smtp_mode'] ?? 'smtp'));
        $smtpHost = trim((string)($_POST['smtp_host'] ?? ''));
        $smtpPort = (int)($_POST['smtp_port'] ?? 587);
        $smtpUser = trim((string)($_POST['smtp_user'] ?? ''));
        $smtpPass = (string)($_POST['smtp_pass'] ?? '');
        $smtpFrom = trim((string)($_POST['smtp_from'] ?? ''));
        $smtpSecure = trim((string)($_POST['smtp_secure'] ?? 'tls'));

        $errors = [];
        $errors = array_merge($errors, validate_smtp_settings($smtpMode, $smtpHost, $smtpPort, $smtpUser, $smtpPass, $smtpFrom, $smtpSecure, !empty(($payload['smtp']['pass'] ?? ''))));

        if ($errors) {
            $flash = '<div class="alert alert-bad">' . implode('<br>', array_map('h', $errors)) . '</div>';
        } else {
            $payload['smtp'] = [
                'mode' => $smtpMode,
                'host' => $smtpHost,
                'port' => $smtpPort,
                'user' => $smtpUser,
                'pass' => $smtpPass !== '' ? $smtpPass : (string)($payload['smtp']['pass'] ?? ''),
                'from' => $smtpFrom,
                'secure' => $smtpSecure,
            ];
            $config['encrypted_payload'] = encrypt_payload($payload);
            write_config($config);
            $flash = '<div class="alert alert-ok">Mailversand gespeichert.</div>';
        }
    }

    if ($action === 'send_test_dms') {
        $recipients = parse_emails((string)($payload['recipients_csv'] ?? ''));
        $subject = '[TEST] ' . (string)($payload['dms_subject'] ?? default_dms_subject());
        $body = "Dies ist ein Testversand.\n\n" . (string)($payload['dms_message'] ?? default_dms_message());
        $result = send_bulk($recipients, $subject, $body, $payload);
        $flash = '<div class="alert ' . (empty($result['fail']) ? 'alert-ok' : 'alert-bad') . '">'
            . 'Test-DMS: erfolgreich ' . count($result['ok']) . ', fehlgeschlagen ' . count($result['fail']) . '</div>';
    }

    if ($action === 'send_test_welcome') {
        $result = send_welcome_mails($config, $payload);
        $flash = '<div class="alert ' . (empty($result['fail']) ? 'alert-ok' : 'alert-bad') . '">'
            . 'Willkommensmail-Test: erfolgreich ' . count($result['ok']) . ', fehlgeschlagen ' . count($result['fail']) . '</div>';
    }

    if ($action === 'send_test_reminder') {
        $rem = trim((string)($payload['reminder_email'] ?? ''));
        if ($rem === '' || !filter_var($rem, FILTER_VALIDATE_EMAIL)) {
            $flash = '<div class="alert alert-bad">Keine gültige Erinnerungs-Mailadresse gespeichert.</div>';
        } else {
            $subject = '[TEST] Erinnerung: Dead Man\'s Switch Check-in';
            $body = "Dies ist eine Test-Erinnerung.\n\nCheck-in-Link: " . base_url($config) . "/checkin";
            $res = send_mail_any($rem, $subject, $body, $payload);
            $flash = '<div class="alert ' . ($res === true ? 'alert-ok' : 'alert-bad') . '">' . h($res === true ? 'Test-Erinnerung gesendet.' : 'Fehler: ' . $res) . '</div>';
        }
    }

    if ($action === 'run_cron_preview') {
        $text = process_cron($config, false);
        $flash = '<div class="alert alert-ok"><pre style="white-space:pre-wrap;margin:0">' . h($text) . '</pre></div>';
    }

    if ($action === 'clear_logs') {
        $currentPassword = (string)($_POST['current_admin_password'] ?? '');
        if ($currentPassword === '' || !password_verify($currentPassword, (string)$config['password_hash'])) {
            $flash = '<div class="alert alert-bad">Aktuelles Admin-Passwort ist falsch.</div>';
        } else {
            try {
                require_data_dir_ready();
                write_file_strict(LOG_FILE, '', 0);
                safe_chmod(LOG_FILE, 0600);
                log_event('Logs cleared via dashboard by admin');
                $flash = '<div class="alert alert-ok">Logs wurden gelöscht.</div>';
            } catch (Throwable $e) {
                $flash = '<div class="alert alert-bad">' . h('Logs konnten nicht gelöscht werden: ' . $e->getMessage()) . '</div>';
            }
        }
    }

    if ($action === 'reset_all') {
        safe_unlink(CONFIG_FILE);
        safe_unlink(KEY_FILE);
        safe_unlink(RATE_LIMIT_FILE);
        safe_unlink(PIN_STATE_FILE);
        invalidate_admin_session();
        header('Location: ' . safe_self_path());
        exit;
    }

    $config = read_config();
    $payload = decrypt_payload((string)$config['encrypted_payload']);
}

// -------------------- Dashboard render --------------------
$checkinUrl = base_url($config) . '/checkin';
$cronUrl = base_url($config) . '?cron_token=' . $config['cron_token'];
$now = time();
$remaining = (int)$config['next_due_at'] - $now;
$thresholdAt = (int)$config['next_due_at'] - (int)floor((int)$config['interval_seconds'] * 0.2);
$statusText = !empty($config['triggered']) ? 'JA - Mails versendet!' : 'NEIN - Alles okay';
$statusClass = !empty($config['triggered']) ? 'bad' : 'ok';

render_header('Dashboard', normalize_theme((string)($config['theme'] ?? 'light')));
echo '<div class="page-shell">';
echo '<div class="card hero">';
echo '<div class="top"><div><h1>' . theme_mascot((string)($config['theme'] ?? 'light'), 'html') . ' Deadman-Switch Dashboard</h1></div><a class="btn btn-logout" href="?logout=1">Logout</a></div>';
echo '<div class="top"><div><h3>Version 3.0 by Spaceinvader.at</h3></div></div>';
echo '</div>';
if ($flash !== '') echo $flash;

echo '<div data-tabs="dashboard-tabs">';
echo '<div class="tabs" role="tablist" aria-label="Dashboard Bereiche">';
echo '<button type="button" class="tab-button active" data-tab-target="tab-dashboard" aria-selected="true">Dashboard</button>';
echo '<button type="button" class="tab-button" data-tab-target="tab-intervals" aria-selected="false">Intervalle &amp; Links</button>';
echo '<button type="button" class="tab-button" data-tab-target="tab-messages" aria-selected="false">Nachrichten</button>';
echo '<button type="button" class="tab-button" data-tab-target="tab-mail" aria-selected="false">Mailversand</button>';
echo '<button type="button" class="tab-button" data-tab-target="tab-system" aria-selected="false">System</button>';
echo '<button type="button" class="tab-button" data-tab-target="tab-logs" aria-selected="false">Logs</button>';
echo '</div>';

echo '<div class="tab-panel active" data-tab-panel="tab-dashboard">';
echo '<div class="section-grid">';
echo '<div class="card"><h3>System Status</h3><table>';
echo '<tr><th>Letzter Check-in</th><td>' . h(date('d.m.Y H:i:s', (int)$config['last_checkin_at'])) . '</td></tr>';
echo '<tr><th>Nächste Fälligkeit</th><td><span class="badge ' . ($remaining > 0 ? 'ok' : 'bad') . '">' . h(date('d.m.Y H:i:s', (int)$config['next_due_at'])) . '</span></td></tr>';
echo '<tr><th>Intervall</th><td>' . h(format_interval((int)$config['interval_seconds'])) . '</td></tr>';
echo '<tr><th>Restzeit</th><td>' . h(format_remaining($remaining)) . '</td></tr>';
echo '<tr><th>Reminder ab ~20% Restzeit</th><td>' . h(date('d.m.Y H:i:s', $thresholdAt)) . ' ';
if (!empty($config['reminder_sent_this_cycle'])) {
    echo '<span class="badge warn">bereits gesendet</span>';
}
echo '</td></tr>';
echo '<tr><th>Alarm ausgelöst</th><td><span class="badge ' . $statusClass . '">' . h($statusText) . '</span>';
if (!empty($config['triggered_at'])) {
    echo ' am ' . h(date('d.m.Y H:i:s', (int)$config['triggered_at']));
}
$res = $config['last_dispatch_result'] ?? ['ok' => [], 'fail' => []];
if (!empty($config['triggered']) && (!empty($res['ok']) || !empty($res['fail']))) {
    echo '<div class="small muted" style="margin-top:8px">Erfolgreich: ' . count($res['ok']) . ' | Fehlgeschlagen: ' . count($res['fail']) . '</div>';
}
echo '</td></tr>';
echo '</table></div>';
echo '<div class="card"><h3>Aktuelle Zeit</h3><div class="stats-grid"><div class="stat-card"><span class="stat-label">Aktuelle lokale Zeit</span><div class="stat-value clock-value" id="dashboard-clock">' . h(date('d.m.Y H:i:s', $now)) . '</div></div></div></div>';
echo '</div>';
echo '</div>';

echo '<div class="tab-panel" data-tab-panel="tab-intervals">';
echo '<div class="section-grid">';
echo '<div class="card"><h3>&#128241; Dein Check-in Link</h3>';
echo '<p class="small">Speichere diesen Link auf deinem Smartphone. Beim Öffnen wird deine 4-stellige PIN abgefragt. Jeder Klick startet das Intervall neu ab genau diesem Moment.</p>';
echo '<div class="code">' . h($checkinUrl) . '</div>';
echo '<div class="btn-row">';
echo '<div><a class="btn btn-secondary" href="' . h($checkinUrl) . '" target="_blank">Gehe zum Link (Test)</a></div>';
echo '</div></div>';

echo '<div class="card"><h3>&#129302; Cronjob</h3>';
echo '<p class="small">Richte diesen Link in einem Web-Cron-Dienst ein, ideal jede Minute oder alle 5 Minuten.</p>';
echo '<div class="code">' . h($cronUrl) . '</div>';
echo '<div class="btn-row">';
echo '<div><form method="post"><input type="hidden" name="csrf_token" value="' . h(csrf_token()) . '"><input type="hidden" name="action" value="run_cron_preview"><button class="btn btn-secondary" type="submit">Cron-Status-Vorschau</button></form></div>';
echo '<div><form method="post"><input type="hidden" name="csrf_token" value="' . h(csrf_token()) . '"><input type="hidden" name="action" value="manual_checkin"><button class="btn btn-success" type="submit">Intervall jetzt neu starten</button></form></div>';
echo '</div></div>';
echo '<div class="card span-2"><h3>⏱ Intervall ändern</h3>';
$ival = (int)$config['interval_seconds'];
$days = intdiv($ival, 86400); $rem = $ival % 86400; $hours = intdiv($rem, 3600); $minutes = intdiv($rem % 3600, 60);
echo '<form method="post" autocomplete="off" data-bwignore="true"><input type="hidden" name="csrf_token" value="' . h(csrf_token()) . '"><input type="hidden" name="action" value="save_interval">';
echo '<div class="grid3"><div><label>Tage</label><input type="number" name="days" min="0" value="' . h((string)$days) . '" autocomplete="off" data-bwignore="true"></div><div><label>Stunden</label><input type="number" name="hours" min="0" value="' . h((string)$hours) . '" autocomplete="off" data-bwignore="true"></div><div><label>Minuten</label><input type="number" name="minutes" min="0" value="' . h((string)$minutes) . '" autocomplete="off" data-bwignore="true"></div></div>';
echo '<p class="small muted">Beim Speichern startet das neue Intervall sofort neu.</p>';
echo '<button type="submit">Intervall speichern</button></form></div>';
echo '</div>';
echo '</div>';

echo '<div class="tab-panel" data-tab-panel="tab-messages">';
echo '<div class="card"><h3>✏️ DMS / Adressen / Willkommensmail bearbeiten</h3>';
echo '<form method="post" autocomplete="off" data-bwignore="true">';
echo '<input type="hidden" name="csrf_token" value="' . h(csrf_token()) . '"><input type="hidden" name="action" value="save_payload">';
echo '<label>Empfänger (Vertrauenspersonen)</label><textarea name="recipients_csv" autocomplete="off" data-bwignore="true" required>' . h((string)($payload['recipients_csv'] ?? '')) . '</textarea>';
echo '<label>Erinnerungs-Mailadresse</label><input type="email" name="reminder_email" value="' . h((string)($payload['reminder_email'] ?? '')) . '" autocomplete="off" data-bwignore="true" required>';
echo '<div class="grid"><div><label>DMS-Betreff</label><input type="text" name="dms_subject" value="' . h((string)($payload['dms_subject'] ?? default_dms_subject())) . '" autocomplete="off" data-bwignore="true" required></div>';
echo '<div><label>Willkommens-Betreff</label><input type="text" name="welcome_subject" value="' . h((string)($payload['welcome_subject'] ?? default_welcome_subject())) . '" autocomplete="off" data-bwignore="true" required></div></div>';
echo '<label>DMS-Nachricht</label><textarea name="dms_message" autocomplete="off" data-bwignore="true" required>' . h((string)($payload['dms_message'] ?? default_dms_message())) . '</textarea>';
echo '<label>Willkommensmail Text</label><textarea name="welcome_body" autocomplete="off" data-bwignore="true" required>' . h((string)($payload['welcome_body'] ?? default_welcome_body())) . '</textarea>';
echo '<p class="small muted">Platzhalter: {{installed_at}}, {{system_url}}, {{interval}}, {{reminder_email}}, {{recipient_email}}</p>';
echo '<button type="submit">Nachrichten speichern</button></form></div>';
echo '</div>';

echo '<div class="tab-panel" data-tab-panel="tab-mail">';
echo '<div class="card"><h3>Mailversand</h3>';
echo '<form method="post" autocomplete="off" data-bwignore="true">';
echo '<input type="hidden" name="csrf_token" value="' . h(csrf_token()) . '"><input type="hidden" name="action" value="save_mail_settings">';
echo '<div class="grid"><div><label>Versandmodus</label><select name="smtp_mode" autocomplete="off" data-bwignore="true"><option value="smtp"' . (((string)($payload['smtp']['mode'] ?? 'smtp')) === 'smtp' ? ' selected' : '') . '>SMTP</option><option value="mail"' . (((string)($payload['smtp']['mode'] ?? 'smtp')) === 'mail' ? ' selected' : '') . '>PHP mail()</option></select></div>';
echo '<div><label>Sicherheit</label><select name="smtp_secure" autocomplete="off" data-bwignore="true"><option value="tls"' . (((string)($payload['smtp']['secure'] ?? 'tls')) === 'tls' ? ' selected' : '') . '>TLS / STARTTLS</option><option value="ssl"' . (((string)($payload['smtp']['secure'] ?? 'tls')) === 'ssl' ? ' selected' : '') . '>SSL</option></select></div></div>';
echo '<div class="grid"><div><label>SMTP Host</label><input type="text" name="smtp_host" value="' . h((string)($payload['smtp']['host'] ?? '')) . '" autocomplete="off" data-bwignore="true"></div><div><label>SMTP Port</label><input type="number" name="smtp_port" value="' . h((string)($payload['smtp']['port'] ?? '587')) . '" autocomplete="off" data-bwignore="true"></div></div>';
echo '<div class="grid"><div><label>SMTP Benutzer</label><input type="email" name="smtp_user" value="' . h((string)($payload['smtp']['user'] ?? '')) . '" autocomplete="off" data-bwignore="true"></div><div><label>SMTP Passwort</label><input type="password" name="smtp_pass" placeholder="leer lassen = unverändert" autocomplete="new-password" data-bwignore="true"></div></div>';
echo '<label>Absenderadresse</label><input type="email" name="smtp_from" value="' . h((string)($payload['smtp']['from'] ?? '')) . '" autocomplete="off" data-bwignore="true">';
echo '<div class="form-submit-gap"><button type="submit">Änderungen speichern</button></div></form>';
echo '<div class="grid3" style="margin-top:16px">';
foreach ([['send_test_dms','Test-DMS senden','btn-success'],['send_test_welcome','Test-Willkommensmail senden','btn-secondary'],['send_test_reminder','Test-Erinnerung senden','btn-secondary']] as $btn) {
    echo '<form method="post"><input type="hidden" name="csrf_token" value="' . h(csrf_token()) . '"><input type="hidden" name="action" value="' . h($btn[0]) . '"><button type="submit" class="btn ' . h($btn[2]) . '">' . h($btn[1]) . '</button></form>';
}
echo '</div></div>';
echo '</div>';

echo '<div class="tab-panel" data-tab-panel="tab-system">';
echo '<div class="card"><h3>Darstellung</h3>';
echo '<form method="post">';
echo '<input type="hidden" name="csrf_token" value="' . h(csrf_token()) . '"><input type="hidden" name="action" value="save_theme">';
echo '<label>Theme</label><select name="theme"><option value="light"' . (((string)($config['theme'] ?? 'light')) === 'light' ? ' selected' : '') . '>Lightmode</option><option value="dark"' . (((string)($config['theme'] ?? 'light')) === 'dark' ? ' selected' : '') . '>Darkmode</option><option value="happy"' . (((string)($config['theme'] ?? 'light')) === 'happy' ? ' selected' : '') . '>Happy Theme</option><option value="cat"' . (((string)($config['theme'] ?? 'light')) === 'cat' ? ' selected' : '') . '>Cat Theme</option></select>';
echo '<div class="form-submit-gap"><button type="submit">Theme speichern</button></div></form></div>';
echo '<div class="card"><h3>Rate-Limiter</h3>';
echo '<p class="small muted">Diese Einstellung gilt für Admin-Login, PIN-Eingabe, Captcha-Fehler und die erneute Admin-Authentifizierung nach einer Sperre. Die Sperrdauer ist intern fest gesetzt.</p>';
echo '<form method="post">';
echo '<input type="hidden" name="csrf_token" value="' . h(csrf_token()) . '"><input type="hidden" name="action" value="save_rate_limit">';
echo '<label>Fehlversuche bis zur Sperre</label><input type="number" name="rate_limit_max_failures" min="1" max="50" value="' . h((string)rate_limit_max_failures($config)) . '" required>';
echo '<div class="form-submit-gap"><button type="submit">Rate-Limiter speichern</button></div></form></div>';
echo '<div class="card"><h3>Sicherheit</h3>';
echo '<p class="small muted">Hier kannst du das Admin-Passwort und die 4-stellige Check-in-PIN ändern. Zur Bestätigung ist immer das aktuelle Admin-Passwort erforderlich.</p>';
echo '<form method="post" autocomplete="off" data-bwignore="true">';
echo '<input type="hidden" name="csrf_token" value="' . h(csrf_token()) . '"><input type="hidden" name="action" value="save_security">';
echo '<label>Aktuelles Admin-Passwort</label><input type="password" name="current_admin_password" autocomplete="off" data-bwignore="true" required>';
echo '<div class="grid"><div><label>Neues Admin-Passwort</label><input type="password" name="new_admin_password" placeholder="mindestens 12 Zeichen" autocomplete="new-password" data-bwignore="true"></div><div><label>Neues Admin-Passwort bestätigen</label><input type="password" name="new_admin_password_confirm" autocomplete="new-password" data-bwignore="true"></div></div>';
echo '<div class="grid"><div><label>Neue Check-in PIN</label><input type="text" name="new_pin" pattern="\d{4}" maxlength="4" placeholder="1234" inputmode="numeric" autocomplete="off" data-bwignore="true"></div><div><label>Neue PIN bestätigen</label><input type="text" name="new_pin_confirm" pattern="\d{4}" maxlength="4" placeholder="1234" inputmode="numeric" autocomplete="off" data-bwignore="true"></div></div>';
echo '<div class="form-submit-gap"><button type="submit">Sicherheitsdaten speichern</button></div></form></div>';
echo '<div class="card danger-card"><h3>&#128736; System-Aktionen</h3><div class="grid">';
echo '<div><form method="post"><input type="hidden" name="csrf_token" value="' . h(csrf_token()) . '"><input type="hidden" name="action" value="reset_all"><button type="submit" class="btn btn-danger" onclick="return confirm(\'Wirklich alles löschen?\')">System zurücksetzen</button></form></div>';
echo '</div></div>';
echo '</div>';
echo '<div class="tab-panel" data-tab-panel="tab-logs">';
echo '<div class="card"><h3>Logs</h3>';
echo '<p class="small muted">Anzeige der letzten Einträge aus der events.log.</p>';
$activeLogFilter = normalize_log_filter((string)($_GET['filter'] ?? 'all'));
$activeLogQuery = normalize_log_query((string)($_GET['query'] ?? ''));
echo '<div class="logs-toolbar">';
echo '<div class="filter-wrap"><label for="logs-filter" style="margin:0">Filter</label><select id="logs-filter" data-logs-filter-select data-logs-refresh-button="logs-refresh">';
foreach (log_filter_options() as $filterValue => $filterLabel) {
    echo '<option value="' . h($filterValue) . '"' . ($activeLogFilter === $filterValue ? ' selected' : '') . '>' . h($filterLabel) . '</option>';
}
echo '</select>';
echo '<input id="logs-query" class="search-input" type="text" value="' . h($activeLogQuery) . '" placeholder="Logs durchsuchen" data-logs-query-input data-logs-refresh-button="logs-refresh">';
echo '</div>';
echo '<button id="logs-refresh" type="button" class="captcha-refresh" data-logs-refresh="logs-output" data-logs-filter="logs-filter" data-logs-query="logs-query" aria-label="Logs aktualisieren" title="Logs aktualisieren">🔄</button></div>';
echo '<pre id="logs-output" class="code" style="white-space:pre-wrap;max-height:70vh;overflow:auto;margin:0">' . h(read_events_log(300, $activeLogFilter, $activeLogQuery)) . '</pre>';
echo '<form method="post" autocomplete="off" data-bwignore="true" style="margin-top:20px">';
echo '<input type="hidden" name="csrf_token" value="' . h(csrf_token()) . '"><input type="hidden" name="action" value="clear_logs">';
echo '<label>Aktuelles Admin-Passwort</label><input type="password" name="current_admin_password" autocomplete="off" data-bwignore="true" required>';
echo '<div class="form-submit-gap"><button type="submit" class="btn btn-danger" onclick="return confirm(\'Wirklich alle Logs löschen?\')">Logs löschen</button></div></form>';
echo '</div>';
echo '</div>';
echo '</div></div>';

render_footer();
