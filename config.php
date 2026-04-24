<?php
// config.php - secure PDO connection + session hardening (fixed guard for active sessions)

// ===== DB settings - change these to match your environment =====
$dbHost = '127.0.0.1';
$dbName = 'blog';
$dbUser = 'root';
$dbPass = ''; // replace with your DB password
$dbCharset = 'utf8mb4';

// ===== PDO connection =====
$dsn = "mysql:host=$dbHost;dbname=$dbName;charset=$dbCharset";
$options = [
    PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION, // throw exceptions
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    PDO::ATTR_EMULATE_PREPARES   => false, // use native prepares
];

try {
    $pdo = new PDO($dsn, $dbUser, $dbPass, $options);
} catch (PDOException $e) {
    error_log('Database connection failed: ' . $e->getMessage());
    exit('Database connection error. Check server logs.');
}

// ===== Session hardening =====
// Only set cookie params and start session if no session exists yet.
// If some other file started the session earlier, we won't try to change params (avoids warning).
if (session_status() === PHP_SESSION_NONE) {
    $secure = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on'; // true if HTTPS
    // Set secure cookie params BEFORE starting the session
    session_set_cookie_params([
        'lifetime' => 0,
        'path' => '/',
        'domain' => '',      // set your domain if needed e.g. 'example.com'
        'secure' => $secure,
        'httponly' => true,
        'samesite' => 'Lax',
    ]);
    session_start();
} else {
    // session already active; do nothing.
}

// ===== Helper functions =====

/**
 * Escape output for HTML (prevent XSS)
 */
function escape($html) {
    return htmlspecialchars($html, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

/**
 * Simple role-checking stub (we will extend later)
 * Use as: require_role(['admin','editor']);
 */
function require_role(array $allowed_roles = []) {
    if (!isset($_SESSION['user'])) {
        http_response_code(401);
        exit('Not authenticated');
    }
    if (empty($allowed_roles)) return; // no restriction
    if (!isset($_SESSION['user']['role']) || !in_array($_SESSION['user']['role'], $allowed_roles, true)) {
        http_response_code(403);
        exit('Forbidden');
    }
}

// If some legacy code expects $conn, provide a minimal alias for compatibility.
// Note: you should migrate code to PDO, but this helps avoid immediate fatal errors.
$conn = $pdo;
