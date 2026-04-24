<?php
require_once 'config.php';

// Unset all session variables
$_SESSION = [];

// Delete session cookie safely
if (ini_get("session.use_cookies")) {
    $params = session_get_cookie_params();
    setcookie(
        session_name(),
        '',
        time() - 42000,
        $params["path"],
        $params["domain"],
        $params["secure"],
        $params["httponly"]
    );
}

// Destroy session
session_destroy();

// Regenerate ID to prevent fixation
session_regenerate_id(true);

// Redirect to login
header("Location: login.php");
exit;
