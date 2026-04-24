<?php
require_once 'config.php';

/* ===============================
   AUTH CHECK
================================ */
if (!isset($_SESSION['user'])) {
    header('Location: login.php');
    exit;
}

/* ===============================
   CSRF TOKEN SAFETY
================================ */
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

/* ===============================
   ONLY POST REQUESTS
================================ */
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    exit('Invalid request method.');
}

/* ===============================
   INPUT VALIDATION
================================ */
$postId = (int)($_POST['id'] ?? 0);
if ($postId <= 0) {
    exit('Invalid post ID.');
}

/* ===============================
   CSRF VALIDATION
================================ */
if (
    !isset($_POST['csrf_token']) ||
    !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])
) {
    exit('Invalid CSRF token.');
}

try {

    /* ===============================
       FETCH POST (OWNERSHIP CHECK)
    ================================ */
    $stmt = $pdo->prepare(
        "SELECT id, user_id, image 
         FROM posts 
         WHERE id = :id 
         LIMIT 1"
    );
    $stmt->execute(['id' => $postId]);
    $post = $stmt->fetch();

    if (!$post) {
        exit('Post not found.');
    }

    $currentUserId = (int)$_SESSION['user']['id'];
    $role = $_SESSION['user']['role'] ?? 'user';

    /* ===============================
       AUTHORIZATION
    ================================ */
    if ($currentUserId !== (int)$post['user_id'] && $role !== 'admin') {
        http_response_code(403);
        exit('Forbidden.');
    }

    /* ===============================
       DELETE POST
    ================================ */
    if ($role === 'admin') {
        // Admin can delete any post
        $del = $pdo->prepare("DELETE FROM posts WHERE id = :id");
        $del->execute(['id' => $postId]);
    } else {
        // User can delete only own post
        $del = $pdo->prepare(
            "DELETE FROM posts 
             WHERE id = :id AND user_id = :user_id"
        );
        $del->execute([
            'id' => $postId,
            'user_id' => $currentUserId
        ]);
    }

    /* ===============================
       DELETE IMAGE FILE (IF EXISTS)
    ================================ */
    if (!empty($post['image'])) {
        $imagePath = __DIR__ . '/uploads/' . basename($post['image']);
        if (is_file($imagePath)) {
            @unlink($imagePath);
        }
    }

    /* ===============================
       ROTATE CSRF TOKEN
    ================================ */
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));

    /* ===============================
       REDIRECT
    ================================ */
    header('Location: index.php');
    exit;

} catch (Exception $e) {
    error_log('Delete error: ' . $e->getMessage());
    exit('Internal server error.');
}
