<?php
require_once 'config.php';

/* ===============================
   AUTH PROTECTION (REQUIRED)
================================ */
if (!isset($_SESSION['user'])) {
    header("Location: login.php");
    exit;
}

/* ===============================
   CSRF TOKEN SAFETY
================================ */
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

/* ===============================
   SEARCH HANDLING
================================ */
$search = trim($_GET['search'] ?? '');

/* ===============================
   PAGINATION
================================ */
$page = max(1, (int)($_GET['page'] ?? 1));
$perPage = 5;
$offset = ($page - 1) * $perPage;

try {

    if ($search !== '') {
        $stmt = $pdo->prepare("
            SELECT p.id, p.title, p.content, p.created_at, p.user_id, p.category, u.username
            FROM posts p
            LEFT JOIN users u ON p.user_id = u.id
            WHERE p.title LIKE :s 
               OR p.content LIKE :s 
               OR p.category LIKE :s
            ORDER BY p.created_at DESC
            LIMIT :limit OFFSET :offset
        ");
        $like = '%' . $search . '%';
        $stmt->bindValue(':s', $like, PDO::PARAM_STR);
        $stmt->bindValue(':limit', (int)$perPage, PDO::PARAM_INT);
        $stmt->bindValue(':offset', (int)$offset, PDO::PARAM_INT);
        $stmt->execute();
        $posts = $stmt->fetchAll();

        $countStmt = $pdo->prepare("
            SELECT COUNT(*) 
            FROM posts 
            WHERE title LIKE :s 
               OR content LIKE :s 
               OR category LIKE :s
        ");
        $countStmt->execute(['s' => $like]);
        $total = (int)$countStmt->fetchColumn();

    } else {
        $stmt = $pdo->prepare("
            SELECT p.id, p.title, p.content, p.created_at, p.user_id, p.category, u.username
            FROM posts p
            LEFT JOIN users u ON p.user_id = u.id
            ORDER BY p.created_at DESC
            LIMIT :limit OFFSET :offset
        ");
        $stmt->bindValue(':limit', (int)$perPage, PDO::PARAM_INT);
        $stmt->bindValue(':offset', (int)$offset, PDO::PARAM_INT);
        $stmt->execute();
        $posts = $stmt->fetchAll();

        $total = (int)$pdo->query("SELECT COUNT(*) FROM posts")->fetchColumn();
    }

    $totalPages = max(1, (int)ceil($total / $perPage));

} catch (Exception $e) {
    error_log('Index error: ' . $e->getMessage());
    $posts = [];
    $totalPages = 1;
}
?>

<!doctype html>
<html>
<head>
    <meta charset="utf-8">
    <title>All Posts</title>
    <link rel="stylesheet" href="styles.css">
</head>
<body>

<!-- NAV BAR -->
<nav style="background:#0b5c8a;color:#fff;padding:12px;margin-bottom:20px;">
  <div style="max-width:1000px;margin:auto;display:flex;align-items:center;gap:14px;">
    <a href="index.php" style="color:#fff;text-decoration:none;font-weight:bold;">Home</a>
    <a href="create.php" style="color:#fff;text-decoration:none;">+ New Post</a>

    <div style="margin-left:auto;display:flex;align-items:center;gap:10px;">
        <span style="background:#fff;color:#0b5c8a;padding:6px 9px;border-radius:6px;font-weight:600;">
            <?= escape($_SESSION['user']['username']) ?> (<?= escape($_SESSION['user']['role']) ?>)
        </span>
        <a href="logout.php" style="color:#fff;text-decoration:none;">Logout</a>
    </div>
  </div>
</nav>

<div class="container">

<!-- SEARCH -->
<form method="GET" style="margin-bottom:20px;display:flex;gap:8px;">
    <input type="text" name="search" placeholder="Search..." value="<?= escape($search) ?>">
    <button type="submit">Search</button>
</form>

<h3>All Posts</h3>

<?php if (empty($posts)): ?>
    <p>No posts found.</p>
<?php else: ?>
    <?php foreach ($posts as $post): ?>
        <div class="post-card">
            <h3><?= escape($post['title']) ?></h3>
            <small>
                Posted on <?= escape($post['created_at']) ?> 
                by <?= escape($post['username'] ?? 'Unknown') ?>
                <?php if ($post['category']): ?>
                    | Category: <?= escape($post['category']) ?>
                <?php endif; ?>
            </small>

            <p><?= nl2br(escape(substr($post['content'], 0, 300))) ?></p>

            <a href="view.php?id=<?= (int)$post['id'] ?>">Read</a>

            <?php if (
                $_SESSION['user']['id'] === (int)$post['user_id'] ||
                $_SESSION['user']['role'] === 'admin'
            ): ?>
                | <a href="edit.php?id=<?= (int)$post['id'] ?>">Edit</a>
                | <form method="POST" action="delete.php" style="display:inline" 
                        onsubmit="return confirm('Delete this post?');">
                    <input type="hidden" name="csrf_token" value="<?= escape($_SESSION['csrf_token']) ?>">
                    <input type="hidden" name="id" value="<?= (int)$post['id'] ?>">
                    <button type="submit" style="border:none;background:none;color:#0b5c8a;cursor:pointer;">
                        Delete
                    </button>
                  </form>
            <?php endif; ?>
        </div>
        <hr>
    <?php endforeach; ?>
<?php endif; ?>

<!-- PAGINATION -->
<div class="pagination" style="margin-top:20px;">
    <?php if ($page > 1): ?>
        <a href="?page=<?= $page - 1 ?>&search=<?= urlencode($search) ?>">&laquo; Prev</a>
    <?php endif; ?>

    <strong> Page <?= $page ?> of <?= $totalPages ?> </strong>

    <?php if ($page < $totalPages): ?>
        <a href="?page=<?= $page + 1 ?>&search=<?= urlencode($search) ?>">Next &raquo;</a>
    <?php endif; ?>
</div>

</div>
</body>
</html>
