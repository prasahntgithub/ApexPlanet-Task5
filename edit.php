<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);

require_once 'config.php';

// Must be logged in
if (!isset($_SESSION['user'])) {
    header('Location: login.php');
    exit;
}

// Ensure CSRF token exists
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

$errors = [];

// Get post id from GET or POST
$postId = isset($_GET['id']) ? (int)$_GET['id'] : (isset($_POST['id']) ? (int)$_POST['id'] : 0);
if ($postId <= 0) {
    exit('Invalid post ID.');
}

// Fetch post and verify ownership
try {
    $stmt = $pdo->prepare('SELECT * FROM posts WHERE id = :id LIMIT 1');
    $stmt->execute(['id' => $postId]);
    $post = $stmt->fetch();

    if (!$post) {
        exit('Post not found.');
    }

    // Access control: owner OR admin can edit
$currentUserId = (int)$_SESSION['user']['id'];
$role = $_SESSION['user']['role'] ?? 'user';

if ($currentUserId !== (int)$post['user_id'] && $role !== 'admin') {
    http_response_code(403);
    exit('Forbidden: you do not have permission to edit this post.');
}


} catch (Exception $e) {
    error_log('Edit fetch error: ' . $e->getMessage());
    exit('Internal error.');
}

// Handle form submit
if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    // CSRF
    $token = $_POST['csrf_token'] ?? '';
    if (!hash_equals($_SESSION['csrf_token'], $token)) {
        $errors[] = 'Invalid CSRF token.';
    }

    // Collect/validate
    $title = trim($_POST['title'] ?? '');
    $content = trim($_POST['content'] ?? '');
    $category = trim($_POST['category'] ?? '');

    if ($title === '') $errors[] = 'Title is required.';
    if ($content === '') $errors[] = 'Content is required.';
    if (mb_strlen($title) > 255) $errors[] = 'Title too long (max 255).';
    if ($category !== '' && mb_strlen($category) > 100) $errors[] = 'Category too long (max 100).';

    if (empty($errors)) {
        try {
            $update = $pdo->prepare('UPDATE posts SET title = :title, content = :content, category = :category WHERE id = :id AND user_id = :user_id');
            $update->execute([
                'title' => $title,
                'content' => $content,
                'category' => $category ?: null,
                'id' => $postId,
                'user_id' => $currentUserId, // extra safety: ensure only owner can update
            ]);

            // rotate CSRF token after successful action
            $_SESSION['csrf_token'] = bin2hex(random_bytes(32));

            header('Location: view.php?id=' . $postId);
            exit;

        } catch (Exception $e) {
            error_log('Edit update error: ' . $e->getMessage());
            $errors[] = 'Failed to update post.';
        }
    }
}

// Pre-fill fields (on GET or after failed POST)
$titleVal = isset($title) ? $title : $post['title'];
$contentVal = isset($content) ? $content : $post['content'];
$categoryVal = isset($category) ? $category : ($post['category'] ?? '');

?>
<!doctype html>
<html>
<head>
    <meta charset="utf-8">
    <title>Edit Post</title>
</head>
<body>

<?php include 'nav_snippet.php'; ?>


<h2>Edit Post</h2>

<?php if (!empty($errors)): ?>
    <div style="color:red;">
        <?php foreach ($errors as $e): ?>
            <?= escape($e) ?><br>
        <?php endforeach; ?>
    </div>
<?php endif; ?>

<form method="POST">
    <input type="hidden" name="csrf_token" value="<?= escape($_SESSION['csrf_token']) ?>">
    <input type="hidden" name="id" value="<?= (int)$postId ?>">

    <label>Title</label><br>
    <input type="text" name="title" value="<?= escape($titleVal) ?>" maxlength="255" required><br><br>

    <label>Content</label><br>
    <textarea name="content" rows="8" required><?= escape($contentVal) ?></textarea><br><br>

    <label>Category (optional)</label><br>
    <input type="text" name="category" value="<?= escape($categoryVal) ?>" maxlength="100"><br><br>

    <button type="submit">Save changes</button>
</form>

<p><a href="view.php?id=<?= (int)$postId ?>">Cancel</a> | <a href="index.php">Home</a></p>

</body>
</html>
