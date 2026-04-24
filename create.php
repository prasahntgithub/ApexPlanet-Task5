<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);

require_once 'config.php';

// Require login
if (!isset($_SESSION['user'])) {
    header('Location: login.php');
    exit;
}

$errors = [];
$success = false;

// Ensure CSRF token exists
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Upload settings
$uploadDir = __DIR__ . '/uploads';
$maxFileSize = 2 * 1024 * 1024; // 2 MB
$allowedMime = ['image/jpeg', 'image/png', 'image/gif'];
$allowedExt = ['jpg', 'jpeg', 'png', 'gif'];

// Create upload dir if not exists (set permissions appropriately)
if (!is_dir($uploadDir)) {
    mkdir($uploadDir, 0755, true);
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // CSRF check
    $token = $_POST['csrf_token'] ?? '';
    if (!hash_equals($_SESSION['csrf_token'], $token)) {
        $errors[] = 'Invalid form submission (CSRF).';
    }

    // Collect input
    $title = trim($_POST['title'] ?? '');
    $content = trim($_POST['content'] ?? '');
    $category = trim($_POST['category'] ?? '');

    // Validation
    if ($title === '') {
        $errors[] = 'Title is required.';
    } elseif (mb_strlen($title) > 255) {
        $errors[] = 'Title must be 255 characters or fewer.';
    }

    if ($content === '') {
        $errors[] = 'Content is required.';
    }

    if ($category !== '' && mb_strlen($category) > 100) {
        $errors[] = 'Category must be 100 characters or fewer.';
    }

    // Handle file upload if provided
    $imageFilename = null;
    if (!empty($_FILES['image']['name'])) {
        $file = $_FILES['image'];

        if ($file['error'] !== UPLOAD_ERR_OK) {
            $errors[] = 'Error uploading file.';
        } else {
            if ($file['size'] > $maxFileSize) {
                $errors[] = 'Image is too large (max 2 MB).';
            } else {
                // Validate MIME type via finfo
                $finfo = new finfo(FILEINFO_MIME_TYPE);
                $mime = $finfo->file($file['tmp_name']);
                if (!in_array($mime, $allowedMime, true)) {
                    $errors[] = 'Unsupported image type. Allowed: JPG, PNG, GIF.';
                } else {
                    // Validate extension
                    $ext = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
                    if (!in_array($ext, $allowedExt, true)) {
                        $errors[] = 'Unsupported file extension.';
                    } else {
                        // Create a random filename to avoid collisions
                        $basename = bin2hex(random_bytes(10));
                        $imageFilename = $basename . '.' . $ext;
                        $destination = $uploadDir . '/' . $imageFilename;

                        // Move uploaded file
                        if (!move_uploaded_file($file['tmp_name'], $destination)) {
                            $errors[] = 'Failed to save uploaded image.';
                            $imageFilename = null;
                        } else {
                            // Optionally set correct permissions
                            chmod($destination, 0644);
                        }
                    }
                }
            }
        }
    }

    // If no errors, insert into DB
    if (empty($errors)) {
        try {
            $pdo->beginTransaction();

            $stmt = $pdo->prepare('INSERT INTO posts (title, content, user_id, image, category) VALUES (:title, :content, :user_id, :image, :category)');
            $stmt->execute([
                'title' => $title,
                'content' => $content,
                'user_id' => $_SESSION['user']['id'],
                'image' => $imageFilename,
                'category' => $category ?: null
            ]);

            $pdo->commit();

            // regenerate CSRF token
            $_SESSION['csrf_token'] = bin2hex(random_bytes(32));

            $success = true;
            header('Location: index.php');
            exit;
        } catch (Exception $e) {
            $pdo->rollBack();
            error_log('Create post error: ' . $e->getMessage());
            // If an image was saved but DB failed, delete the file
            if (!empty($imageFilename)) {
                @unlink($uploadDir . '/' . $imageFilename);
            }
            $errors[] = 'Could not create post. Try again later.';
        }
    }
}

?>
<!doctype html>
<html>
<head>
    <meta charset="utf-8">
    <title>Create Post</title>
    <link rel="stylesheet" href="styles.css">
</head>
<body>

<?php include 'nav_snippet.php'; ?>


<div class="container">
<h2>Create Post</h2>

<?php if (!empty($errors)): ?>
    <div style="color:red;">
        <?php foreach ($errors as $err): ?>
            <?= escape($err) ?><br>
        <?php endforeach; ?>
    </div>
<?php endif; ?>

<form method="POST" enctype="multipart/form-data">
    <input type="hidden" name="csrf_token" value="<?= escape($_SESSION['csrf_token']) ?>">

    <label for="title">Title</label><br>
    <input id="title" name="title" type="text" required maxlength="255" value="<?= isset($title) ? escape($title) : '' ?>">

    <label for="content">Content</label><br>
    <textarea id="content" name="content" rows="8" required><?= isset($content) ? escape($content) : '' ?></textarea>

    <label for="category">Category (optional)</label><br>
    <input id="category" name="category" type="text" maxlength="100" value="<?= isset($category) ? escape($category) : '' ?>">

    <label for="image">Image (optional, JPG/PNG/GIF, max 2MB)</label><br>
    <input id="image" name="image" type="file" accept=".jpg,.jpeg,.png,.gif,image/*">

    <div style="margin-top:12px;">
        <button type="submit">Create</button>
    </div>
</form>

<p><a href="index.php">Back to posts</a></p>
</div>
</body>
</html>
