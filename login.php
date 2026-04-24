<?php
require_once 'config.php';

$errors = [];
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}


if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    // Basic validation
    $username = trim($_POST['username'] ?? '');
    $password = trim($_POST['password'] ?? '');

    if ($username === '' || $password === '') {
        $errors[] = "Username and password are required.";
    }

    if (!isset($_POST['csrf_token']) ||
    !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
    $errors[] = "Invalid form submission.";
    }

    if (empty($errors)) {
        // Secure query; join roles to fetch role name
        $stmt = $pdo->prepare("
            SELECT u.id, u.username, u.password, r.name AS role
            FROM users u
            LEFT JOIN roles r ON u.role_id = r.id
            WHERE u.username = :username
            LIMIT 1
        ");
        $stmt->execute(['username' => $username]);
        $user = $stmt->fetch();

        if ($user && password_verify($password, $user['password'])) {

            session_regenerate_id(true);

            // Store user and role in session
            $_SESSION['user'] = [
                'id' => (int)$user['id'],
                'username' => $user['username'],
                'role' => $user['role'] ?? 'user'
            ];

            header("Location: index.php");
            exit;

        } else {
            $errors[] = "Invalid username or password.";
        }
    }
}
?>

<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Login</title></head>
<body>
<h2>Login</h2>

<?php if (!empty($errors)): ?>
    <div style="color:red;">
        <?php foreach($errors as $err): ?>
            <?= escape($err) ?><br>
        <?php endforeach; ?>
    </div>
<?php endif; ?>

<form method="POST">
    <label>Username:</label><br>
    <input type="text" name="username" required><br><br>

    <label>Password:</label><br>
    <input type="hidden" name="csrf_token" value="<?= escape($_SESSION['csrf_token']) ?>">
    <input type="password" name="password" required><br><br>

    <button type="submit">Login</button>
</form>
</body>
</html>
