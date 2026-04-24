<?php
require_once 'config.php';

$errors = [];
$success = false;

// Ensure CSRF token exists
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    // CSRF validation
    if (!isset($_POST['csrf_token']) || 
        !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        $errors[] = 'Invalid form submission. Please refresh and try again.';
    }

    // Input values
    $username = trim($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';
    $password_confirm = $_POST['password_confirm'] ?? '';

    // Username validation
    if ($username === '') {
        $errors[] = 'Username is required.';
    } elseif (!preg_match('/^[A-Za-z0-9_]{3,50}$/', $username)) {
        $errors[] = 'Username must be 3–50 characters and contain only letters, numbers, and underscores.';
    }

    // Password validation
    if ($password === '') {
        $errors[] = 'Password is required.';
    } elseif (strlen($password) < 8) {
        $errors[] = 'Password must be at least 8 characters long.';
    }

    if ($password !== $password_confirm) {
        $errors[] = 'Passwords do not match.';
    }

    if (empty($errors)) {

        // Check existing username
        $check = $pdo->prepare("SELECT id FROM users WHERE username = :username LIMIT 1");
        $check->execute(['username' => $username]);

        if ($check->fetch()) {
            $errors[] = 'Username already exists.';
        } else {

            // Hash password
            $password_hash = password_hash($password, PASSWORD_DEFAULT);

            // Insert user (default role_id = 1 → user)
            $insert = $pdo->prepare("
                INSERT INTO users (username, password, role_id)
                VALUES (:username, :password, :role_id)
            ");

            $insert->execute([
                'username' => $username,
                'password' => $password_hash,
                'role_id'  => 1
            ]);

            $success = true;
        }
    }
}
?>

<!DOCTYPE html>
<html>
<head>
    <title>Register</title>
    <meta charset="utf-8">
</head>
<body>

<h2>Register</h2>

<?php if ($success): ?>
    <p style="color:green;">Registration successful. <a href="login.php">Login here</a></p>
<?php endif; ?>

<?php if (!empty($errors)): ?>
    <ul style="color:red;">
        <?php foreach ($errors as $error): ?>
            <li><?= escape($error) ?></li>
        <?php endforeach; ?>
    </ul>
<?php endif; ?>

<form method="post">
    <input type="hidden" name="csrf_token" value="<?= escape($_SESSION['csrf_token']) ?>">

    <label>Username</label><br>
    <input type="text" name="username" required><br><br>

    <label>Password</label><br>
    <input type="password" name="password" required><br><br>

    <label>Confirm Password</label><br>
    <input type="password" name="password_confirm" required><br><br>

    <button type="submit">Register</button>
</form>

</body>
</html>
