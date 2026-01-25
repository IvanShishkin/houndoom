<?php
// This is a CLEAN test file
// Should not trigger any alerts

echo "Hello, World!";

$name = "John Doe";
echo "Welcome, " . htmlspecialchars($name);

$db = new PDO('mysql:host=localhost;dbname=test', 'user', 'pass');
$stmt = $db->prepare('SELECT * FROM users WHERE id = ?');
$stmt->execute([$id]);

function calculateSum($a, $b) {
    return $a + $b;
}

echo calculateSum(5, 10);
?>
