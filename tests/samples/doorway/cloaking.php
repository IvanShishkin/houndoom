<?php
// TEST FILE: Doorway with cloaking
// This should trigger: doorway detector DOOR-CLOAK

// Cloaking - show different content to bots
$ua = $_SERVER['HTTP_USER_AGENT'];

if (preg_match('/googlebot|yandexbot|bingbot|crawler|spider/i', $ua)) {
    // Content for search engine bots
    echo "<h1>SEO optimized content</h1>";
    echo "<p>Keywords keywords keywords keywords keywords</p>";
    // Redirect bots to spam page
    header("Location: http://spam-site.com/landing");
} else {
    // Content for regular users
    echo "<h1>Normal website</h1>";
}

// Another cloaking method
if (isBot()) {
    include('seo-content.html');
} else {
    include('real-content.html');
}

function isBot() {
    return preg_match('/bot|crawl|spider/i', $_SERVER['HTTP_USER_AGENT']);
}
?>
