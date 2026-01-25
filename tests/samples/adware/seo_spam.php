<?php
// TEST FILE: SEO Spam / Link Networks
// This should trigger: adware detector, ADW signatures

// Sape.ru link network
$links = new SAPE_client();
echo $links->return_links();

// Trustlink network
$tl = new TrustlinkClient();
echo $tl->build_links();

// Linkfeed
$lf = new LinkfeedClient();

// Mainlink
include("codes.mainlink.ru/template.php");

// Hidden SEO block
?>
<!--seo-->
<div style="display:none">
    <a href="http://spam1.com">Keyword stuffing link</a>
    <a href="http://spam2.com">Another spam link</a>
</div>
<!--/seo-->
