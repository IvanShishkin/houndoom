package wordpress

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/IvanShishkin/houndoom/internal/detectors"
	"github.com/IvanShishkin/houndoom/internal/signatures"
	"github.com/IvanShishkin/houndoom/pkg/models"
)

// WordPressDetector performs WordPress CMS-specific threat detection.
//
// Detection model:
//   - Content patterns (eval, SQLi, auth, hooks, malware families, ...) are defined
//     in YAML signatures under configs/signatures/wordpress_*.yaml. The matcher is
//     the single source of truth for content-level detection.
//   - This detector adds path / structure context that YAML cannot express:
//     PHP in uploads, mu-plugins persistence, fake core files, .htaccess / .user.ini
//     injection vectors, hidden dot-files, etc.
//   - A suppression layer reduces false positives on legitimate core files and on
//     security / managed plugins that legitimately contain detection patterns.
type WordPressDetector struct {
	*detectors.BaseDetector
	matcher *signatures.Matcher
	level   models.SignatureLevel

	// Whitelists
	coreFileWhitelist []string // WP core paths that legitimately use sensitive APIs
	securityPlugins   []string // security plugins — content fully trusted (skip all WP- sigs)
	managedPlugins    []string // caching/membership/forms — skip vulnerability-family sigs
	legitMUDropins    []string // legitimate must-use plugin filenames

	// Path classification
	uploadsPathRe   *regexp.Regexp
	muPluginsPathRe *regexp.Regexp
	includesPathRe  *regexp.Regexp
	adminPathRe     *regexp.Regexp
	themePluginRe   *regexp.Regexp
	hiddenPhpRe     *regexp.Regexp

	// Content patterns used ONLY inside structure context (not duplicated in YAML)
	htaccessSuspiciousRe *regexp.Regexp // .htaccess injection directives
	userIniPrependRe     *regexp.Regexp // .user.ini auto_prepend
	shellFuncRe          *regexp.Regexp // generic shell functions for mu-plugins context
	pluginHeaderRe       *regexp.Regexp // "Plugin Name:" header
	fakeCoreFileNames    []string       // names mimicking WP core
	fakeMUFileNames      []string       // names mimicking core inside mu-plugins
}

// NewWordPressDetector creates a new WordPress-specific detector.
func NewWordPressDetector(matcher *signatures.Matcher, level models.SignatureLevel) *WordPressDetector {
	d := &WordPressDetector{
		BaseDetector: detectors.NewBaseDetector("wordpress_cms", 95, []string{
			"php", "php3", "php4", "php5", "php6", "php7", "phtml", "pht", "inc",
			"js", "html", "htm", "htaccess", "ini",
		}),
		matcher: matcher,
		level:   level,

		coreFileWhitelist: []string{
			"wp-includes/pluggable.php",
			"wp-includes/pluggable-deprecated.php",
			"wp-includes/user.php",
			"wp-includes/class-wp-user.php",
			"wp-includes/capabilities.php",
			"wp-includes/class-wp-roles.php",
			"wp-includes/class-wp-role.php",
			"wp-includes/ms-functions.php",
			"wp-includes/ms-default-filters.php",
			"wp-includes/default-filters.php",
			"wp-includes/class-wp-xmlrpc-server.php",
			"wp-includes/rest-api.php",
			"wp-includes/rest-api/class-wp-rest-server.php",
			"wp-includes/rest-api/endpoints/class-wp-rest-users-controller.php",
			"wp-includes/class-wp-customize-manager.php",
			"wp-includes/cron.php",
			"wp-includes/option.php",
			"wp-includes/http.php",
			"wp-includes/class-http.php",
			"wp-includes/class-wp-http.php",
			"wp-login.php",
			"wp-admin/includes/user.php",
			"wp-admin/includes/upgrade.php",
			"wp-admin/includes/file.php",
			"wp-admin/includes/plugin.php",
			"wp-admin/user-new.php",
			"wp-admin/user-edit.php",
			"wp-admin/async-upload.php",
		},

		// Security plugins contain detection patterns (eval/base64/wp_set_auth_cookie/...)
		// as part of their own scanning logic. Suppress WP- signatures there to avoid FPs.
		securityPlugins: []string{
			"wp-content/plugins/wordfence/",
			"wp-content/plugins/wordfence-assistant/",
			"wp-content/plugins/wordfence-login-security/",
			"wp-content/plugins/sucuri-scanner/",
			"wp-content/plugins/better-wp-security/",
			"wp-content/plugins/solid-security/",
			"wp-content/plugins/ithemes-security/",
			"wp-content/plugins/all-in-one-wp-security/",
			"wp-content/plugins/wp-security-audit-log/",
			"wp-content/plugins/anti-malware/",
			"wp-content/plugins/wp-cerber/",
			"wp-content/plugins/secupress/",
			"wp-content/plugins/defender-security/",
		},

		// Plugins that legitimately use sensitive APIs (caching auto_prepend,
		// membership wp_insert_user, forms move_uploaded_file, backup file ops).
		// Vulnerability-family signatures are suppressed; malware/backdoor stay on.
		managedPlugins: []string{
			// Caching / performance (auto_prepend_file, file_put_contents)
			"wp-content/plugins/w3-total-cache/",
			"wp-content/plugins/wp-super-cache/",
			"wp-content/plugins/wp-rocket/",
			"wp-content/plugins/litespeed-cache/",
			"wp-content/plugins/wp-optimize/",
			"wp-content/plugins/comet-cache/",
			"wp-content/plugins/sg-cachepress/",
			"wp-content/plugins/bunnycdn/",
			// Membership / users (wp_insert_user, set_role, add_cap, wp_set_auth_cookie)
			"wp-content/plugins/woocommerce/",
			"wp-content/plugins/memberpress/",
			"wp-content/plugins/paid-memberships-pro/",
			"wp-content/plugins/ultimate-member/",
			"wp-content/plugins/bbpress/",
			"wp-content/plugins/buddypress/",
			"wp-content/plugins/wp-members/",
			"wp-content/plugins/userswp/",
			"wp-content/plugins/profile-builder/",
			"wp-content/plugins/user-registration/",
			"wp-content/plugins/learndash/",
			"wp-content/plugins/lifterlms/",
			"wp-content/plugins/restrict-content-pro/",
			"wp-content/plugins/wishlist-member/",
			// Forms (move_uploaded_file, file writes)
			"wp-content/plugins/wpforms/",
			"wp-content/plugins/wpforms-lite/",
			"wp-content/plugins/formidable/",
			"wp-content/plugins/gravityforms/",
			"wp-content/plugins/ninja-forms/",
			"wp-content/plugins/contact-form-7/",
			// Migration / backup (file ops, download_url)
			"wp-content/plugins/duplicator/",
			"wp-content/plugins/all-in-one-wp-migration/",
			"wp-content/plugins/updraftplus/",
			"wp-content/plugins/backwpup/",
			"wp-content/plugins/wpvivid-backuprestore/",
			// Jetpack (SSO -> wp_set_auth_cookie, wp_insert_user, REST, wp_remote_get)
			"wp-content/plugins/jetpack/",
			// Page builders (template rendering)
			"wp-content/plugins/elementor/",
			"wp-content/plugins/elementor-pro/",
			"wp-content/plugins/beaver-builder-lite-version/",
			"wp-content/plugins/bb-plugin/",
			"wp-content/plugins/divi/",
			"wp-content/plugins/js_composer/",
			"wp-content/plugins/wpbakery-page-builder/",
			"wp-content/plugins/brizy/",
			"wp-content/plugins/siteorigin-panels/",
			// Dev tools (eval for profiling, phar, file ops)
			"wp-content/plugins/query-monitor/",
			"wp-content/plugins/debug-bar/",
			"wp-content/plugins/code-snippets/",
		},

		// Legitimate must-use plugin dropin filenames.
		legitMUDropins: []string{
			"gd-system-plugin.php",
			"wpcom-integrity-checker.php",
			"vip-init.php",
			"health-check-disable-plugins.php",
			"wp-debug-data.php",
			"wpcom-helper.php",
			"elementor-pro-mu.php",
			"health-check-troubleshooting-mode.php",
			"load.php",
		},

		fakeCoreFileNames: []string{
			"wp-xmlrpc.php",
			"wp-cron-jobs.php",
			"wp-cron-signals.php",
			"wp-cron-task.php",
			"wp-vcd-loader.php",
			"wp-vcd.php",
			"wp-tmp.php",
			"wp-feed.php",
			"wp-blog-header.php", // legit name, but suspicious when planted outside root
		},

		fakeMUFileNames: []string{
			"wp-cron.php",
			"wp-load.php",
			"wp-config.php",
			"load.php",
			"ms-load.php",
			"admin-ajax.php",
			"xmlrpc.php",
			"index.php", // mu-plugins has no index.php by default
			"0.php",
		},
	}

	d.initPatterns()
	return d
}

func (d *WordPressDetector) initPatterns() {
	d.uploadsPathRe = regexp.MustCompile(`(?i)wp-content[/\\]uploads[/\\]`)
	d.muPluginsPathRe = regexp.MustCompile(`(?i)wp-content[/\\]mu-plugins[/\\]`)
	d.includesPathRe = regexp.MustCompile(`(?i)wp-includes[/\\]`)
	d.adminPathRe = regexp.MustCompile(`(?i)wp-admin[/\\]`)
	d.themePluginRe = regexp.MustCompile(`(?i)wp-content[/\\](themes|plugins)[/\\]`)
	d.hiddenPhpRe = regexp.MustCompile(`(?i)[/\\]\.[^/\\]+\.php$`)

	// .htaccess injection directives (expanded per 2024-2026 research)
	d.htaccessSuspiciousRe = regexp.MustCompile(
		`(?i)(auto_prepend_file|auto_append_file|php_value\s+(auto_prepend|auto_append)|` +
			`php_admin_value\s+(auto_prepend|auto_append|engine)|` +
			`SetHandler\s+application/x-httpd-php|` +
			`AddHandler\s+(server-parsed|application/x-httpd-php)|` +
			`SecFilter(Engine|ScanPOST)\s+Off|` +
			`(SetEnv\s+PHPRC|suPHP_ConfigPath)|` +
			`ErrorDocument\s+\d{3}\s+/[^ \n]*\.php)`)

	// .user.ini auto_prepend (PHP-FPM hosts)
	d.userIniPrependRe = regexp.MustCompile(
		`(?i)auto_(prepend|append)_file\s*=`)

	// Generic shell / obfuscation functions used to qualify mu-plugins findings
	d.shellFuncRe = regexp.MustCompile(
		`(?i)\b(eval|assert|create_function|system|exec|shell_exec|passthru|proc_open|popen|` +
			`base64_decode|gzinflate|gzuncompress|str_rot13|file_put_contents|` +
			`wp_insert_user|wp_set_auth_cookie|move_uploaded_file)\s*\(`)

	d.pluginHeaderRe = regexp.MustCompile(`(?i)Plugin\s+Name\s*:`)
}

// Detect performs WordPress-specific threat detection on a file.
func (d *WordPressDetector) Detect(ctx context.Context, file *models.File) ([]*models.Finding, error) {
	var findings []*models.Finding

	// 1. YAML signature content detection (single source of truth) with suppression.
	findings = append(findings, d.detectSignatures(file)...)

	// 2. Path / structure anomalies (context YAML cannot express).
	findings = append(findings, d.detectStructureAnomalies(file)...)

	return findings, nil
}

// ---------------------------------------------------------------------------
// Signature detection + suppression
// ---------------------------------------------------------------------------

// detectSignatures runs the YAML matcher and filters WordPress-specific matches
// through a suppression layer that removes false positives on legitimate core
// files, security plugins and managed plugins.
func (d *WordPressDetector) detectSignatures(file *models.File) []*models.Finding {
	ctx := d.classifyFile(file.Path)

	matches := d.matcher.Match(file.Content, file.Extension, d.level)

	// Deduplicate by signature ID: matcher can return the same signature twice if
	// it is referenced from multiple level buckets, and multiple detectors share
	// the matcher. Keep the first (highest-priority) match per ID.
	seen := make(map[string]bool)
	var findings []*models.Finding

	for _, match := range matches {
		sigID := match.Signature.ID
		if !strings.HasPrefix(sigID, "WP-") {
			continue
		}
		if seen[sigID] {
			continue
		}
		if d.shouldSuppress(sigID, ctx) {
			continue
		}
		seen[sigID] = true

		findings = append(findings, d.matchToFinding(file, match))
	}
	return findings
}

// fileContext describes the role a file plays, used for FP suppression.
type fileContext struct {
	isCore           bool
	isSecurityPlugin bool
	isManagedPlugin  bool
}

// classifyFile determines the file context from its path.
func (d *WordPressDetector) classifyFile(path string) fileContext {
	normalized := strings.ReplaceAll(path, "\\", "/")
	lower := strings.ToLower(normalized)

	ctx := fileContext{}
	if d.isCoreFile(lower) {
		ctx.isCore = true
	}
	if anyContains(lower, d.securityPlugins) {
		ctx.isSecurityPlugin = true
	}
	if !ctx.isSecurityPlugin && anyContains(lower, d.managedPlugins) {
		ctx.isManagedPlugin = true
	}
	return ctx
}

// shouldSuppress returns true when a signature should be skipped for a context.
//
// Suppression matrix:
//   - security plugins: suppress ALL WP- signatures (they contain detection
//     patterns themselves; a real compromise inside a security plugin is out of
//     scope for static content matching).
//   - core files: suppress vulnerability-family signatures (auth/API/hook/...)
//     which are legitimate inside WP core; keep backdoor / malware detection.
//   - managed plugins: suppress vulnerability-family signatures + htaccess
//     signatures (caching uses auto_prepend legitimately); keep backdoor /
//     malware detection.
func (d *WordPressDetector) shouldSuppress(sigID string, ctx fileContext) bool {
	if ctx.isSecurityPlugin {
		return true
	}
	family := sigFamily(sigID)
	if !isVulnerabilityFamily(family) {
		return false
	}
	return ctx.isCore || ctx.isManagedPlugin
}

// sigFamily extracts the family token from a signature ID: "WP-BACKDOOR-004" -> "BACKDOOR".
func sigFamily(sigID string) string {
	// IDs use the form WP-<FAMILY>-<NUM> or WP-<FAMILY>-<SUB>-<NUM>.
	parts := strings.Split(sigID, "-")
	if len(parts) < 2 {
		return ""
	}
	return parts[1]
}

// isVulnerabilityFamily reports whether a family describes a vulnerability /
// API-misuse pattern (as opposed to concrete malware / backdoor indicators).
// Vulnerability families are the main false-positive source on core & managed
// plugins which legitimately call these APIs.
func isVulnerabilityFamily(family string) bool {
	switch family {
	case "AUTH", "SQLI", "SSRF", "VULN", "HOOK", "REST", "CRON", "OPT", "AJAX", "DESER":
		return true
	}
	return false
}

func anyContains(s string, candidates []string) bool {
	for _, c := range candidates {
		if strings.Contains(s, c) {
			return true
		}
	}
	return false
}

// matchToFinding converts a matcher result into a Finding with WordPress
// metadata and risk weighting based on the signature family.
func (d *WordPressDetector) matchToFinding(file *models.File, match *signatures.MatchResult) *models.Finding {
	fragment, lineNumber := signatures.GetFragment(file.Content, match.Position, 100)

	riskScore := models.NewRiskScore()
	riskScore.Contexts[models.ContextDefault] = true
	riskScore.TotalWeight = familyWeight(match.Signature.ID)
	if isVulnerabilityFamily(sigFamily(match.Signature.ID)) {
		riskScore.Contexts[models.ContextUserInput] = true
	}
	riskScore.Calculate()

	return &models.Finding{
		File:          file,
		Type:          match.Signature.Category,
		Severity:      riskScore.GetSeverity(),
		SignatureID:   match.Signature.ID,
		SignatureName: match.Signature.Name,
		Description:   match.Signature.Description + " [WordPress CMS Specific]",
		Position:      match.Position,
		LineNumber:    lineNumber,
		Snippet:       match.Matched,
		Fragment:      fragment,
		Confidence:    95,
		RiskScore:     riskScore,
		Timestamp:     time.Now(),
		Metadata: map[string]interface{}{
			"wordpress_signature": true,
			"pattern":             match.Signature.Pattern,
			"weight":              riskScore.TotalWeight,
			"cms":                 "wordpress",
		},
	}
}

// familyWeight maps a signature family to a risk weight used for scoring.
func familyWeight(sigID string) float64 {
	switch sigFamily(sigID) {
	case "BACKDOOR":
		return 2.5
	case "MALWARE":
		return 2.2
	case "MUP":
		return 2.5
	case "SQLI", "AUTH", "REST", "CRON", "OPT":
		return 2.0
	case "SSRF", "HOOK", "DESER":
		return 1.8
	case "AJAX", "VULN":
		return 1.5
	default:
		return 1.2
	}
}

// ---------------------------------------------------------------------------
// Path / structure anomalies
// ---------------------------------------------------------------------------

// detectStructureAnomalies flags WordPress placement violations and injection
// vectors that require path or filename context and therefore cannot live in
// the YAML signature database.
func (d *WordPressDetector) detectStructureAnomalies(file *models.File) []*models.Finding {
	var findings []*models.Finding

	normalized := strings.ReplaceAll(file.Path, "\\", "/")
	lower := strings.ToLower(normalized)
	content := string(file.Content)
	baseName := file.Name
	if baseName == "" {
		if idx := strings.LastIndex(normalized, "/"); idx >= 0 {
			baseName = normalized[idx+1:]
		}
	}

	// --- PHP file inside wp-content/uploads/ (media-only directory) ---------
	if d.uploadsPathRe.MatchString(lower) && file.Extension == "php" {
		findings = append(findings, d.structureFinding(file, "WP-STRUCTURE-001",
			"PHP File in Uploads Directory",
			"PHP file found in wp-content/uploads/ - this directory should only contain media files",
			"php_in_uploads", models.SeverityHigh, 1.5, 90))
	}

	// --- .htaccess with injection directives in protected dirs --------------
	if file.Extension == "htaccess" {
		isProtected := d.adminPathRe.MatchString(lower) || d.includesPathRe.MatchString(lower)
		// Suspicious directives anywhere are also worth reporting, but raise
		// severity when they appear inside wp-admin / wp-includes.
		if loc := d.htaccessSuspiciousRe.FindStringIndex(content); loc != nil {
			sev := models.SeverityHigh
			weight := 1.8
			conf := 80
			if isProtected {
				sev = models.SeverityCritical
				weight = 2.2
				conf = 90
			}
			findings = append(findings, d.structureFindingWithMatch(file, "WP-STRUCTURE-002",
				"Suspicious .htaccess Directive",
				"auto_prepend_file / SetHandler php / mod_security disable / PHPRC in .htaccess - common injection vector",
				"suspicious_htaccess", sev, weight, conf, loc[0], content[loc[0]:loc[1]]))
		}
	}

	// --- .user.ini auto_prepend_file (PHP-FPM hosts) -----------------------
	if file.Extension == "ini" {
		if loc := d.userIniPrependRe.FindStringIndex(content); loc != nil {
			findings = append(findings, d.structureFindingWithMatch(file, "WP-STRUCTURE-008",
				".user.ini auto_prepend Injection",
				"auto_prepend_file / auto_append_file set in a .user.ini - PHP-FPM auto-load injection vector",
				"user_ini_prepend", models.SeverityCritical, 2.2, 85, loc[0], content[loc[0]:loc[1]]))
		}
	}

	// --- Hidden dot-prefixed PHP in themes/plugins -------------------------
	if file.Extension == "php" && d.themePluginRe.MatchString(lower) && d.hiddenPhpRe.MatchString(lower) {
		findings = append(findings, d.structureFinding(file, "WP-STRUCTURE-003",
			"Hidden PHP File in Theme/Plugin",
			"Dot-prefixed (hidden) PHP file in themes/plugins - may be a hidden backdoor",
			"hidden_php_file", models.SeverityMedium, 1.2, 75))
	}

	// --- Fake core files planted inside wp-includes/ -----------------------
	if file.Extension == "php" && d.includesPathRe.MatchString(lower) {
		for _, fake := range []string{"wp-includes/wp-vcd.php", "wp-includes/wp-tmp.php", "wp-includes/class-wp-cache.php"} {
			if strings.HasSuffix(lower, fake) {
				findings = append(findings, d.structureFinding(file, "WP-STRUCTURE-004",
					"Fake Core File in wp-includes",
					fmt.Sprintf("Non-standard file %s in wp-includes/ - likely planted backdoor", baseName),
					"fake_core_file", models.SeverityCritical, 2.2, 90))
				break
			}
		}
	}

	// --- Fake WP core filenames anywhere -----------------------------------
	if file.Extension == "php" {
		for _, fake := range d.fakeCoreFileNames {
			if strings.HasSuffix(lower, "/"+fake) {
				// wp-blog-header.php is a legit root file; only flag outside document root.
				if fake == "wp-blog-header.php" && !d.uploadsPathRe.MatchString(lower) && !d.muPluginsPathRe.MatchString(lower) {
					continue
				}
				findings = append(findings, d.structureFinding(file, "WP-STRUCTURE-005",
					"Fake WordPress Core File",
					fmt.Sprintf("File %s is not a legitimate WordPress core file - likely backdoor", fake),
					"fake_core_file", models.SeverityCritical, 2.5, 95))
				break
			}
		}
	}

	// --- must-use plugins persistence --------------------------------------
	if file.Extension == "php" && d.muPluginsPathRe.MatchString(lower) {
		findings = append(findings, d.detectMUPluginsAnomaly(file, lower, baseName, content)...)
	}

	return findings
}

// detectMUPluginsAnomaly handles the mu-plugins persistence vector. Files in
// wp-content/mu-plugins/ are auto-loaded on every request and cannot be
// disabled from wp-admin, making them a favourite attacker hideout.
func (d *WordPressDetector) detectMUPluginsAnomaly(file *models.File, lowerPath, baseName, content string) []*models.Finding {
	var findings []*models.Finding

	// Core-name mimicry inside mu-plugins (wp-cron.php, wp-load.php, ...).
	for _, fake := range d.fakeMUFileNames {
		if strings.HasSuffix(lowerPath, "/mu-plugins/"+fake) && !d.isLegitMUDropin(baseName) {
			findings = append(findings, d.structureFinding(file, "WP-STRUCTURE-007",
				"Core-Name Mimic in mu-plugins",
				fmt.Sprintf("File %s mimics a WordPress core file inside mu-plugins/ - likely planted backdoor", baseName),
				"mu_core_mimic", models.SeverityCritical, 2.5, 90))
			break
		}
	}

	// Shell functions in an mu-plugins file that lacks a Plugin Name header.
	hasHeader := d.pluginHeaderRe.MatchString(content)
	hasShellFunc := d.shellFuncRe.MatchString(content)
	if hasShellFunc && !hasHeader {
		loc := d.shellFuncRe.FindStringIndex(content)
		findings = append(findings, d.structureFindingWithMatch(file, "WP-STRUCTURE-006",
			"Shell Code in mu-plugins (no Plugin Header)",
			"Auto-loaded must-use plugin without a Plugin Name header contains shell/exec functions - high-risk persistence",
			"mu_shell_no_header", models.SeverityCritical, 2.5, 90, loc[0], content[loc[0]:loc[1]]))
	}

	return findings
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// isCoreFile checks if the path is a WordPress core file that legitimately
// uses sensitive APIs.
func (d *WordPressDetector) isCoreFile(lowerPath string) bool {
	for _, corePath := range d.coreFileWhitelist {
		if strings.HasSuffix(lowerPath, corePath) {
			return true
		}
	}
	return false
}

// isLegitMUDropin reports whether the filename is a known legitimate dropin.
func (d *WordPressDetector) isLegitMUDropin(baseName string) bool {
	for _, name := range d.legitMUDropins {
		if baseName == name {
			return true
		}
	}
	return false
}

// structureFinding builds a non-positional structure finding.
func (d *WordPressDetector) structureFinding(file *models.File, sigID, name, desc, anomaly string,
	sev models.Severity, weight float64, confidence int) *models.Finding {

	riskScore := models.NewRiskScore()
	riskScore.Contexts[models.ContextDefault] = true
	riskScore.TotalWeight = weight
	riskScore.Calculate()

	return &models.Finding{
		File:          file,
		Type:          threatTypeForSeverity(sev),
		Severity:      sev,
		SignatureID:   sigID,
		SignatureName: name,
		Description:   desc,
		Confidence:    confidence,
		RiskScore:     riskScore,
		Timestamp:     time.Now(),
		Metadata: map[string]interface{}{
			"anomaly_type": anomaly,
			"cms":          "wordpress",
		},
	}
}

// structureFindingWithMatch builds a positional structure finding (with snippet).
func (d *WordPressDetector) structureFindingWithMatch(file *models.File, sigID, name, desc, anomaly string,
	sev models.Severity, weight float64, confidence, pos int, snippet string) *models.Finding {

	fragment, lineNumber := signatures.GetFragment(file.Content, pos, 100)
	finding := d.structureFinding(file, sigID, name, desc, anomaly, sev, weight, confidence)
	finding.Position = pos
	finding.LineNumber = lineNumber
	finding.Snippet = snippet
	finding.Fragment = fragment
	return finding
}

// threatTypeForSeverity maps a severity to a representative threat type for
// structure-based findings (which have no signature category of their own).
func threatTypeForSeverity(sev models.Severity) models.ThreatType {
	switch sev {
	case models.SeverityCritical, models.SeverityHigh:
		return models.ThreatPHPBackdoor
	case models.SeverityMedium:
		return models.ThreatPHPSuspicious
	default:
		return models.ThreatSuspicious
	}
}
