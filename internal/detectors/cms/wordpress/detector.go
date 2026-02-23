package wordpress

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/IvanShishkin/houndoom/internal/detectors"
	"github.com/IvanShishkin/houndoom/internal/signatures"
	"github.com/IvanShishkin/houndoom/pkg/models"
)

// WordPressDetector performs WordPress CMS-specific threat detection
type WordPressDetector struct {
	*detectors.BaseDetector
	matcher           *signatures.Matcher
	level             models.SignatureLevel
	falsePositiveHash map[string]bool

	// Category 1: Backdoors
	fakeWPFilePattern    *regexp.Regexp
	evalInjectionPattern *regexp.Regexp
	remoteIncludePattern *regexp.Regexp
	fakePluginPattern    *regexp.Regexp
	adminCreationPattern *regexp.Regexp

	// Category 2: Dangerous API usage
	sqliPattern         *regexp.Regexp
	ssrfPattern         *regexp.Regexp
	unsafeOptionPattern *regexp.Regexp
	callUserFuncPattern *regexp.Regexp

	// Category 3: Auth bypass
	authCookiePattern    *regexp.Regexp
	insertUserPattern    *regexp.Regexp
	capEscalationPattern *regexp.Regexp
	roleEscalationPattern *regexp.Regexp

	// Category 4: Malicious hooks
	initHookRCEPattern     *regexp.Regexp
	headFooterHookPattern  *regexp.Regexp
	contentFilterPattern   *regexp.Regexp
	scheduleEventPattern   *regexp.Regexp
	activationHookPattern  *regexp.Regexp

	// Category 5: Structure anomalies
	uploadsPhpPattern  *regexp.Regexp
	htaccessPattern    *regexp.Regexp
	hiddenPhpPattern   *regexp.Regexp

	// Category 6: Known malware
	wpVCDPattern       *regexp.Regexp
	cryptoMinerPattern *regexp.Regexp
	skimmerPattern     *regexp.Regexp
	pharmaPattern      *regexp.Regexp
	redirectPattern    *regexp.Regexp
	siteurlPattern     *regexp.Regexp
	cloakingPattern    *regexp.Regexp

	// Core file whitelist - paths that legitimately use auth/user functions
	coreFileWhitelist []string
}

// NewWordPressDetector creates a new WordPress-specific detector
func NewWordPressDetector(matcher *signatures.Matcher, level models.SignatureLevel) *WordPressDetector {
	d := &WordPressDetector{
		BaseDetector: detectors.NewBaseDetector("wordpress_cms", 95, []string{
			"php", "php3", "php4", "php5", "php7", "phtml", "pht", "inc",
		}),
		matcher:           matcher,
		level:             level,
		falsePositiveHash: make(map[string]bool),

		// Core file whitelist - WP core files that legitimately use sensitive functions
		coreFileWhitelist: []string{
			"wp-includes/pluggable.php",
			"wp-includes/user.php",
			"wp-includes/class-wp-user.php",
			"wp-includes/capabilities.php",
			"wp-includes/class-wp-roles.php",
			"wp-includes/class-wp-role.php",
			"wp-login.php",
			"wp-admin/includes/user.php",
			"wp-admin/includes/upgrade.php",
			"wp-admin/user-new.php",
			"wp-admin/user-edit.php",
			"wp-includes/ms-functions.php",
			"wp-includes/class-wp-xmlrpc-server.php",
			"wp-includes/rest-api/endpoints/class-wp-rest-users-controller.php",
			"wp-includes/class-wp-customize-manager.php",
			"wp-includes/cron.php",
			"wp-includes/option.php",
			"wp-includes/http.php",
			"wp-includes/class-http.php",
		},
	}

	d.initFalsePositives()
	d.initPatterns()

	return d
}

// initFalsePositives initializes MD5 hashes of known good security plugin files
func (d *WordPressDetector) initFalsePositives() {
	// MD5 hashes of known legitimate security plugin files that contain
	// detection patterns (Wordfence, Sucuri, iThemes Security, etc.)
	falsePositives := []string{
		// Wordfence scanner files
		"a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
		// Sucuri scanner patterns
		"d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1",
	}

	for _, hash := range falsePositives {
		d.falsePositiveHash[hash] = true
	}
}

// initPatterns compiles all regex patterns for each detection category
func (d *WordPressDetector) initPatterns() {
	// Category 1: Backdoors & Web Shells
	d.fakeWPFilePattern = regexp.MustCompile(
		`(?i)(wp-xmlrpc|wp-cron-jobs|wp-vcd|wp-tmp|wp-feed)\.php`)

	d.evalInjectionPattern = regexp.MustCompile(
		`(?i)eval\s*\(\s*(base64_decode|gzinflate|gzuncompress|str_rot13|strrev)\s*\(`)

	d.remoteIncludePattern = regexp.MustCompile(
		`(?i)(include|require|include_once|require_once)\s*\(?\s*['"]https?://`)

	d.fakePluginPattern = regexp.MustCompile(
		`(?i)Plugin Name\s*:`)

	d.adminCreationPattern = regexp.MustCompile(
		`(?i)(wp_create_user|wp_insert_user)\s*\(`)

	// Category 2: Dangerous API usage
	d.sqliPattern = regexp.MustCompile(
		`(?i)\$wpdb\s*->\s*query\s*\([^)]*\$_(GET|POST|REQUEST)\s*\[`)

	d.ssrfPattern = regexp.MustCompile(
		`(?i)wp_remote_(get|post)\s*\([^)]*\$_(GET|POST|REQUEST)\s*\[`)

	d.unsafeOptionPattern = regexp.MustCompile(
		`(?i)(update_option|add_option)\s*\([^)]*\$_(GET|POST|REQUEST)\s*\[`)

	d.callUserFuncPattern = regexp.MustCompile(
		`(?i)call_user_func(_array)?\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)\s*\[`)

	// Category 3: Auth bypass
	d.authCookiePattern = regexp.MustCompile(
		`(?i)wp_set_auth_cookie\s*\(`)

	d.insertUserPattern = regexp.MustCompile(
		`(?i)wp_insert_user\s*\([^)]*['"]role['"]\s*=>\s*['"]administrator['"]`)

	d.capEscalationPattern = regexp.MustCompile(
		`(?i)->add_cap\s*\(\s*['"]`)

	d.roleEscalationPattern = regexp.MustCompile(
		`(?i)->set_role\s*\(\s*['"]administrator['"]\s*\)`)

	// Category 4: Malicious hooks
	d.initHookRCEPattern = regexp.MustCompile(
		`(?i)add_action\s*\(\s*['"]init['"]\s*,\s*function[^}]*\b(eval|system|exec|passthru|shell_exec)\s*\(`)

	d.headFooterHookPattern = regexp.MustCompile(
		`(?i)add_action\s*\(\s*['"](wp_head|wp_footer|admin_init)['"]\s*,\s*function[^}]*\b(eval|base64_decode|gzinflate|file_put_contents|wp_insert_user|wp_set_auth_cookie)\s*\(`)

	d.contentFilterPattern = regexp.MustCompile(
		`(?i)add_filter\s*\(\s*['"]the_content['"]\s*,\s*function[^}]*(eval|base64_decode|<script|<iframe|header\s*\(\s*['"]Location)`)

	d.scheduleEventPattern = regexp.MustCompile(
		`(?i)wp_schedule_event\s*\(`)

	d.activationHookPattern = regexp.MustCompile(
		`(?i)register_activation_hook\s*\([^)]*,\s*function[^}]*\b(eval|system|exec|wp_remote_get|file_get_contents\s*\(\s*['"]https?)\b`)

	// Category 5: Structure anomalies
	d.uploadsPhpPattern = regexp.MustCompile(
		`(?i)wp-content[/\\]uploads[/\\]`)

	d.htaccessPattern = regexp.MustCompile(
		`(?i)(auto_prepend_file|auto_append_file|php_value\s+auto_prepend|php_value\s+auto_append)`)

	d.hiddenPhpPattern = regexp.MustCompile(
		`(?i)[/\\]\.[^/\\]+\.php$`)

	// Category 6: Known malware
	d.wpVCDPattern = regexp.MustCompile(
		`(?i)(WP_CD_CODE|wp-tmp\.php|wp-feed\.php)`)

	d.cryptoMinerPattern = regexp.MustCompile(
		`(?i)(coinhive\.min\.js|CoinHive\.Anonymous|coinhive\.com/lib|` +
			`cryptoloot\.pro|crypto-loot\.com|CryptoLoot\.Anonymous|` +
			`deepMiner|webminerpool|jsecoin\.com|authedmine\.com)`)

	d.skimmerPattern = regexp.MustCompile(
		`(?i)(card.?number|cc.?num|cvv|cvc|expir).{0,50}(XMLHttpRequest|fetch\s*\(|navigator\.sendBeacon)`)

	d.pharmaPattern = regexp.MustCompile(
		`(?i)(viagra|cialis|levitra|pharmacy|pharmacie)\s*</?(a|div|span|h[1-6])`)

	d.redirectPattern = regexp.MustCompile(
		`(?i)(header\s*\(\s*['"]Location\s*:\s*https?://[^'"]*\.(tk|ml|ga|cf|gq)[/'"` + "`" + `]|` +
			`(window\.location|location\.href|location\.replace)\s*=\s*['"]https?://[^'"]*\.(tk|ml|ga|cf|gq)[/'"` + "`" + `])`)

	d.siteurlPattern = regexp.MustCompile(
		`(?i)update_option\s*\(\s*['"](?:siteurl|home)['"]\s*,`)

	d.cloakingPattern = regexp.MustCompile(
		`(?i)(HTTP_USER_AGENT|\$_SERVER\s*\[\s*['"]HTTP_USER_AGENT['"]\s*\])[^;]*(googlebot|bingbot|yahoo|baidu|yandex)`)
}

// Detect performs WordPress-specific threat detection
func (d *WordPressDetector) Detect(ctx context.Context, file *models.File) ([]*models.Finding, error) {
	var findings []*models.Finding

	// Check MD5 false-positive whitelist
	if d.isWhitelisted(file) {
		return findings, nil
	}

	// Determine if file is WP core (to skip API/auth checks on core files)
	isCoreFile := d.isCoreFile(file.Path)

	// 1. Run signature-based detection (YAML matcher)
	sigFindings := d.detectSignatures(file)
	findings = append(findings, sigFindings...)

	// 2. Check structure anomalies (Category 5)
	structFindings := d.detectStructureAnomalies(file)
	findings = append(findings, structFindings...)

	// 3. Detect backdoors (Category 1)
	backdoorFindings := d.detectBackdoors(file)
	findings = append(findings, backdoorFindings...)

	// Skip API/auth/hook checks for core files
	if !isCoreFile {
		// 4. Detect dangerous API usage (Category 2)
		apiFindings := d.detectDangerousAPI(file)
		findings = append(findings, apiFindings...)

		// 5. Detect auth bypass (Category 3)
		authFindings := d.detectAuthBypass(file)
		findings = append(findings, authFindings...)

		// 6. Detect malicious hooks (Category 4)
		hookFindings := d.detectMaliciousHooks(file)
		findings = append(findings, hookFindings...)
	}

	// 7. Detect known malware (Category 6)
	malwareFindings := d.detectKnownMalware(file)
	findings = append(findings, malwareFindings...)

	return findings, nil
}

// isWhitelisted checks if file MD5 is in the false-positive whitelist
func (d *WordPressDetector) isWhitelisted(file *models.File) bool {
	hash := md5.Sum(file.Content)
	hashStr := hex.EncodeToString(hash[:])
	return d.falsePositiveHash[hashStr]
}

// isCoreFile checks if the file is a WordPress core file that legitimately
// uses sensitive functions (auth cookies, user creation, etc.)
func (d *WordPressDetector) isCoreFile(path string) bool {
	normalizedPath := strings.ReplaceAll(path, "\\", "/")
	for _, corePath := range d.coreFileWhitelist {
		if strings.HasSuffix(normalizedPath, corePath) {
			return true
		}
	}
	return false
}

// isSecurityPlugin checks if the file belongs to a known security plugin
func (d *WordPressDetector) isSecurityPlugin(path string) bool {
	securityPlugins := []string{
		"wp-content/plugins/wordfence/",
		"wp-content/plugins/sucuri-scanner/",
		"wp-content/plugins/better-wp-security/",
		"wp-content/plugins/all-in-one-wp-security/",
		"wp-content/plugins/wp-security-audit-log/",
		"wp-content/plugins/anti-malware/",
	}
	normalizedPath := strings.ReplaceAll(path, "\\", "/")
	for _, plugin := range securityPlugins {
		if strings.Contains(normalizedPath, plugin) {
			return true
		}
	}
	return false
}

// detectSignatures runs YAML signature-based detection
func (d *WordPressDetector) detectSignatures(file *models.File) []*models.Finding {
	var findings []*models.Finding

	matches := d.matcher.Match(file.Content, file.Extension, d.level)

	for _, match := range matches {
		// Only process WordPress-specific signatures
		if !strings.HasPrefix(match.Signature.ID, "WP-") {
			continue
		}

		fragment, lineNumber := signatures.GetFragment(file.Content, match.Position, 100)

		riskScore := models.NewRiskScore()
		riskScore.Contexts[models.ContextDefault] = true

		// Weight based on signature category
		switch {
		case strings.Contains(match.Signature.ID, "BACKDOOR") || strings.Contains(match.Signature.ID, "MALWARE-001"):
			riskScore.TotalWeight = 2.5
		case strings.Contains(match.Signature.ID, "SQLI") || strings.Contains(match.Signature.ID, "AUTH"):
			riskScore.TotalWeight = 2.0
		case strings.Contains(match.Signature.ID, "MALWARE"):
			riskScore.TotalWeight = 1.8
		case strings.Contains(match.Signature.ID, "HOOK"):
			riskScore.TotalWeight = 1.5
		default:
			riskScore.TotalWeight = 1.2
		}

		riskScore.Calculate()

		finding := &models.Finding{
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
				"pattern":            match.Signature.Pattern,
				"weight":             riskScore.TotalWeight,
				"cms":                "wordpress",
			},
		}

		findings = append(findings, finding)
	}

	return findings
}

// detectStructureAnomalies checks for WordPress structure violations (Category 5)
func (d *WordPressDetector) detectStructureAnomalies(file *models.File) []*models.Finding {
	var findings []*models.Finding

	normalizedPath := strings.ReplaceAll(file.Path, "\\", "/")

	// Check for PHP files in wp-content/uploads/ (should be media only)
	if d.uploadsPhpPattern.MatchString(normalizedPath) && file.Extension == "php" {
		riskScore := models.NewRiskScore()
		riskScore.TotalWeight = 1.5
		riskScore.Calculate()

		findings = append(findings, &models.Finding{
			File:          file,
			Type:          models.ThreatPHPSuspicious,
			Severity:      models.SeverityHigh,
			SignatureID:   "WP-STRUCTURE-001",
			SignatureName: "PHP File in Uploads Directory",
			Description:   "PHP file found in wp-content/uploads/ - this directory should only contain media files",
			Confidence:    90,
			RiskScore:     riskScore,
			Timestamp:     time.Now(),
			Metadata: map[string]interface{}{
				"anomaly_type": "php_in_uploads",
				"cms":          "wordpress",
			},
		})
	}

	// Check for suspicious .htaccess in wp-admin or wp-includes
	if strings.HasSuffix(file.Name, ".htaccess") {
		isProtectedDir := strings.Contains(normalizedPath, "wp-admin/") ||
			strings.Contains(normalizedPath, "wp-includes/")

		if isProtectedDir {
			content := string(file.Content)
			if d.htaccessPattern.MatchString(content) {
				match := d.htaccessPattern.FindStringIndex(content)
				fragment, lineNumber := signatures.GetFragment(file.Content, match[0], 100)

				riskScore := models.NewRiskScore()
				riskScore.TotalWeight = 2.0
				riskScore.Calculate()

				findings = append(findings, &models.Finding{
					File:          file,
					Type:          models.ThreatPHPBackdoor,
					Severity:      models.SeverityCritical,
					SignatureID:   "WP-STRUCTURE-002",
					SignatureName: "Suspicious .htaccess in Protected Directory",
					Description:   "auto_prepend_file or php_value directive in wp-admin/wp-includes .htaccess - may inject malicious code",
					Position:      match[0],
					LineNumber:    lineNumber,
					Snippet:       content[match[0]:match[1]],
					Fragment:      fragment,
					Confidence:    90,
					RiskScore:     riskScore,
					Timestamp:     time.Now(),
					Metadata: map[string]interface{}{
						"anomaly_type": "suspicious_htaccess",
						"cms":          "wordpress",
					},
				})
			}
		}
	}

	// Check for hidden PHP files (dot-prefixed) in themes/plugins
	if file.Extension == "php" {
		isThemeOrPlugin := strings.Contains(normalizedPath, "wp-content/themes/") ||
			strings.Contains(normalizedPath, "wp-content/plugins/")

		if isThemeOrPlugin && d.hiddenPhpPattern.MatchString(normalizedPath) {
			riskScore := models.NewRiskScore()
			riskScore.TotalWeight = 1.2
			riskScore.Calculate()

			findings = append(findings, &models.Finding{
				File:          file,
				Type:          models.ThreatPHPSuspicious,
				Severity:      models.SeverityMedium,
				SignatureID:   "WP-STRUCTURE-003",
				SignatureName: "Hidden PHP File in Theme/Plugin",
				Description:   "Dot-prefixed (hidden) PHP file found in themes/plugins directory - may be a hidden backdoor",
				Confidence:    75,
				RiskScore:     riskScore,
				Timestamp:     time.Now(),
				Metadata: map[string]interface{}{
					"anomaly_type": "hidden_php_file",
					"cms":          "wordpress",
				},
			})
		}
	}

	// Check for non-standard PHP files in wp-includes/
	if file.Extension == "php" && strings.Contains(normalizedPath, "wp-includes/") {
		// Known fake files that mimic core
		fakeFiles := []string{
			"wp-includes/wp-vcd.php",
			"wp-includes/wp-tmp.php",
			"wp-includes/class-wp-cache.php",
		}
		for _, fake := range fakeFiles {
			if strings.HasSuffix(normalizedPath, fake) {
				riskScore := models.NewRiskScore()
				riskScore.TotalWeight = 2.0
				riskScore.Calculate()

				findings = append(findings, &models.Finding{
					File:          file,
					Type:          models.ThreatPHPBackdoor,
					Severity:      models.SeverityCritical,
					SignatureID:   "WP-STRUCTURE-004",
					SignatureName: "Fake Core File in wp-includes",
					Description:   fmt.Sprintf("Non-standard file %s in wp-includes/ - likely planted backdoor", file.Name),
					Confidence:    90,
					RiskScore:     riskScore,
					Timestamp:     time.Now(),
					Metadata: map[string]interface{}{
						"anomaly_type": "fake_core_file",
						"cms":          "wordpress",
					},
				})
				break
			}
		}
	}

	return findings
}

// detectBackdoors detects WordPress-specific backdoors (Category 1)
func (d *WordPressDetector) detectBackdoors(file *models.File) []*models.Finding {
	var findings []*models.Finding
	content := string(file.Content)

	// Skip security plugins - they contain these patterns as part of their detection
	if d.isSecurityPlugin(file.Path) {
		return findings
	}

	// Check if the file itself is a known fake WP file (path-based check)
	normalizedPath := strings.ReplaceAll(file.Path, "\\", "/")
	fakeFiles := []string{"wp-xmlrpc.php", "wp-cron-jobs.php"}
	for _, fakeBase := range fakeFiles {
		if strings.HasSuffix(normalizedPath, fakeBase) {
			riskScore := models.NewRiskScore()
			riskScore.TotalWeight = 2.5
			riskScore.Calculate()

			findings = append(findings, &models.Finding{
				File:          file,
				Type:          models.ThreatPHPBackdoor,
				Severity:      models.SeverityCritical,
				SignatureID:   "WP-DETECT-FAKEFILE",
				SignatureName: "Fake WordPress Core File",
				Description:   fmt.Sprintf("File %s is not a legitimate WordPress core file - likely backdoor", fakeBase),
				Confidence:    95,
				RiskScore:     riskScore,
				Timestamp:     time.Now(),
				Metadata: map[string]interface{}{
					"fake_file": fakeBase,
					"cms":       "wordpress",
				},
			})
			break
		}
	}

	// Check for eval injection patterns in theme files
	if d.evalInjectionPattern.MatchString(content) {
		normalizedPath := strings.ReplaceAll(file.Path, "\\", "/")
		themeFiles := []string{"functions.php", "header.php", "footer.php", "index.php"}
		isThemeFile := false
		for _, tf := range themeFiles {
			if strings.HasSuffix(normalizedPath, tf) &&
				strings.Contains(normalizedPath, "wp-content/themes/") {
				isThemeFile = true
				break
			}
		}

		if isThemeFile {
			match := d.evalInjectionPattern.FindStringIndex(content)
			fragment, lineNumber := signatures.GetFragment(file.Content, match[0], 100)

			riskScore := models.NewRiskScore()
			riskScore.TotalWeight = 2.5
			riskScore.Calculate()

			findings = append(findings, &models.Finding{
				File:          file,
				Type:          models.ThreatPHPBackdoor,
				Severity:      models.SeverityCritical,
				SignatureID:   "WP-DETECT-EVALTHEME",
				SignatureName: "Eval Injection in WordPress Theme",
				Description:   "Obfuscated eval execution detected in WordPress theme file - strong backdoor indicator",
				Position:      match[0],
				LineNumber:    lineNumber,
				Snippet:       content[match[0]:match[1]],
				Fragment:      fragment,
				Confidence:    95,
				RiskScore:     riskScore,
				Timestamp:     time.Now(),
				Metadata: map[string]interface{}{
					"theme_injection": true,
					"cms":             "wordpress",
				},
			})
		}
	}

	// Check for remote file inclusion
	if d.remoteIncludePattern.MatchString(content) {
		match := d.remoteIncludePattern.FindStringIndex(content)
		fragment, lineNumber := signatures.GetFragment(file.Content, match[0], 100)

		riskScore := models.NewRiskScore()
		riskScore.TotalWeight = 2.5
		riskScore.Calculate()

		findings = append(findings, &models.Finding{
			File:          file,
			Type:          models.ThreatPHPBackdoor,
			Severity:      models.SeverityCritical,
			SignatureID:   "WP-DETECT-RFI",
			SignatureName: "Remote File Inclusion",
			Description:   "Remote URL include/require detected - loads and executes code from external server",
			Position:      match[0],
			LineNumber:    lineNumber,
			Snippet:       content[match[0]:match[1]],
			Fragment:      fragment,
			Confidence:    90,
			RiskScore:     riskScore,
			Timestamp:     time.Now(),
			Metadata: map[string]interface{}{
				"rfi": true,
				"cms": "wordpress",
			},
		})
	}

	// Check for fake plugin with shell functions
	if d.fakePluginPattern.MatchString(content) {
		shellPattern := regexp.MustCompile(`(?i)(system|passthru|shell_exec|exec|popen|proc_open)\s*\(`)
		evalPattern := regexp.MustCompile(`(?i)(eval|assert|create_function)\s*\(`)

		if shellPattern.MatchString(content) {
			match := shellPattern.FindStringIndex(content)
			fragment, lineNumber := signatures.GetFragment(file.Content, match[0], 100)

			riskScore := models.NewRiskScore()
			riskScore.TotalWeight = 2.5
			riskScore.Calculate()

			findings = append(findings, &models.Finding{
				File:          file,
				Type:          models.ThreatPHPShell,
				Severity:      models.SeverityCritical,
				SignatureID:   "WP-DETECT-FAKEPLUGIN-SHELL",
				SignatureName: "Fake Plugin with Shell Execution",
				Description:   "WordPress plugin file contains shell execution functions - likely malicious plugin",
				Position:      match[0],
				LineNumber:    lineNumber,
				Snippet:       content[match[0]:match[1]],
				Fragment:      fragment,
				Confidence:    90,
				RiskScore:     riskScore,
				Timestamp:     time.Now(),
				Metadata: map[string]interface{}{
					"fake_plugin": true,
					"cms":         "wordpress",
				},
			})
		} else if evalPattern.MatchString(content) {
			match := evalPattern.FindStringIndex(content)
			fragment, lineNumber := signatures.GetFragment(file.Content, match[0], 100)

			riskScore := models.NewRiskScore()
			riskScore.TotalWeight = 2.0
			riskScore.Calculate()

			findings = append(findings, &models.Finding{
				File:          file,
				Type:          models.ThreatPHPBackdoor,
				Severity:      models.SeverityCritical,
				SignatureID:   "WP-DETECT-FAKEPLUGIN-EVAL",
				SignatureName: "Fake Plugin with Eval Backdoor",
				Description:   "WordPress plugin file contains eval/assert/create_function - likely malicious plugin",
				Position:      match[0],
				LineNumber:    lineNumber,
				Snippet:       content[match[0]:match[1]],
				Fragment:      fragment,
				Confidence:    85,
				RiskScore:     riskScore,
				Timestamp:     time.Now(),
				Metadata: map[string]interface{}{
					"fake_plugin": true,
					"cms":         "wordpress",
				},
			})
		}
	}

	return findings
}

// detectDangerousAPI detects dangerous WordPress API usage (Category 2)
func (d *WordPressDetector) detectDangerousAPI(file *models.File) []*models.Finding {
	var findings []*models.Finding
	content := string(file.Content)

	// Skip security plugins
	if d.isSecurityPlugin(file.Path) {
		return findings
	}

	type apiCheck struct {
		pattern    *regexp.Regexp
		sigID      string
		name       string
		desc       string
		threatType models.ThreatType
		weight     float64
		confidence int
		level      models.SignatureLevel
	}

	checks := []apiCheck{
		{
			pattern:    d.sqliPattern,
			sigID:      "WP-DETECT-SQLI",
			name:       "SQL Injection via wpdb",
			desc:       "$wpdb->query() with unsanitized user input - SQL injection vulnerability",
			threatType: models.ThreatPHPInjection,
			weight:     2.5,
			confidence: 90,
			level:      models.LevelBasic,
		},
		{
			pattern:    d.ssrfPattern,
			sigID:      "WP-DETECT-SSRF",
			name:       "SSRF via wp_remote_get/post",
			desc:       "WordPress HTTP API called with user-controlled URL - server-side request forgery",
			threatType: models.ThreatVulnerability,
			weight:     1.8,
			confidence: 85,
			level:      models.LevelExpert,
		},
		{
			pattern:    d.unsafeOptionPattern,
			sigID:      "WP-DETECT-UNSAFE-OPTION",
			name:       "Unsafe Option Manipulation",
			desc:       "update_option/add_option with unsanitized user input - site configuration takeover risk",
			threatType: models.ThreatVulnerability,
			weight:     1.8,
			confidence: 85,
			level:      models.LevelBasic,
		},
		{
			pattern:    d.callUserFuncPattern,
			sigID:      "WP-DETECT-CALLUSERFUNC",
			name:       "Dynamic Function Call with User Input",
			desc:       "call_user_func() with user-controlled function name - remote code execution",
			threatType: models.ThreatPHPInjection,
			weight:     2.5,
			confidence: 90,
			level:      models.LevelBasic,
		},
	}

	for _, check := range checks {
		if check.level > d.level {
			continue
		}
		if check.pattern.MatchString(content) {
			match := check.pattern.FindStringIndex(content)
			fragment, lineNumber := signatures.GetFragment(file.Content, match[0], 100)

			riskScore := models.NewRiskScore()
			riskScore.Contexts[models.ContextUserInput] = true
			riskScore.TotalWeight = check.weight
			riskScore.Calculate()

			findings = append(findings, &models.Finding{
				File:          file,
				Type:          check.threatType,
				Severity:      riskScore.GetSeverity(),
				SignatureID:   check.sigID,
				SignatureName: check.name,
				Description:   check.desc + " [WordPress CMS Specific]",
				Position:      match[0],
				LineNumber:    lineNumber,
				Snippet:       content[match[0]:match[1]],
				Fragment:      fragment,
				Confidence:    check.confidence,
				RiskScore:     riskScore,
				Timestamp:     time.Now(),
				Metadata: map[string]interface{}{
					"api_abuse": true,
					"cms":       "wordpress",
				},
			})
		}
	}

	return findings
}

// detectAuthBypass detects authentication/authorization bypass (Category 3)
func (d *WordPressDetector) detectAuthBypass(file *models.File) []*models.Finding {
	var findings []*models.Finding

	if d.level < models.LevelExpert {
		return findings
	}

	content := string(file.Content)

	// Skip security plugins
	if d.isSecurityPlugin(file.Path) {
		return findings
	}

	type authCheck struct {
		pattern    *regexp.Regexp
		sigID      string
		name       string
		desc       string
		weight     float64
		confidence int
	}

	checks := []authCheck{
		{
			pattern:    d.authCookiePattern,
			sigID:      "WP-DETECT-AUTHCOOKIE",
			name:       "Direct Auth Cookie Manipulation",
			desc:       "Direct wp_set_auth_cookie() call - may grant unauthorized session access",
			weight:     2.0,
			confidence: 80,
		},
		{
			pattern:    d.insertUserPattern,
			sigID:      "WP-DETECT-ADMININSERT",
			name:       "Admin Account Creation",
			desc:       "wp_insert_user() creating administrator account - hidden admin user backdoor",
			weight:     2.5,
			confidence: 90,
		},
		{
			pattern:    d.capEscalationPattern,
			sigID:      "WP-DETECT-CAPESCALATION",
			name:       "Capability Escalation",
			desc:       "add_cap() modifying user capabilities - privilege escalation attempt",
			weight:     1.5,
			confidence: 75,
		},
		{
			pattern:    d.roleEscalationPattern,
			sigID:      "WP-DETECT-ROLEESCALATION",
			name:       "Role Escalation to Admin",
			desc:       "set_role('administrator') call - user privilege escalation to admin",
			weight:     2.0,
			confidence: 85,
		},
	}

	for _, check := range checks {
		if check.pattern.MatchString(content) {
			match := check.pattern.FindStringIndex(content)
			fragment, lineNumber := signatures.GetFragment(file.Content, match[0], 100)

			riskScore := models.NewRiskScore()
			riskScore.Contexts[models.ContextDefault] = true
			riskScore.TotalWeight = check.weight
			riskScore.Calculate()

			findings = append(findings, &models.Finding{
				File:          file,
				Type:          models.ThreatPHPBackdoor,
				Severity:      riskScore.GetSeverity(),
				SignatureID:   check.sigID,
				SignatureName: check.name,
				Description:   check.desc + " [WordPress CMS Specific]",
				Position:      match[0],
				LineNumber:    lineNumber,
				Snippet:       content[match[0]:match[1]],
				Fragment:      fragment,
				Confidence:    check.confidence,
				RiskScore:     riskScore,
				Timestamp:     time.Now(),
				Metadata: map[string]interface{}{
					"auth_bypass": true,
					"cms":         "wordpress",
				},
			})
		}
	}

	return findings
}

// detectMaliciousHooks detects malicious WordPress hooks and filters (Category 4)
func (d *WordPressDetector) detectMaliciousHooks(file *models.File) []*models.Finding {
	var findings []*models.Finding
	content := string(file.Content)

	// Skip security plugins
	if d.isSecurityPlugin(file.Path) {
		return findings
	}

	type hookCheck struct {
		pattern    *regexp.Regexp
		sigID      string
		name       string
		desc       string
		threatType models.ThreatType
		weight     float64
		confidence int
		level      models.SignatureLevel
	}

	checks := []hookCheck{
		{
			pattern:    d.initHookRCEPattern,
			sigID:      "WP-DETECT-INITRCE",
			name:       "Init Hook with RCE",
			desc:       "add_action('init') with shell/eval execution - remote code execution via WordPress hook",
			threatType: models.ThreatPHPMalware,
			weight:     2.5,
			confidence: 90,
			level:      models.LevelBasic,
		},
		{
			pattern:    d.headFooterHookPattern,
			sigID:      "WP-DETECT-HOOKINJECTION",
			name:       "Hook-based Code Injection",
			desc:       "WordPress action hook (wp_head/wp_footer/admin_init) with malicious payload",
			threatType: models.ThreatPHPMalware,
			weight:     2.0,
			confidence: 85,
			level:      models.LevelExpert,
		},
		{
			pattern:    d.contentFilterPattern,
			sigID:      "WP-DETECT-CONTENTFILTER",
			name:       "Malicious Content Filter",
			desc:       "add_filter('the_content') injecting malicious code/redirects into page content",
			threatType: models.ThreatPHPMalware,
			weight:     1.8,
			confidence: 85,
			level:      models.LevelExpert,
		},
		{
			pattern:    d.scheduleEventPattern,
			sigID:      "WP-DETECT-SCHEDEVENT",
			name:       "Scheduled Event for Persistence",
			desc:       "wp_schedule_event() call - may be used for malware persistence mechanism",
			threatType: models.ThreatPHPSuspicious,
			weight:     1.0,
			confidence: 60,
			level:      models.LevelExpert,
		},
		{
			pattern:    d.activationHookPattern,
			sigID:      "WP-DETECT-ACTIVATIONHOOK",
			name:       "Malicious Activation Hook",
			desc:       "register_activation_hook() with suspicious code - executes on plugin activation",
			threatType: models.ThreatPHPMalware,
			weight:     1.8,
			confidence: 80,
			level:      models.LevelExpert,
		},
	}

	for _, check := range checks {
		if check.level > d.level {
			continue
		}
		if check.pattern.MatchString(content) {
			match := check.pattern.FindStringIndex(content)
			fragment, lineNumber := signatures.GetFragment(file.Content, match[0], 100)

			riskScore := models.NewRiskScore()
			riskScore.Contexts[models.ContextDefault] = true
			riskScore.TotalWeight = check.weight
			riskScore.Calculate()

			findings = append(findings, &models.Finding{
				File:          file,
				Type:          check.threatType,
				Severity:      riskScore.GetSeverity(),
				SignatureID:   check.sigID,
				SignatureName: check.name,
				Description:   check.desc + " [WordPress CMS Specific]",
				Position:      match[0],
				LineNumber:    lineNumber,
				Snippet:       content[match[0]:match[1]],
				Fragment:      fragment,
				Confidence:    check.confidence,
				RiskScore:     riskScore,
				Timestamp:     time.Now(),
				Metadata: map[string]interface{}{
					"malicious_hook": true,
					"cms":            "wordpress",
				},
			})
		}
	}

	return findings
}

// detectKnownMalware detects known WordPress malware families (Category 6)
func (d *WordPressDetector) detectKnownMalware(file *models.File) []*models.Finding {
	var findings []*models.Finding
	content := string(file.Content)

	type malwareCheck struct {
		pattern    *regexp.Regexp
		sigID      string
		name       string
		desc       string
		threatType models.ThreatType
		weight     float64
		confidence int
		level      models.SignatureLevel
	}

	checks := []malwareCheck{
		{
			pattern:    d.wpVCDPattern,
			sigID:      "WP-DETECT-WPVCD",
			name:       "WP-VCD Malware Family",
			desc:       "wp-vcd malware detected (WP_CD_CODE/wp-tmp.php/wp-feed.php) - known malware family",
			threatType: models.ThreatPHPMalware,
			weight:     2.5,
			confidence: 95,
			level:      models.LevelBasic,
		},
		{
			pattern:    d.cryptoMinerPattern,
			sigID:      "WP-DETECT-MINER",
			name:       "Cryptocurrency Miner",
			desc:       "Cryptocurrency mining script injection (Coinhive/CryptoLoot/etc.)",
			threatType: models.ThreatPHPMalware,
			weight:     2.0,
			confidence: 90,
			level:      models.LevelBasic,
		},
		{
			pattern:    d.skimmerPattern,
			sigID:      "WP-DETECT-SKIMMER",
			name:       "Credit Card Skimmer",
			desc:       "Payment card data exfiltration pattern - credit card skimmer detected",
			threatType: models.ThreatPhishing,
			weight:     2.5,
			confidence: 85,
			level:      models.LevelBasic,
		},
		{
			pattern:    d.pharmaPattern,
			sigID:      "WP-DETECT-PHARMA",
			name:       "Pharma SEO Spam",
			desc:       "Pharmaceutical SEO spam injection (pharma hack) - search engine manipulation",
			threatType: models.ThreatSpam,
			weight:     1.5,
			confidence: 80,
			level:      models.LevelBasic,
		},
		{
			pattern:    d.redirectPattern,
			sigID:      "WP-DETECT-REDIRECT",
			name:       "Malicious Redirect",
			desc:       "Redirect to suspicious TLD (.tk/.ml/.ga/.cf/.gq) - likely malicious redirect",
			threatType: models.ThreatRedirect,
			weight:     1.8,
			confidence: 85,
			level:      models.LevelBasic,
		},
		{
			pattern:    d.siteurlPattern,
			sigID:      "WP-DETECT-SITEURL",
			name:       "Site URL Manipulation",
			desc:       "Direct update of siteurl/home WordPress option - may redirect entire site",
			threatType: models.ThreatRedirect,
			weight:     2.0,
			confidence: 80,
			level:      models.LevelBasic,
		},
		{
			pattern:    d.cloakingPattern,
			sigID:      "WP-DETECT-CLOAKING",
			name:       "User-Agent Cloaking",
			desc:       "Content served conditionally based on search engine user-agent - SEO cloaking",
			threatType: models.ThreatSpam,
			weight:     1.5,
			confidence: 75,
			level:      models.LevelExpert,
		},
	}

	for _, check := range checks {
		if check.level > d.level {
			continue
		}
		if check.pattern.MatchString(content) {
			match := check.pattern.FindStringIndex(content)
			fragment, lineNumber := signatures.GetFragment(file.Content, match[0], 100)

			riskScore := models.NewRiskScore()
			riskScore.Contexts[models.ContextDefault] = true
			riskScore.TotalWeight = check.weight
			riskScore.Calculate()

			findings = append(findings, &models.Finding{
				File:          file,
				Type:          check.threatType,
				Severity:      riskScore.GetSeverity(),
				SignatureID:   check.sigID,
				SignatureName: check.name,
				Description:   check.desc + " [WordPress CMS Specific]",
				Position:      match[0],
				LineNumber:    lineNumber,
				Snippet:       content[match[0]:match[1]],
				Fragment:      fragment,
				Confidence:    check.confidence,
				RiskScore:     riskScore,
				Timestamp:     time.Now(),
				Metadata: map[string]interface{}{
					"known_malware": true,
					"cms":           "wordpress",
				},
			})
		}
	}

	return findings
}
