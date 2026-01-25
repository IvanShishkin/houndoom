package bitrix

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

// BitrixDetector performs Bitrix CMS-specific malware detection
type BitrixDetector struct {
	*detectors.BaseDetector
	matcher           *signatures.Matcher
	level             models.SignatureLevel
	falsePositiveHash map[string]bool
	blacklistPattern  *regexp.Regexp
	wordpressPattern  *regexp.Regexp
	securityWhitelist []string // Bitrix security modules that contain signatures
}

// NewBitrixDetector creates a new Bitrix-specific detector
func NewBitrixDetector(matcher *signatures.Matcher, level models.SignatureLevel) *BitrixDetector {
	detector := &BitrixDetector{
		BaseDetector: detectors.NewBaseDetector("bitrix_cms", 95, []string{
			"php", "php3", "php4", "php5", "php7", "phtml", "pht", "inc",
		}),
		matcher:           matcher,
		level:             level,
		falsePositiveHash: make(map[string]bool),
		// Whitelist Bitrix security modules that contain malware signatures
		// These files have blacklist patterns as part of their detection logic
		securityWhitelist: []string{
			"modules/security/classes/general/xscan.php",
			"modules/security/admin/security_file_verifier.php",
			"modules/scale/lib/shelladapter.php",
		},
	}

	// Initialize false-positive MD5 hashes from Bitrix XScan
	detector.initFalsePositives()

	// Initialize blacklist patterns
	detector.initBlacklists()

	return detector
}

// Detect performs Bitrix-specific malware detection
func (d *BitrixDetector) Detect(ctx context.Context, file *models.File) ([]*models.Finding, error) {
	var findings []*models.Finding

	// Check if file is in false-positive whitelist
	if d.isWhitelisted(file) {
		return findings, nil
	}

	// 1. Check for dangerous Bitrix methods
	methodFindings := d.detectDangerousMethods(file)
	findings = append(findings, methodFindings...)

	// 2. Check for WordPress files in Bitrix project (sign of compromise)
	wpFindings := d.detectWordPressInBitrix(file)
	findings = append(findings, wpFindings...)

	// 3. Check for blacklisted patterns
	blacklistFindings := d.detectBlacklistPatterns(file)
	findings = append(findings, blacklistFindings...)

	// 4. Check Bitrix structure violations
	structureFindings := d.checkBitrixStructure(file)
	findings = append(findings, structureFindings...)

	return findings, nil
}

// initFalsePositives initializes the false-positive MD5 hash database
// Based on Bitrix XScan false_positives constant (32 hashes)
func (d *BitrixDetector) initFalsePositives() {
	// From ref_bitrix/security/classes/general/xscan.php lines 36-41
	falsePositives := []string{
		"9223e925409363b7db262cfea1b6a7e2",
		"4d2cb64743ff3647bad4dea540d5b08e",
		"d40c4da27ce1860c111fc0e68a4b39b5",
		"ef9287187dc22a6ce47476fd80720878",
		"13484affcdf9f45d29b61d732f8a5855",
		"4a171d5dc7381cce26227c5d83b5ba0c",
		"b41d3b390f0f5ac060f9819e40bda7eb",
		"40142320d26a29586dc8528cfb183aac",
		"f454f39a15ec9240d93df67536372c1b",
		"29bba835e33ab80598f88e438857f342",
		"77cdd8164d4940cb6bfaac906383a766",
		"4c92c1e6518d05096f0f6b5ad5dcd589",
		"50ca067b97cc036b63e0a27c19ec896f",
		"e57ac2b7e89114c518bec63444e21fc2",
		"66cdfdb8bc9e718bf007f3ab6ba98ba3",
		"9c38c47adf1a6a8e18c0b17fef59cfdc",
		"3c66eb345b61e43cd2a3fc2f625cb979",
		"21e6f24d144ef1b2c8c4eff23ee5eea4",
		"ea13c90de6d582ed13dcd84f6b137095",
		"fafd988dbd1076ae1eac7f5b73d64f94",
		"9f29b09a89b0eaf1f37760e047bc7b4f",
		"b4c78a2b3bedf3e7975d3a0ddaafdf2f",
		"1a6f17bf35b6e72d80d45c1d33dc5580",
		"a85abce54b4deb8cb157438dddca5a7c",
		"de4f7ee97d421cf14d3951c0b4e5c2dd",
		"379918e8f6486ce9a7bb2ed5a69dbee6",
		"7ac4a2afcee04e683b092eb9402ee7ed",
		"1d5eb769111fc9c7be2021300ee5740e",
		"f2357a1fe8e984052b6ee69933d467dc",
		"a9158139e1a619ca8cc320cf4469c250",
	}

	for _, hash := range falsePositives {
		d.falsePositiveHash[hash] = true
	}
}

// initBlacklists initializes blacklist patterns from Bitrix XScan
func (d *BitrixDetector) initBlacklists() {
	// Combined blacklist pattern for suspicious strings
	// Note: password_verify removed - it's a standard safe PHP function
	d.blacklistPattern = regexp.MustCompile(
		`(?i)(https?://[0-9a-z\-]+\.pw/|` + // .pw domain attacks
			`https?://(?:sw\.)?bitrix\.dev|` + // Fake bitrix.dev domains
			`wp-config\.php|/wp-admin/|wp-login\.php|` + // WordPress files in Bitrix (with path context)
			`deprecated-media-js|customize-menus-rtl|` + // WP JS files (known malicious)
			`adminer_errors|` + // Adminer tool
			`/etc/passwd|/etc/hosts|` + // System file access
			`__halt_compiler|` + // PHP obfuscation technique
			`/bin/sh|/bin/bash|` + // Shell access
			`registerPHPFunctions)`, // XML external entity vuln
	)

	// Specific WordPress detection pattern
	// Require path context (/ or .php) to avoid false positives like fa-wordpress icons
	d.wordpressPattern = regexp.MustCompile(`(?i)(wp-config\.php|/wp-admin/|/wp-admin\b|wp-login\.php|/wp-content/|/wp-includes/)`)
}

// isWhitelisted checks if file is in the false-positive whitelist
func (d *BitrixDetector) isWhitelisted(file *models.File) bool {
	hash := md5.Sum(file.Content)
	hashStr := hex.EncodeToString(hash[:])
	return d.falsePositiveHash[hashStr]
}

// detectDangerousMethods detects dangerous Bitrix methods using signature matcher
func (d *BitrixDetector) detectDangerousMethods(file *models.File) []*models.Finding {
	var findings []*models.Finding

	// Use signature matcher for Bitrix methods
	matches := d.matcher.Match(file.Content, file.Extension, d.level)

	for _, match := range matches {
		// Only process Bitrix-specific signatures
		if !strings.HasPrefix(match.Signature.ID, "BITRIX-") {
			continue
		}

		fragment, lineNumber := signatures.GetFragment(file.Content, match.Position, 100)

		// Create risk score for this finding
		riskScore := models.NewRiskScore()
		riskScore.Contexts[models.ContextDefault] = true

		// Dangerous Bitrix methods always get high weight
		if strings.Contains(match.Signature.ID, "RCE") || strings.Contains(match.Signature.ID, "AUTH") {
			riskScore.TotalWeight = 2.5 // Critical
		} else if strings.Contains(match.Signature.ID, "SQLI") {
			riskScore.TotalWeight = 1.8 // High
		} else {
			riskScore.TotalWeight = 1.2 // Medium-High
		}

		riskScore.Calculate()

		finding := &models.Finding{
			File:          file,
			Type:          match.Signature.Category,
			Severity:      riskScore.GetSeverity(),
			SignatureID:   match.Signature.ID,
			SignatureName: match.Signature.Name,
			Description:   match.Signature.Description + " [Bitrix CMS Specific]",
			Position:      match.Position,
			LineNumber:    lineNumber,
			Snippet:       match.Matched,
			Fragment:      fragment,
			Confidence:    95, // High confidence for known dangerous methods
			RiskScore:     riskScore,
			Timestamp:     time.Now(),
			Metadata: map[string]interface{}{
				"bitrix_method": true,
				"pattern":       match.Signature.Pattern,
				"weight":        riskScore.TotalWeight,
				"cms":           "bitrix",
			},
		}

		findings = append(findings, finding)
	}

	return findings
}

// detectWordPressInBitrix detects WordPress files in Bitrix projects (compromise indicator)
func (d *BitrixDetector) detectWordPressInBitrix(file *models.File) []*models.Finding {
	var findings []*models.Finding

	content := string(file.Content)

	// Check if this looks like a Bitrix project
	isBitrixProject := strings.Contains(file.Path, "/bitrix/") ||
		strings.Contains(file.Path, "\\bitrix\\")

	if !isBitrixProject {
		return findings
	}

	// Check for WordPress patterns
	if d.wordpressPattern.MatchString(content) {
		matches := d.wordpressPattern.FindAllStringIndex(content, -1)

		for _, match := range matches {
			fragment, lineNumber := signatures.GetFragment(file.Content, match[0], 100)

			riskScore := models.NewRiskScore()
			riskScore.TotalWeight = 2.0 // High risk - indicates compromise
			riskScore.Calculate()

			finding := &models.Finding{
				File:          file,
				Type:          models.ThreatPHPBackdoor,
				Severity:      models.SeverityHigh,
				SignatureID:   "BITRIX-COMPROMISE-001",
				SignatureName: "WordPress Files in Bitrix Project",
				Description:   "WordPress files detected in Bitrix project - strong indicator of compromise or backdoor",
				Position:      match[0],
				LineNumber:    lineNumber,
				Snippet:       content[match[0]:match[1]],
				Fragment:      fragment,
				Confidence:    90,
				RiskScore:     riskScore,
				Timestamp:     time.Now(),
				Metadata: map[string]interface{}{
					"bitrix_compromise": true,
					"wordpress_pattern": true,
					"cms":               "bitrix",
				},
			}

			findings = append(findings, finding)
		}
	}

	return findings
}

// isSecurityModule checks if file is a whitelisted Bitrix security module
func (d *BitrixDetector) isSecurityModule(path string) bool {
	for _, pattern := range d.securityWhitelist {
		if strings.Contains(path, pattern) {
			return true
		}
	}
	return false
}

// detectBlacklistPatterns detects blacklisted patterns from Bitrix XScan
func (d *BitrixDetector) detectBlacklistPatterns(file *models.File) []*models.Finding {
	var findings []*models.Finding

	// Skip Bitrix security modules - they contain these patterns as signatures
	if d.isSecurityModule(file.Path) {
		return findings
	}

	content := string(file.Content)

	if d.blacklistPattern.MatchString(content) {
		matches := d.blacklistPattern.FindAllStringSubmatchIndex(content, -1)

		for _, match := range matches {
			if len(match) < 2 {
				continue
			}

			matchedText := content[match[0]:match[1]]
			fragment, lineNumber := signatures.GetFragment(file.Content, match[0], 100)

			riskScore := models.NewRiskScore()
			riskScore.TotalWeight = 1.5
			riskScore.Calculate()

			finding := &models.Finding{
				File:          file,
				Type:          models.ThreatPHPSuspicious,
				Severity:      riskScore.GetSeverity(),
				SignatureID:   "BITRIX-BLACKLIST-001",
				SignatureName: "Bitrix Blacklist Pattern",
				Description:   fmt.Sprintf("Detected blacklisted pattern: %s", matchedText),
				Position:      match[0],
				LineNumber:    lineNumber,
				Snippet:       matchedText,
				Fragment:      fragment,
				Confidence:    85,
				RiskScore:     riskScore,
				Timestamp:     time.Now(),
				Metadata: map[string]interface{}{
					"blacklist_pattern": matchedText,
					"cms":               "bitrix",
				},
			}

			findings = append(findings, finding)
		}
	}

	return findings
}

// bitrixAccessFilePattern matches legitimate Bitrix .access.php content
// Format: <?$PERM["hash"]["group"]="permission";?> or <?php $PERM[...]=...;
var bitrixAccessFilePattern = regexp.MustCompile(`(?s)^<\?(?:php)?\s*\$PERM\s*\[["'][a-f0-9]+["']\]\s*\[["'][^"']*["']\]\s*=\s*["'][A-Z]+["']\s*;?\s*\?>?\s*$`)

// isLegitimateAccessFile checks if file is a standard Bitrix .access.php
// These files only contain $PERM array assignments for access control
func isLegitimateAccessFile(file *models.File) bool {
	// Must be named .access.php
	if !strings.HasSuffix(file.Path, ".access.php") {
		return false
	}

	// Check content - must match Bitrix access control pattern only
	content := strings.TrimSpace(string(file.Content))
	if len(content) == 0 {
		return true // Empty .access.php is also legitimate
	}

	// Check if content is ONLY $PERM assignments (no other code)
	return bitrixAccessFilePattern.MatchString(content)
}

// checkBitrixStructure checks for Bitrix-specific structure violations
func (d *BitrixDetector) checkBitrixStructure(file *models.File) []*models.Finding {
	var findings []*models.Finding

	// Check if file is in suspicious location for Bitrix
	// Note: /bitrix/cache/ is excluded - Bitrix stores cache as PHP files by design
	// Note: /bitrix/backup/index.php is standard, only flag other PHP files there
	suspiciousLocations := []struct {
		pattern     string
		description string
	}{
		{"/upload/", "Suspicious PHP file in upload directory"},
	}

	for _, loc := range suspiciousLocations {
		if strings.Contains(file.Path, loc.pattern) && file.Extension == "php" {
			// Skip legitimate .access.php files (Bitrix access control)
			if isLegitimateAccessFile(file) {
				continue
			}
			riskScore := models.NewRiskScore()
			riskScore.TotalWeight = 1.0
			riskScore.Calculate()

			finding := &models.Finding{
				File:          file,
				Type:          models.ThreatPHPSuspicious,
				Severity:      models.SeverityMedium,
				SignatureID:   "BITRIX-STRUCTURE-001",
				SignatureName: "Suspicious File Location",
				Description:   loc.description,
				Confidence:    70,
				RiskScore:     riskScore,
				Timestamp:     time.Now(),
				Metadata: map[string]interface{}{
					"suspicious_location": loc.pattern,
					"cms":                 "bitrix",
				},
			}

			findings = append(findings, finding)
			break // Only report once per file
		}
	}

	return findings
}
