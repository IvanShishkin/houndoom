package php

import (
	"context"
	"regexp"
	"strings"
	"time"

	"github.com/IvanShishkin/houndoom/internal/detectors"
	"github.com/IvanShishkin/houndoom/internal/signatures"
	"github.com/IvanShishkin/houndoom/pkg/models"
)

// Injection patterns for various vulnerability types
var injectionPatterns = []struct {
	pattern     string
	name        string
	description string
	severity    models.Severity
	threatType  models.ThreatType
}{
	// SQL Injection
	{
		pattern:     `(?i)(?:mysql_query|mysqli_query|pg_query|sqlite_query)\s*\([^)]*\$_(GET|POST|REQUEST|COOKIE)`,
		name:        "SQL Injection via User Input",
		description: "Direct user input in SQL query without proper escaping",
		severity:    models.SeverityCritical,
		threatType:  models.ThreatPHPInjection,
	},
	{
		pattern:     `(?i)\$\w+->query\s*\([^)]*\.\s*\$_(GET|POST|REQUEST)`,
		name:        "PDO/MySQLi Query Injection",
		description: "User input concatenated into database query",
		severity:    models.SeverityCritical,
		threatType:  models.ThreatPHPInjection,
	},
	// Code Injection - only flag when user input is directly used
	{
		pattern:     `(?i)\beval\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)\s*\[`,
		name:        "Eval Code Injection",
		description: "User input passed directly to eval() - code injection vulnerability",
		severity:    models.SeverityCritical,
		threatType:  models.ThreatPHPInjection,
	},
	{
		pattern:     `(?i)\bassert\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)\s*\[`,
		name:        "Assert Code Injection",
		description: "User input passed to assert() - can execute arbitrary code",
		severity:    models.SeverityHigh,
		threatType:  models.ThreatPHPInjection,
	},
	{
		// Pattern matches preg_replace with /e modifier before closing quote
		// Uses [^'"]+ to capture entire regex pattern including escaped slashes
		pattern:     `(?i)\bpreg_replace\s*\(\s*['"]/[^'"]+/[imsxADSUXJu]*e[imsxADSUXJu]*['"]`,
		name:        "Preg Replace /e Injection",
		description: "preg_replace with /e modifier allows code execution",
		severity:    models.SeverityCritical,
		threatType:  models.ThreatPHPInjection,
	},
	// Local/Remote File Inclusion
	{
		pattern:     `(?i)\b(?:include|require|include_once|require_once)\s*\(\s*\$_(GET|POST|REQUEST)`,
		name:        "Direct LFI/RFI Vulnerability",
		description: "User input directly used in include/require - file inclusion vulnerability",
		severity:    models.SeverityCritical,
		threatType:  models.ThreatPHPInjection,
	},
	{
		pattern:     `(?i)\b(?:include|require|include_once|require_once)\s*\(\s*\$\w+\s*\.\s*\$_(GET|POST|REQUEST)`,
		name:        "Path Concatenation LFI",
		description: "User input concatenated into include path",
		severity:    models.SeverityHigh,
		threatType:  models.ThreatPHPInjection,
	},
	// Command Injection
	{
		pattern:     `(?i)\b(?:system|exec|shell_exec|passthru|popen|proc_open)\s*\([^)]*\$_(GET|POST|REQUEST)`,
		name:        "Command Injection",
		description: "User input in command execution function",
		severity:    models.SeverityCritical,
		threatType:  models.ThreatPHPInjection,
	},
	{
		pattern:     `(?i)\bexec\s*\(\s*['"].*\$_(GET|POST|REQUEST|COOKIE)`,
		name:        "User Input in Exec",
		description: "User input interpolated in command string",
		severity:    models.SeverityCritical,
		threatType:  models.ThreatPHPInjection,
	},
	// Object Injection
	// Note: allowed_classes => false (PHP 7+) prevents object instantiation
	// Post-filtering in Detect() excludes safe patterns
	{
		pattern:     `(?i)\bunserialize\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)\s*\[`,
		name:        "Object Injection",
		description: "Unserialize of user input - PHP object injection vulnerability",
		severity:    models.SeverityCritical,
		threatType:  models.ThreatPHPInjection,
	},
	// XPath Injection
	{
		pattern:     `(?i)->xpath\s*\([^)]*\$_(GET|POST|REQUEST)`,
		name:        "XPath Injection",
		description: "User input in XPath query",
		severity:    models.SeverityHigh,
		threatType:  models.ThreatPHPInjection,
	},
	// LDAP Injection
	{
		pattern:     `(?i)\bldap_search\s*\([^)]*\$_(GET|POST|REQUEST)`,
		name:        "LDAP Injection",
		description: "User input in LDAP search query",
		severity:    models.SeverityHigh,
		threatType:  models.ThreatPHPInjection,
	},
	// Header Injection
	{
		pattern:     `(?i)\bheader\s*\(\s*['"]\s*Location\s*:\s*['"]\s*\.\s*\$_(GET|POST|REQUEST)`,
		name:        "Open Redirect",
		description: "User-controlled redirect URL - open redirect vulnerability",
		severity:    models.SeverityMedium,
		threatType:  models.ThreatRedirect,
	},
	{
		pattern:     `(?i)\bheader\s*\([^)]*\$_(GET|POST|REQUEST)`,
		name:        "Header Injection",
		description: "User input in HTTP header - potential header injection",
		severity:    models.SeverityHigh,
		threatType:  models.ThreatPHPInjection,
	},
	// File Operations
	{
		pattern:     `(?i)\bfile_put_contents\s*\(\s*\$_(GET|POST|REQUEST)`,
		name:        "Arbitrary File Write",
		description: "User-controlled filename in file write operation",
		severity:    models.SeverityCritical,
		threatType:  models.ThreatPHPInjection,
	},
	{
		pattern:     `(?i)\bunlink\s*\(\s*\$_(GET|POST|REQUEST)`,
		name:        "Arbitrary File Delete",
		description: "User-controlled filename in file deletion",
		severity:    models.SeverityCritical,
		threatType:  models.ThreatPHPInjection,
	},
}

// InjectionDetector detects code injection vulnerabilities
type InjectionDetector struct {
	*detectors.BaseDetector
	matcher          *signatures.Matcher
	level            models.SignatureLevel
	compiledPatterns []struct {
		regex       *regexp.Regexp
		name        string
		description string
		severity    models.Severity
		threatType  models.ThreatType
	}
}

// NewInjectionDetector creates a new PHP injection detector
func NewInjectionDetector(matcher *signatures.Matcher, level models.SignatureLevel) *InjectionDetector {
	d := &InjectionDetector{
		BaseDetector: detectors.NewBaseDetector("php_injection", 98, []string{
			"php", "php3", "php4", "php5", "php7", "phtml", "pht", "inc",
		}),
		matcher: matcher,
		level:   level,
	}

	// Compile patterns
	for _, p := range injectionPatterns {
		compiled := struct {
			regex       *regexp.Regexp
			name        string
			description string
			severity    models.Severity
			threatType  models.ThreatType
		}{
			regex:       regexp.MustCompile(p.pattern),
			name:        p.name,
			description: p.description,
			severity:    p.severity,
			threatType:  p.threatType,
		}
		d.compiledPatterns = append(d.compiledPatterns, compiled)
	}

	return d
}

// safeUnserializePattern matches allowed_classes => false which makes unserialize safe
var safeUnserializePattern = regexp.MustCompile(`(?i)allowed_classes['\"]?\s*=>\s*false`)

// isSafeUnserialize checks if unserialize call has allowed_classes => false
func isSafeUnserialize(content string, matchPos int) bool {
	// Look at the next 200 characters after the match to find the closing );
	end := matchPos + 200
	if end > len(content) {
		end = len(content)
	}
	// Find the statement end (semicolon)
	snippet := content[matchPos:end]
	semicolonPos := strings.Index(snippet, ";")
	if semicolonPos > 0 {
		snippet = snippet[:semicolonPos]
	}
	return safeUnserializePattern.MatchString(snippet)
}

// isMethodCall checks if the match is a method call (->func or ::func) rather than a function call
// This prevents false positives like $obj->exec() being flagged as command injection
func isMethodCall(content string, matchPos int) bool {
	// Look at characters before the match to check for -> or ::
	if matchPos < 2 {
		return false
	}
	// Check up to 3 characters before (for "->", "::", or whitespace before them)
	start := matchPos - 3
	if start < 0 {
		start = 0
	}
	prefix := content[start:matchPos]
	return strings.Contains(prefix, "->") || strings.Contains(prefix, "::")
}

// isLanguageFile checks if file is in a language/translation directory
// Language files contain code examples in documentation, not actual code
func isLanguageFile(path string) bool {
	return strings.Contains(path, "/lang/") || strings.Contains(path, "\\lang\\")
}

// securityModulePatterns - Bitrix/CMS security modules that legitimately use
// patterns like header() with user input (properly sanitized through framework methods)
var securityModulePatterns = []string{
	"modules/security/admin/",
	"modules/security/classes/",
	"modules\\security\\admin\\",
	"modules\\security\\classes\\",
}

// isSecurityModule checks if file is a CMS security module
// These modules often have sanitized user input in headers for downloads, etc.
func isSecurityModule(path string) bool {
	for _, pattern := range securityModulePatterns {
		if strings.Contains(path, pattern) {
			return true
		}
	}
	return false
}

// Detect scans a file for injection vulnerabilities
func (d *InjectionDetector) Detect(ctx context.Context, file *models.File) ([]*models.Finding, error) {
	var findings []*models.Finding

	// Skip language/translation files - they contain code examples in docs, not real code
	if isLanguageFile(file.Path) {
		return findings, nil
	}

	content := string(file.Content)

	// 1. Check for injection patterns
	for _, pattern := range d.compiledPatterns {
		matches := pattern.regex.FindAllStringIndex(content, -1)
		for _, match := range matches {
			// Skip safe unserialize patterns with allowed_classes => false
			if pattern.name == "Object Injection" && isSafeUnserialize(content, match[0]) {
				continue
			}

			// Skip method calls for command injection patterns
			// e.g., $obj->exec() is a method call, not the exec() function
			if (pattern.name == "Command Injection" || pattern.name == "User Input in Exec") &&
				isMethodCall(content, match[0]) {
				continue
			}

			// Skip header injection in security modules - they use sanitization methods
			if pattern.name == "Header Injection" && isSecurityModule(file.Path) {
				continue
			}

			fragment, lineNumber := signatures.GetFragment(file.Content, match[0], 120)
			matched := content[match[0]:match[1]]

			findings = append(findings, &models.Finding{
				File:          file,
				Type:          pattern.threatType,
				Severity:      pattern.severity,
				SignatureID:   "INJECTION-" + sanitizeID(pattern.name),
				SignatureName: pattern.name,
				Description:   pattern.description,
				Position:      match[0],
				LineNumber:    lineNumber,
				Snippet:       truncate(matched, 100),
				Fragment:      fragment,
				Confidence:    calculateInjectionConfidence(pattern.severity),
				Timestamp:     time.Now(),
				Metadata: map[string]any{
					"detector": "injection_heuristic",
					"category": string(pattern.threatType),
				},
			})
		}
	}

	// 2. Match signatures from database (filter by injection category)
	matches := d.matcher.Match(file.Content, file.Extension, d.level)
	for _, match := range matches {
		if match.Signature.Category != models.ThreatPHPInjection {
			continue
		}

		fragment, lineNumber := signatures.GetFragment(file.Content, match.Position, 100)

		findings = append(findings, &models.Finding{
			File:          file,
			Type:          match.Signature.Category,
			Severity:      match.Signature.Severity,
			SignatureID:   match.Signature.ID,
			SignatureName: match.Signature.Name,
			Description:   match.Signature.Description,
			Position:      match.Position,
			LineNumber:    lineNumber,
			Snippet:       match.Matched,
			Fragment:      fragment,
			Confidence:    70 + severityBonus(match.Signature.Severity),
			Timestamp:     time.Now(),
			Metadata: map[string]any{
				"pattern":  match.Signature.Pattern,
				"is_regex": match.Signature.IsRegex,
				"detector": "injection_signature",
			},
		})
	}

	return findings, nil
}

// sanitizeID creates a valid ID from a name
func sanitizeID(name string) string {
	result := ""
	for _, c := range name {
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') {
			result += string(c)
		} else if c == ' ' || c == '-' || c == '_' {
			result += "-"
		}
	}
	return result
}

// truncate truncates a string to max length
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// calculateInjectionConfidence returns confidence based on severity
func calculateInjectionConfidence(severity models.Severity) int {
	switch severity {
	case models.SeverityCritical:
		return 95
	case models.SeverityHigh:
		return 85
	case models.SeverityMedium:
		return 75
	default:
		return 65
	}
}

// severityBonus returns bonus confidence based on severity
func severityBonus(severity models.Severity) int {
	switch severity {
	case models.SeverityCritical:
		return 25
	case models.SeverityHigh:
		return 15
	case models.SeverityMedium:
		return 5
	default:
		return 0
	}
}
