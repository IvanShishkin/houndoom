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

// Common backdoor shells signatures
// Note: Short patterns like "c99" cause false positives in cache files (e.g., hashes containing "c99")
// Using more specific patterns to reduce false positives
var shellSignatures = []string{
	// c99 shell variants - require context (shell/sh suffix or variable prefix)
	"c99shell", "c99sh", "c99_", "$c99",
	// r57 shell variants
	"r57shell", "r57sh", "r57_", "$r57",
	// Other known shells - these are specific enough
	"wso_version", "wsoshell", "wso2_",
	"b374k", "weevely", "alfa_", "alfashell",
	"indoxploit", "priv8", "filesman",
	"adminer", "phpspy", "antichat",
}

// Suspicious function combinations that indicate backdoors
// Note: These patterns must be directly connected (same expression) to avoid false positives
var suspiciousCombinations = []struct {
	patterns []string
	name     string
	desc     string
}{
	{
		// eval() with user input directly inside: eval($_GET['x']) or eval($_POST['cmd'])
		patterns: []string{`\beval\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\s*\[`},
		name:     "User Input to Eval",
		desc:     "Direct user input passed to eval() function",
	},
	{
		// Command execution with user input directly: system($_GET['cmd'])
		patterns: []string{`\b(?:system|exec|passthru|shell_exec|popen|proc_open)\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\s*\[`},
		name:     "User Input to Command Execution",
		desc:     "User input directly passed to command execution function",
	},
	{
		// eval(base64_decode(...)) pattern
		patterns: []string{`\beval\s*\(\s*base64_decode\s*\(`},
		name:     "Base64 Eval Execution",
		desc:     "Base64 decoded content executed via eval",
	},
	{
		// eval(gzinflate(base64_decode(...))) - common obfuscation
		patterns: []string{`\beval\s*\(\s*(?:gzinflate|gzuncompress|gzdecode)\s*\(\s*base64_decode`},
		name:     "Obfuscated Eval Execution",
		desc:     "Compressed and encoded content executed via eval",
	},
	{
		// assert() with user input - dangerous in older PHP
		patterns: []string{`\bassert\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\s*\[`},
		name:     "Assert Code Execution",
		desc:     "User input passed to assert() function",
	},
	{
		// create_function with user input
		patterns: []string{`\bcreate_function\s*\([^)]*\$_(?:GET|POST|REQUEST|COOKIE)`},
		name:     "Create Function Backdoor",
		desc:     "User input used in create_function()",
	},
}

// BackdoorDetector detects PHP backdoors and web shells
type BackdoorDetector struct {
	*detectors.BaseDetector
	matcher            *signatures.Matcher
	level              models.SignatureLevel
	compiledShellRegex *regexp.Regexp
	compiledCombos     []struct {
		patterns []*regexp.Regexp
		name     string
		desc     string
	}
}

// NewBackdoorDetector creates a new PHP backdoor detector
func NewBackdoorDetector(matcher *signatures.Matcher, level models.SignatureLevel) *BackdoorDetector {
	d := &BackdoorDetector{
		BaseDetector: detectors.NewBaseDetector("php_backdoor", 95, []string{
			"php", "php3", "php4", "php5", "php7", "phtml", "pht", "inc",
		}),
		matcher: matcher,
		level:   level,
	}

	// Compile shell signatures regex
	shellPattern := `(?i)\b(` + strings.Join(shellSignatures, "|") + `)\b`
	d.compiledShellRegex = regexp.MustCompile(shellPattern)

	// Compile combination patterns
	for _, combo := range suspiciousCombinations {
		compiled := struct {
			patterns []*regexp.Regexp
			name     string
			desc     string
		}{
			name: combo.name,
			desc: combo.desc,
		}
		for _, p := range combo.patterns {
			re := regexp.MustCompile(`(?i)` + p)
			compiled.patterns = append(compiled.patterns, re)
		}
		d.compiledCombos = append(d.compiledCombos, compiled)
	}

	return d
}

// isMethodCallAtPosition checks if the match is a method call (->func or ::func)
// This prevents false positives like $obj->exec() being flagged as command execution
func isMethodCallAtPosition(content string, matchPos int) bool {
	if matchPos < 2 {
		return false
	}
	start := matchPos - 3
	if start < 0 {
		start = 0
	}
	prefix := content[start:matchPos]
	return strings.Contains(prefix, "->") || strings.Contains(prefix, "::")
}

// isCacheDirectory checks if file is in a cache directory (high false positive rate)
func isCacheDirectory(path string) bool {
	cachePatterns := []string{
		"/cache/", "\\cache\\",
		"/bitrix/cache/", "\\bitrix\\cache\\",
		"/wp-content/cache/", "\\wp-content\\cache\\",
		"/tmp/", "\\tmp\\",
	}
	pathLower := strings.ToLower(path)
	for _, pattern := range cachePatterns {
		if strings.Contains(pathLower, pattern) {
			return true
		}
	}
	return false
}

// Detect scans a file for PHP backdoors
func (d *BackdoorDetector) Detect(ctx context.Context, file *models.File) ([]*models.Finding, error) {
	var findings []*models.Finding
	content := string(file.Content)

	// Skip shell signature detection for cache directories (high false positive rate)
	// Cache files often contain hashes that match short patterns
	isCache := isCacheDirectory(file.Path)

	// 1. Check for known shell signatures (skip for cache files)
	if !isCache {
		if matches := d.compiledShellRegex.FindAllStringIndex(content, -1); matches != nil {
			for _, match := range matches {
				fragment, lineNumber := signatures.GetFragment(file.Content, match[0], 100)
				matched := content[match[0]:match[1]]

				findings = append(findings, &models.Finding{
					File:          file,
					Type:          models.ThreatPHPBackdoor,
					Severity:      models.SeverityCritical,
					SignatureID:   "BACKDOOR-SHELL",
					SignatureName: "Known Web Shell Signature",
					Description:   "Detected known web shell identifier: " + matched,
					Position:      match[0],
					LineNumber:    lineNumber,
					Snippet:       matched,
					Fragment:      fragment,
					Confidence:    95,
					Timestamp:     time.Now(),
					Metadata: map[string]any{
						"shell_type": matched,
						"detector":   "backdoor_heuristic",
					},
				})
			}
		}
	}

	// 2. Check for suspicious function combinations
	for _, combo := range d.compiledCombos {
		allMatch := true
		var positions []int

		for _, pattern := range combo.patterns {
			if match := pattern.FindStringIndex(content); match != nil {
				positions = append(positions, match[0])
			} else {
				allMatch = false
				break
			}
		}

		if allMatch && len(positions) > 0 {
			// Use the first match position for the finding
			pos := positions[0]

			// Skip method calls for command execution patterns
			// e.g., $obj->exec() is a method call, not the exec() function
			if combo.name == "User Input to Command Execution" && isMethodCallAtPosition(content, pos) {
				continue
			}

			fragment, lineNumber := signatures.GetFragment(file.Content, pos, 100)

			findings = append(findings, &models.Finding{
				File:          file,
				Type:          models.ThreatPHPBackdoor,
				Severity:      models.SeverityCritical,
				SignatureID:   "BACKDOOR-COMBO",
				SignatureName: combo.name,
				Description:   combo.desc,
				Position:      pos,
				LineNumber:    lineNumber,
				Fragment:      fragment,
				Confidence:    85,
				Timestamp:     time.Now(),
				Metadata: map[string]any{
					"pattern_count": len(combo.patterns),
					"detector":      "backdoor_combination",
				},
			})
		}
	}

	// 3. Match signatures from database (filter by backdoor categories)
	matches := d.matcher.Match(file.Content, file.Extension, d.level)
	for _, match := range matches {
		// Only include backdoor-related signatures
		if !isBackdoorCategory(match.Signature.Category) {
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
			Confidence:    calculateBackdoorConfidence(match),
			Timestamp:     time.Now(),
			Metadata: map[string]any{
				"pattern":  match.Signature.Pattern,
				"is_regex": match.Signature.IsRegex,
				"detector": "backdoor_signature",
			},
		})
	}

	return findings, nil
}

// isBackdoorCategory checks if the threat type is backdoor-related
func isBackdoorCategory(category models.ThreatType) bool {
	switch category {
	case models.ThreatPHPBackdoor, models.ThreatPHPShell, models.ThreatPHPObfuscated:
		return true
	default:
		return false
	}
}

// calculateBackdoorConfidence calculates confidence for backdoor detection
func calculateBackdoorConfidence(match *signatures.MatchResult) int {
	confidence := 75

	switch match.Signature.Severity {
	case models.SeverityCritical:
		confidence += 20
	case models.SeverityHigh:
		confidence += 10
	}

	if match.Signature.Category == models.ThreatPHPShell {
		confidence += 10 // Known shells are highly confident
	}

	if confidence > 100 {
		confidence = 100
	}

	return confidence
}
