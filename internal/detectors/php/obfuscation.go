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

// Obfuscation detection patterns
var (
	// Goto statements - used for control flow obfuscation
	gotoPattern = regexp.MustCompile(`\bgoto\s+[a-zA-Z_]\w*\s*;`)
	// Note: labelPattern removed - we count gotos only, labels are implicit

	// Hex-encoded strings: \x72\x61\x6e etc
	hexStringPattern = regexp.MustCompile(`\\x[0-9a-fA-F]{2}`)

	// Octal-encoded strings: \162\141\156 etc
	octalStringPattern = regexp.MustCompile(`\\[0-7]{2,3}`)

	// Characteristic range encoding: range('~', ' ') or range("\176", "\x20")
	// Specifically matches tilde (~) or high ASCII values used for string encoding
	rangeEncodingPattern = regexp.MustCompile(`\brange\s*\(\s*["'](?:~|\\176|\\x7e)["']\s*,\s*["'](?:\s|\\040|\\x20)["']\s*\)`)

	// Eval via variable/array: eval($var), eval($arr[0]), @eval($x(...))
	evalViaVarPattern = regexp.MustCompile(`@?\beval\s*\(\s*\$[a-zA-Z_]\w*\s*[\[\(]`)

	// Dynamic function call via variable: $func(), $arr[0]()
	dynamicCallPattern = regexp.MustCompile(`\$[a-zA-Z_]\w*\s*\[[^\]]+\]\s*\(`)

	// Long random variable names (likely generated): $HXDIFty21JcP7t
	randomVarPattern = regexp.MustCompile(`\$[a-zA-Z]{2,}[a-zA-Z0-9_]{8,}`)

	// Concatenated single chars to build strings: "r" . "a" . "n" . "g" . "e"
	charConcatPattern = regexp.MustCompile(`["'][a-zA-Z\\x][0-9a-fA-F]*["']\s*\.\s*["'][a-zA-Z\\x]`)

	// Base64 + eval/gzinflate combo
	base64EvalPattern = regexp.MustCompile(`(?i)\b(?:eval|assert)\s*\(\s*(?:gzinflate|gzuncompress|gzdecode|str_rot13|base64_decode)\s*\(`)

	// Create_function with encoded content
	createFunctionPattern = regexp.MustCompile(`\bcreate_function\s*\(\s*["'][^"']*["']\s*,\s*(?:base64_decode|gzinflate|\$)`)

	// Curl + eval in same file (C2 pattern)
	curlPattern = regexp.MustCompile(`\bcurl_exec\s*\(`)

	// preg_replace with /e modifier (code execution)
	pregReplaceEPattern = regexp.MustCompile(`\bpreg_replace\s*\(\s*["']/[^"']+/[a-z]*e[a-z]*["']`)

	// Multiple @ error suppression (hiding errors)
	errorSuppressionPattern = regexp.MustCompile(`@\s*(?:eval|system|exec|passthru|shell_exec|assert|include|require|file_get_contents|curl_exec|fopen|unlink)`)
)

// ObfuscationDetector detects obfuscated PHP code
type ObfuscationDetector struct {
	*detectors.BaseDetector
	matcher *signatures.Matcher
	level   models.SignatureLevel
}

// NewObfuscationDetector creates a new obfuscation detector
func NewObfuscationDetector(matcher *signatures.Matcher, level models.SignatureLevel) *ObfuscationDetector {
	return &ObfuscationDetector{
		BaseDetector: detectors.NewBaseDetector("php_obfuscation", 90, []string{
			"php", "php3", "php4", "php5", "php7", "phtml", "pht", "inc",
		}),
		matcher: matcher,
		level:   level,
	}
}

// Detect scans a file for obfuscation patterns
func (d *ObfuscationDetector) Detect(ctx context.Context, file *models.File) ([]*models.Finding, error) {
	var findings []*models.Finding
	content := string(file.Content)
	contentLen := len(content)

	// Skip very small files
	if contentLen < 100 {
		return findings, nil
	}

	// 1. Detect goto-based obfuscation
	if finding := d.detectGotoObfuscation(file, content); finding != nil {
		findings = append(findings, finding)
	}

	// 2. Detect high density of hex-encoded strings
	if finding := d.detectHexStringObfuscation(file, content); finding != nil {
		findings = append(findings, finding)
	}

	// 3. Detect characteristic range encoding
	if finding := d.detectRangeEncoding(file, content); finding != nil {
		findings = append(findings, finding)
	}

	// 4. Detect eval via variable
	if finding := d.detectEvalViaVariable(file, content); finding != nil {
		findings = append(findings, finding)
	}

	// 5. Detect dynamic function calls
	if finding := d.detectDynamicCalls(file, content); finding != nil {
		findings = append(findings, finding)
	}

	// 6. Detect string concatenation obfuscation
	if finding := d.detectCharConcatenation(file, content); finding != nil {
		findings = append(findings, finding)
	}

	// 7. Detect base64/gzip + eval combo
	if finding := d.detectBase64Eval(file, content); finding != nil {
		findings = append(findings, finding)
	}

	// 8. Detect C2 pattern (curl + eval)
	if finding := d.detectC2Pattern(file, content); finding != nil {
		findings = append(findings, finding)
	}

	// 9. Detect multiple error suppression on dangerous functions
	if finding := d.detectErrorSuppression(file, content); finding != nil {
		findings = append(findings, finding)
	}

	// 10. Calculate overall obfuscation score
	if finding := d.calculateObfuscationScore(file, content, len(findings)); finding != nil {
		findings = append(findings, finding)
	}

	return findings, nil
}

// detectGotoObfuscation detects control flow obfuscation via goto
func (d *ObfuscationDetector) detectGotoObfuscation(file *models.File, content string) *models.Finding {
	gotos := gotoPattern.FindAllStringIndex(content, -1)

	gotoCount := len(gotos)

	// Threshold: more than 5 gotos is suspicious, more than 15 is definitely obfuscation
	if gotoCount < 5 {
		return nil
	}

	severity := models.SeverityMedium
	confidence := 70

	if gotoCount >= 15 {
		severity = models.SeverityCritical
		confidence = 95
	} else if gotoCount >= 10 {
		severity = models.SeverityHigh
		confidence = 85
	}

	pos := 0
	if len(gotos) > 0 {
		pos = gotos[0][0]
	}
	fragment, lineNumber := signatures.GetFragment(file.Content, pos, 100)

	return &models.Finding{
		File:          file,
		Type:          models.ThreatPHPObfuscated,
		Severity:      severity,
		SignatureID:   "OBFUSCATION-GOTO",
		SignatureName: "Goto Control Flow Obfuscation",
		Description:   "Code uses excessive goto statements for control flow obfuscation - common in webshells",
		Position:      pos,
		LineNumber:    lineNumber,
		Fragment:      fragment,
		Confidence:    confidence,
		Timestamp:     time.Now(),
		Metadata: map[string]interface{}{
			"goto_count": gotoCount,
			"technique":  "control_flow_obfuscation",
		},
	}
}

// detectHexStringObfuscation detects high density of hex-encoded strings
func (d *ObfuscationDetector) detectHexStringObfuscation(file *models.File, content string) *models.Finding {
	hexMatches := hexStringPattern.FindAllStringIndex(content, -1)
	octalMatches := octalStringPattern.FindAllStringIndex(content, -1)

	totalEncoded := len(hexMatches) + len(octalMatches)

	// Calculate density: encoded sequences per KB
	density := float64(totalEncoded) / (float64(len(content)) / 1024.0)

	// Threshold: more than 20 per KB is suspicious
	if density < 20 || totalEncoded < 15 {
		return nil
	}

	severity := models.SeverityMedium
	confidence := 70

	if density >= 50 || totalEncoded >= 50 {
		severity = models.SeverityHigh
		confidence = 85
	}

	pos := 0
	if len(hexMatches) > 0 {
		pos = hexMatches[0][0]
	}
	fragment, lineNumber := signatures.GetFragment(file.Content, pos, 100)

	return &models.Finding{
		File:          file,
		Type:          models.ThreatPHPObfuscated,
		Severity:      severity,
		SignatureID:   "OBFUSCATION-HEXSTRING",
		SignatureName: "Hex/Octal String Encoding",
		Description:   "High density of hex/octal encoded strings - used to hide malicious content",
		Position:      pos,
		LineNumber:    lineNumber,
		Fragment:      fragment,
		Confidence:    confidence,
		Timestamp:     time.Now(),
		Metadata: map[string]interface{}{
			"hex_count":      len(hexMatches),
			"octal_count":    len(octalMatches),
			"density_per_kb": density,
			"technique":      "string_encoding",
		},
	}
}

// detectRangeEncoding detects range('~', ' ') encoding technique
func (d *ObfuscationDetector) detectRangeEncoding(file *models.File, content string) *models.Finding {
	matches := rangeEncodingPattern.FindAllStringIndex(content, -1)

	if len(matches) == 0 {
		return nil
	}

	pos := matches[0][0]
	fragment, lineNumber := signatures.GetFragment(file.Content, pos, 100)
	matched := content[matches[0][0]:matches[0][1]]

	return &models.Finding{
		File:          file,
		Type:          models.ThreatPHPObfuscated,
		Severity:      models.SeverityCritical,
		SignatureID:   "OBFUSCATION-RANGE-ENCODING",
		SignatureName: "Range-Based String Encoding",
		Description:   "Uses range() function for string encoding - characteristic of PHP webshells",
		Position:      pos,
		LineNumber:    lineNumber,
		Snippet:       matched,
		Fragment:      fragment,
		Confidence:    95,
		Timestamp:     time.Now(),
		Metadata: map[string]interface{}{
			"technique": "range_encoding",
			"pattern":   matched,
		},
	}
}

// detectEvalViaVariable detects eval called via variable
func (d *ObfuscationDetector) detectEvalViaVariable(file *models.File, content string) *models.Finding {
	matches := evalViaVarPattern.FindAllStringIndex(content, -1)

	if len(matches) == 0 {
		return nil
	}

	pos := matches[0][0]
	fragment, lineNumber := signatures.GetFragment(file.Content, pos, 100)
	matched := content[matches[0][0]:min(matches[0][1]+20, len(content))]

	return &models.Finding{
		File:          file,
		Type:          models.ThreatPHPBackdoor,
		Severity:      models.SeverityCritical,
		SignatureID:   "OBFUSCATION-EVAL-VAR",
		SignatureName: "Eval via Variable",
		Description:   "Eval called through variable/array - hides the actual function being called",
		Position:      pos,
		LineNumber:    lineNumber,
		Snippet:       truncateSnippet(matched, 60),
		Fragment:      fragment,
		Confidence:    90,
		Timestamp:     time.Now(),
		Metadata: map[string]interface{}{
			"technique": "dynamic_eval",
		},
	}
}

// detectDynamicCalls detects dynamic function calls via array
func (d *ObfuscationDetector) detectDynamicCalls(file *models.File, content string) *models.Finding {
	matches := dynamicCallPattern.FindAllStringIndex(content, -1)

	// Need multiple dynamic calls to be suspicious
	if len(matches) < 3 {
		return nil
	}

	pos := matches[0][0]
	fragment, lineNumber := signatures.GetFragment(file.Content, pos, 100)

	return &models.Finding{
		File:          file,
		Type:          models.ThreatPHPObfuscated,
		Severity:      models.SeverityHigh,
		SignatureID:   "OBFUSCATION-DYNAMIC-CALL",
		SignatureName: "Dynamic Function Calls",
		Description:   "Multiple dynamic function calls via array - used to hide function names",
		Position:      pos,
		LineNumber:    lineNumber,
		Fragment:      fragment,
		Confidence:    80,
		Timestamp:     time.Now(),
		Metadata: map[string]interface{}{
			"call_count": len(matches),
			"technique":  "dynamic_calls",
		},
	}
}

// detectCharConcatenation detects character-by-character string building
func (d *ObfuscationDetector) detectCharConcatenation(file *models.File, content string) *models.Finding {
	matches := charConcatPattern.FindAllStringIndex(content, -1)

	// Need multiple occurrences
	if len(matches) < 5 {
		return nil
	}

	pos := matches[0][0]
	fragment, lineNumber := signatures.GetFragment(file.Content, pos, 100)

	severity := models.SeverityMedium
	if len(matches) >= 10 {
		severity = models.SeverityHigh
	}

	return &models.Finding{
		File:          file,
		Type:          models.ThreatPHPObfuscated,
		Severity:      severity,
		SignatureID:   "OBFUSCATION-CHAR-CONCAT",
		SignatureName: "Character Concatenation",
		Description:   "Strings built by concatenating single characters - hides string content",
		Position:      pos,
		LineNumber:    lineNumber,
		Fragment:      fragment,
		Confidence:    75,
		Timestamp:     time.Now(),
		Metadata: map[string]interface{}{
			"concat_count": len(matches),
			"technique":    "char_concatenation",
		},
	}
}

// detectBase64Eval detects base64/gzip + eval combinations
func (d *ObfuscationDetector) detectBase64Eval(file *models.File, content string) *models.Finding {
	matches := base64EvalPattern.FindAllStringIndex(content, -1)

	if len(matches) == 0 {
		return nil
	}

	pos := matches[0][0]
	fragment, lineNumber := signatures.GetFragment(file.Content, pos, 100)
	matched := content[matches[0][0]:matches[0][1]]

	return &models.Finding{
		File:          file,
		Type:          models.ThreatPHPBackdoor,
		Severity:      models.SeverityCritical,
		SignatureID:   "OBFUSCATION-BASE64-EVAL",
		SignatureName: "Encoded Eval Execution",
		Description:   "Eval with base64/gzip decoding - classic webshell pattern",
		Position:      pos,
		LineNumber:    lineNumber,
		Snippet:       matched,
		Fragment:      fragment,
		Confidence:    95,
		Timestamp:     time.Now(),
		Metadata: map[string]interface{}{
			"technique": "encoded_eval",
		},
	}
}

// detectC2Pattern detects Command & Control pattern (curl + eval)
func (d *ObfuscationDetector) detectC2Pattern(file *models.File, content string) *models.Finding {
	hasCurl := curlPattern.MatchString(content)
	hasEval := strings.Contains(content, "eval(") || strings.Contains(content, "eval (")
	hasAssert := strings.Contains(content, "assert(")

	if !hasCurl || (!hasEval && !hasAssert) {
		return nil
	}

	matches := curlPattern.FindStringIndex(content)
	pos := 0
	if matches != nil {
		pos = matches[0]
	}

	fragment, lineNumber := signatures.GetFragment(file.Content, pos, 100)

	return &models.Finding{
		File:          file,
		Type:          models.ThreatPHPBackdoor,
		Severity:      models.SeverityCritical,
		SignatureID:   "OBFUSCATION-C2-PATTERN",
		SignatureName: "Command & Control Pattern",
		Description:   "File contains curl + eval - downloads and executes remote code",
		Position:      pos,
		LineNumber:    lineNumber,
		Fragment:      fragment,
		Confidence:    90,
		Timestamp:     time.Now(),
		Metadata: map[string]interface{}{
			"has_curl":   hasCurl,
			"has_eval":   hasEval,
			"has_assert": hasAssert,
			"technique":  "c2_backdoor",
		},
	}
}

// detectErrorSuppression detects multiple @ on dangerous functions
func (d *ObfuscationDetector) detectErrorSuppression(file *models.File, content string) *models.Finding {
	matches := errorSuppressionPattern.FindAllStringIndex(content, -1)

	// Need multiple suppressions to be suspicious
	if len(matches) < 3 {
		return nil
	}

	pos := matches[0][0]
	fragment, lineNumber := signatures.GetFragment(file.Content, pos, 100)

	return &models.Finding{
		File:          file,
		Type:          models.ThreatPHPSuspicious,
		Severity:      models.SeverityMedium,
		SignatureID:   "OBFUSCATION-ERROR-SUPPRESS",
		SignatureName: "Error Suppression on Dangerous Functions",
		Description:   "Multiple @ error suppression on dangerous functions - hiding malicious activity",
		Position:      pos,
		LineNumber:    lineNumber,
		Fragment:      fragment,
		Confidence:    70,
		Timestamp:     time.Now(),
		Metadata: map[string]interface{}{
			"suppression_count": len(matches),
			"technique":         "error_hiding",
		},
	}
}

// calculateObfuscationScore calculates overall obfuscation score
func (d *ObfuscationDetector) calculateObfuscationScore(file *models.File, content string, existingFindings int) *models.Finding {
	// If we already have multiple findings, calculate composite score
	if existingFindings < 2 {
		return nil
	}

	// Additional heuristics
	randomVars := randomVarPattern.FindAllStringIndex(content, -1)

	// High number of random variable names is suspicious
	if len(randomVars) < 10 && existingFindings < 3 {
		return nil
	}

	severity := models.SeverityHigh
	confidence := 85

	if existingFindings >= 4 || len(randomVars) >= 20 {
		severity = models.SeverityCritical
		confidence = 95
	}

	return &models.Finding{
		File:          file,
		Type:          models.ThreatPHPObfuscated,
		Severity:      severity,
		SignatureID:   "OBFUSCATION-COMPOSITE",
		SignatureName: "Multiple Obfuscation Techniques",
		Description:   "File uses multiple obfuscation techniques - highly likely to be a webshell",
		Confidence:    confidence,
		Timestamp:     time.Now(),
		Metadata: map[string]interface{}{
			"technique_count":   existingFindings,
			"random_vars_count": len(randomVars),
			"technique":         "composite_obfuscation",
		},
	}
}

// truncateSnippet truncates a snippet to max length
func truncateSnippet(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
