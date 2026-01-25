package heuristic

import (
	"regexp"
	"strings"
)

// VariablePattern represents a suspicious variable naming pattern
type VariablePattern struct {
	Name        string
	Pattern     *regexp.Regexp
	Description string
	Score       int
}

// VariableAnalyzer analyzes variable naming patterns
type VariableAnalyzer struct {
	patterns         []VariablePattern
	varRegex         *regexp.Regexp
	phpSuperglobals  map[string]bool
}

// NewVariableAnalyzer creates a new variable analyzer
func NewVariableAnalyzer() *VariableAnalyzer {
	va := &VariableAnalyzer{
		varRegex: regexp.MustCompile(`\$([a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*)`),
	}

	// PHP superglobals whitelist - never flag these as suspicious
	phpSuperglobals := map[string]bool{
		"_GET": true, "_POST": true, "_REQUEST": true, "_SERVER": true,
		"_SESSION": true, "_COOKIE": true, "_FILES": true, "_ENV": true,
		"GLOBALS": true,
	}

	va.patterns = []VariablePattern{
		{
			Name:        "O0_Pattern",
			Pattern:     regexp.MustCompile(`^[O0]+[_O0]*$`),
			Description: "Variable uses O/0 obfuscation pattern",
			Score:       80,
		},
		{
			Name:        "Hex_Pattern",
			Pattern:     regexp.MustCompile(`^_0x[0-9a-fA-F]+$`),
			Description: "Variable uses hex obfuscation pattern",
			Score:       85,
		},
		{
			Name:        "Underscore_Pattern",
			Pattern:     regexp.MustCompile(`^_{2,}[a-zA-Z0-9]*_{2,}$`),
			Description: "Variable uses underscore obfuscation",
			Score:       70,
		},
		{
			Name:        "Random_Long",
			// Increased threshold to 25+ chars to avoid false positives on camelCase
			// Also ensure it doesn't look like camelCase (no lowercase after uppercase)
			Pattern:     regexp.MustCompile(`^[a-z]{25,}$|^[A-Z]{25,}$`),
			Description: "Unusually long random variable name",
			Score:       60,
		},
		{
			Name:        "Single_Char_Numeric",
			Pattern:     regexp.MustCompile(`^[a-z][0-9]{2,}$`),
			Description: "Single letter with numbers pattern",
			Score:       50,
		},
		{
			Name:        "GLOBALS_Like",
			// Modified to exclude standard PHP superglobals pattern
			// Only flag suspicious patterns that don't match standard conventions
			Pattern:     regexp.MustCompile(`^_{3,}[A-Z]+_{3,}$`),
			Description: "Suspicious GLOBALS-like naming pattern",
			Score:       65,
		},
		{
			Name:        "Base64_Like",
			// Increased threshold and exclude common patterns
			// Avoid matching variables with clear word boundaries
			Pattern:     regexp.MustCompile(`^[A-Za-z0-9+/]{20,}$`),
			Description: "Base64-like variable name",
			Score:       75,
		},
		{
			Name:        "Mixed_Case_Noise",
			Pattern:     regexp.MustCompile(`^([A-Z][a-z]){4,}$`),
			Description: "Alternating case pattern",
			Score:       55,
		},
	}

	va.phpSuperglobals = phpSuperglobals
	return va
}

// VariableAnalysis contains analysis results
type VariableAnalysis struct {
	TotalVariables     int
	SuspiciousCount    int
	SuspiciousVars     []SuspiciousVariable
	ObfuscationScore   int
	UniquePatterns     map[string]int
	LongStrings        int // Count of very long string assignments
	ConcatenationCount int // Count of string concatenations
}

// SuspiciousVariable represents a found suspicious variable
type SuspiciousVariable struct {
	Name        string
	PatternName string
	Description string
	Score       int
	Position    int
}

// Analyze analyzes content for suspicious variable patterns
func (va *VariableAnalyzer) Analyze(content string) *VariableAnalysis {
	analysis := &VariableAnalysis{
		UniquePatterns: make(map[string]int),
	}

	// Find all variables
	matches := va.varRegex.FindAllStringSubmatchIndex(content, -1)
	seenVars := make(map[string]bool)

	for _, match := range matches {
		if len(match) < 4 {
			continue
		}

		varName := content[match[2]:match[3]]
		analysis.TotalVariables++

		// Skip if already seen
		if seenVars[varName] {
			continue
		}
		seenVars[varName] = true

		// Skip PHP superglobals - they are never suspicious
		if va.phpSuperglobals != nil && va.phpSuperglobals[varName] {
			continue
		}

		// Skip common naming patterns that look like legitimate code
		if isLegitimateNaming(varName) {
			continue
		}

		// Check against patterns
		for _, pattern := range va.patterns {
			if pattern.Pattern.MatchString(varName) {
				analysis.SuspiciousCount++
				analysis.SuspiciousVars = append(analysis.SuspiciousVars, SuspiciousVariable{
					Name:        varName,
					PatternName: pattern.Name,
					Description: pattern.Description,
					Score:       pattern.Score,
					Position:    match[0],
				})
				analysis.UniquePatterns[pattern.Name]++
				break // Count each variable only once
			}
		}
	}

	// Analyze long strings (potential encoded payloads)
	// Increased threshold to 500 chars to reduce false positives
	// Long SQL queries, HTML templates, etc. are normal
	longStringRegex := regexp.MustCompile(`['"][^'"]{500,}['"]`)
	analysis.LongStrings = len(longStringRegex.FindAllString(content, -1))

	// Count string concatenations
	concatRegex := regexp.MustCompile(`['"]s*\.s*['"]`)
	analysis.ConcatenationCount = len(concatRegex.FindAllString(content, -1))

	// Calculate overall obfuscation score
	if analysis.TotalVariables > 0 {
		suspiciousRatio := float64(analysis.SuspiciousCount) / float64(len(seenVars))
		analysis.ObfuscationScore = int(suspiciousRatio * 100)

		// Boost score if multiple patterns found
		if len(analysis.UniquePatterns) >= 3 {
			analysis.ObfuscationScore += 20
		}

		// Boost score for long strings
		if analysis.LongStrings > 0 {
			analysis.ObfuscationScore += analysis.LongStrings * 10
		}

		// Cap at 100
		if analysis.ObfuscationScore > 100 {
			analysis.ObfuscationScore = 100
		}
	}

	return analysis
}

// isLegitimateNaming checks if a variable name follows common legitimate patterns
func isLegitimateNaming(name string) bool {
	// camelCase pattern (starts with lowercase, has uppercase letters)
	if regexp.MustCompile(`^[a-z][a-z0-9]*[A-Z]`).MatchString(name) {
		return true
	}

	// PascalCase pattern (starts with uppercase)
	if regexp.MustCompile(`^[A-Z][a-z]+[A-Z]`).MatchString(name) {
		return true
	}

	// snake_case pattern
	if regexp.MustCompile(`^[a-z]+(_[a-z0-9]+)+$`).MatchString(name) {
		return true
	}

	// Hungarian notation patterns (ar*, str*, is*, has*, etc.)
	if regexp.MustCompile(`^(ar|str|is|has|can|should|will|obj|arr|int|bool|num)[A-Z]`).MatchString(name) {
		return true
	}

	// Common prefixes in frameworks
	if regexp.MustCompile(`^(tmp|temp|data|result|response|request|param|config|option)[A-Z]?`).MatchString(name) {
		return true
	}

	return false
}

// CodeStructureAnalysis analyzes code structure anomalies
type CodeStructureAnalysis struct {
	SingleLineRatio   float64 // Ratio of code on single line
	MaxLineLength     int
	AverageLineLength float64
	EmptyLines        int
	TotalLines        int
	IsMinified        bool
	Score             int
}

// AnalyzeCodeStructure checks for structural anomalies
func AnalyzeCodeStructure(content string) *CodeStructureAnalysis {
	analysis := &CodeStructureAnalysis{}

	lines := strings.Split(content, "\n")
	analysis.TotalLines = len(lines)

	if analysis.TotalLines == 0 {
		return analysis
	}

	var totalLength int
	for _, line := range lines {
		lineLen := len(line)
		totalLength += lineLen

		if lineLen > analysis.MaxLineLength {
			analysis.MaxLineLength = lineLen
		}

		if strings.TrimSpace(line) == "" {
			analysis.EmptyLines++
		}
	}

	analysis.AverageLineLength = float64(totalLength) / float64(analysis.TotalLines)

	// Check for minified/single-line code
	nonEmptyLines := analysis.TotalLines - analysis.EmptyLines
	if nonEmptyLines > 0 {
		// If most content is on few lines
		if analysis.MaxLineLength > 1000 && nonEmptyLines < 10 {
			analysis.IsMinified = true
			analysis.Score = 70
		}

		// Single very long line
		if analysis.MaxLineLength > 5000 {
			analysis.Score = 85
		}

		// High average with few lines
		if analysis.AverageLineLength > 500 && nonEmptyLines < 5 {
			analysis.IsMinified = true
			analysis.Score = 75
		}
	}

	return analysis
}
