package heuristic

import (
	"regexp"
	"strings"

	"github.com/IvanShishkin/houndoom/pkg/models"
)

// ContextDetector analyzes code to determine scoring contexts
// Based on Bitrix XScan context analysis
type ContextDetector struct {
	userInputPattern   *regexp.Regexp
	evalPattern        *regexp.Regexp
	fileOpPattern      *regexp.Regexp
	networkOpPattern   *regexp.Regexp
	dbOpPattern        *regexp.Regexp
	systemCallPattern  *regexp.Regexp
	obfuscatedPatterns []*regexp.Regexp
	encodedPatterns    []*regexp.Regexp
}

// NewContextDetector creates a new context detector
func NewContextDetector() *ContextDetector {
	return &ContextDetector{
		// User input sources
		userInputPattern: regexp.MustCompile(`(?i)\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)\s*\[`),

		// Eval-like functions
		evalPattern: regexp.MustCompile(`(?i)\b(eval|assert|create_function)\s*\(`),

		// File operations
		fileOpPattern: regexp.MustCompile(`(?i)\b(file_get_contents|file_put_contents|fopen|fwrite|fread|readfile|include|require|include_once|require_once|move_uploaded_file)\s*\(`),

		// Network operations
		networkOpPattern: regexp.MustCompile(`(?i)\b(curl_exec|curl_init|fsockopen|socket_create|socket_connect|file_get_contents\s*\(\s*['"](https?|ftp)://)\s*\(`),

		// Database operations
		dbOpPattern: regexp.MustCompile(`(?i)\b(mysql_query|mysqli_query|pg_query|sqlite_query|PDO::query|execute|prepare)\s*\(`),

		// System calls
		systemCallPattern: regexp.MustCompile(`(?i)\b(exec|system|passthru|shell_exec|proc_open|popen|pcntl_exec)\s*\(|` + "`" + `[^` + "`" + `]+` + "`"),

		// Obfuscation indicators
		obfuscatedPatterns: []*regexp.Regexp{
			regexp.MustCompile(`\$[a-z]\d+[a-z]+\d+`),                    // $a1b2c3 style vars
			regexp.MustCompile(`\$[O0][O0Il1]+`),                         // $O0O0l1l style vars
			regexp.MustCompile(`\$_[A-F0-9]{32,}`),                       // $_HEXHEXHEX style vars
			regexp.MustCompile(`\$\{[^}]{30,}\}`),                        // ${very_long_var_name}
			regexp.MustCompile(`\$\$+[a-zA-Z_]`),                         // $$var, $$$var variable variables
			regexp.MustCompile(`[\w]+\s*=\s*["'][^"']{100,}["']`),        // Very long string assignments
			regexp.MustCompile(`(?i)\bstr_rot13\s*\(\s*["'][^"']{50,}`), // rot13 encoded strings
		},

		// Encoding indicators
		encodedPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)\bbase64_decode\s*\(`),
			regexp.MustCompile(`(?i)\bgzinflate\s*\(`),
			regexp.MustCompile(`(?i)\bgzuncompress\s*\(`),
			regexp.MustCompile(`(?i)\bstr_rot13\s*\(`),
			regexp.MustCompile(`(?i)\bconvert_uudecode\s*\(`),
			regexp.MustCompile(`(?i)\bhex2bin\s*\(`),
			regexp.MustCompile(`(?i)\bunserialize\s*\(`),
			regexp.MustCompile(`["'][A-Za-z0-9+/]{100,}={0,2}["']`), // Long base64-like strings
		},
	}
}

// DetectContexts analyzes content and returns all detected contexts
func (cd *ContextDetector) DetectContexts(content string) map[models.ScoringContext]bool {
	contexts := make(map[models.ScoringContext]bool)

	// Always have default context
	contexts[models.ContextDefault] = true

	// Check for user input
	if cd.userInputPattern.MatchString(content) {
		contexts[models.ContextUserInput] = true
	}

	// Check for eval usage
	if cd.evalPattern.MatchString(content) {
		contexts[models.ContextEval] = true
	}

	// Check for file operations
	if cd.fileOpPattern.MatchString(content) {
		contexts[models.ContextFileOperation] = true
	}

	// Check for network operations
	if cd.networkOpPattern.MatchString(content) {
		contexts[models.ContextNetworkOperation] = true
	}

	// Check for database operations
	if cd.dbOpPattern.MatchString(content) {
		contexts[models.ContextDatabaseOperation] = true
	}

	// Check for system calls
	if cd.systemCallPattern.MatchString(content) {
		contexts[models.ContextSystemCall] = true
	}

	// Check for obfuscation
	obfuscationScore := 0
	for _, pattern := range cd.obfuscatedPatterns {
		if pattern.MatchString(content) {
			obfuscationScore++
		}
	}
	// Need at least 2 obfuscation indicators
	if obfuscationScore >= 2 {
		contexts[models.ContextObfuscated] = true
	}

	// Check for encoding
	encodingScore := 0
	for _, pattern := range cd.encodedPatterns {
		if pattern.MatchString(content) {
			encodingScore++
		}
	}
	// Need at least 1 encoding indicator
	if encodingScore >= 1 {
		contexts[models.ContextEncoded] = true
	}

	return contexts
}

// GetPrimaryContext returns the most significant context for scoring
// Priority: Eval > UserInput > NetworkOp > SystemCall > Obfuscated > Encoded > FileOp > DB > Default
func (cd *ContextDetector) GetPrimaryContext(contexts map[models.ScoringContext]bool) models.ScoringContext {
	// Priority order
	priority := []models.ScoringContext{
		models.ContextEval,
		models.ContextUserInput,
		models.ContextNetworkOperation,
		models.ContextSystemCall,
		models.ContextObfuscated,
		models.ContextEncoded,
		models.ContextFileOperation,
		models.ContextDatabaseOperation,
		models.ContextDefault,
	}

	for _, ctx := range priority {
		if contexts[ctx] {
			return ctx
		}
	}

	return models.ContextDefault
}

// AnalyzeLocalContext analyzes a code snippet (around a finding) for local context
// This is more precise than analyzing the whole file
func (cd *ContextDetector) AnalyzeLocalContext(snippet string, surroundingLines string) models.ScoringContext {
	// Combine snippet with surrounding context
	fullContext := snippet + "\n" + surroundingLines

	contexts := cd.DetectContexts(fullContext)
	return cd.GetPrimaryContext(contexts)
}

// DetectDataFlow checks if there's a data flow from user input to dangerous function
// Returns true if user input flows into dangerous operations
func (cd *ContextDetector) DetectDataFlow(content string) (bool, []string) {
	flows := make([]string, 0)

	// Simple heuristic: user input variable used in dangerous function
	// More sophisticated: track variable assignments

	// Pattern: $_X[...] -> $var -> dangerous_function($var)
	lines := strings.Split(content, "\n")

	userVars := make(map[string]bool)
	dangerousCalls := make([]string, 0)

	for _, line := range lines {
		// Find user input assignments: $var = $_GET[...];
		userInputAssignment := regexp.MustCompile(`\$([a-zA-Z_][a-zA-Z0-9_]*)\s*=.*\$_(GET|POST|REQUEST|COOKIE)`)
		if matches := userInputAssignment.FindStringSubmatch(line); matches != nil {
			userVars[matches[1]] = true
		}

		// Find dangerous function calls with variables
		dangerousFuncs := []string{"eval", "exec", "system", "passthru", "assert", "create_function"}
		for _, fn := range dangerousFuncs {
			pattern := regexp.MustCompile(`(?i)\b` + fn + `\s*\([^)]*\$([a-zA-Z_][a-zA-Z0-9_]*)`)
			if matches := pattern.FindStringSubmatch(line); matches != nil {
				varName := matches[1]
				if userVars[varName] {
					flows = append(flows, "User input $"+varName+" flows into "+fn+"()")
					dangerousCalls = append(dangerousCalls, fn)
				}
			}
		}

		// Direct usage: dangerous_function($_GET[...])
		directPattern := regexp.MustCompile(`(?i)\b(eval|exec|system|passthru|assert|create_function)\s*\([^)]*\$_(GET|POST|REQUEST|COOKIE)`)
		if matches := directPattern.FindStringSubmatch(line); matches != nil {
			flows = append(flows, "Direct user input into "+matches[1]+"()")
			dangerousCalls = append(dangerousCalls, matches[1])
		}
	}

	return len(flows) > 0, flows
}

// GetContextDescription returns human-readable description of contexts
func GetContextDescription(contexts map[models.ScoringContext]bool) string {
	descriptions := make([]string, 0)

	if contexts[models.ContextUserInput] {
		descriptions = append(descriptions, "user input handling")
	}
	if contexts[models.ContextEval] {
		descriptions = append(descriptions, "dynamic code evaluation")
	}
	if contexts[models.ContextFileOperation] {
		descriptions = append(descriptions, "file operations")
	}
	if contexts[models.ContextNetworkOperation] {
		descriptions = append(descriptions, "network operations")
	}
	if contexts[models.ContextDatabaseOperation] {
		descriptions = append(descriptions, "database operations")
	}
	if contexts[models.ContextSystemCall] {
		descriptions = append(descriptions, "system calls")
	}
	if contexts[models.ContextObfuscated] {
		descriptions = append(descriptions, "obfuscated code")
	}
	if contexts[models.ContextEncoded] {
		descriptions = append(descriptions, "encoded content")
	}

	if len(descriptions) == 0 {
		return "default context"
	}

	return strings.Join(descriptions, ", ")
}
