package heuristic

import (
	"regexp"
	"strings"
)

// SuspiciousCombination represents a dangerous function combination
type SuspiciousCombination struct {
	Name        string
	Description string
	Functions   []string // All must be present
	Severity    string   // critical, high, medium, low
	Score       int      // Risk score 1-100
}

// Pre-defined suspicious combinations
var suspiciousCombinations = []SuspiciousCombination{
	{
		Name:        "Remote Code Execution",
		Description: "File fetch combined with code execution",
		Functions:   []string{"file_get_contents", "eval"},
		Severity:    "critical",
		Score:       95,
	},
	{
		Name:        "Remote Include",
		Description: "URL fetch combined with include",
		Functions:   []string{"file_get_contents", "include"},
		Severity:    "critical",
		Score:       90,
	},
	{
		Name:        "Curl Code Execution",
		Description: "Curl request combined with eval",
		Functions:   []string{"curl_exec", "eval"},
		Severity:    "critical",
		Score:       95,
	},
	{
		Name:        "Base64 Execution",
		Description: "Base64 decode combined with eval",
		Functions:   []string{"base64_decode", "eval"},
		Severity:    "high",
		Score:       85,
	},
	{
		Name:        "Gzip Code Execution",
		Description: "Decompression combined with eval",
		Functions:   []string{"gzinflate", "eval"},
		Severity:    "high",
		Score:       85,
	},
	{
		Name:        "User Input Execution",
		Description: "User input passed to dangerous function",
		Functions:   []string{"$_GET", "eval"},
		Severity:    "critical",
		Score:       100,
	},
	{
		Name:        "User Input System Call",
		Description: "User input passed to system command",
		Functions:   []string{"$_GET", "system"},
		Severity:    "critical",
		Score:       100,
	},
	{
		Name:        "POST Data Execution",
		Description: "POST data passed to eval",
		Functions:   []string{"$_POST", "eval"},
		Severity:    "critical",
		Score:       100,
	},
	{
		Name:        "Request Execution",
		Description: "Request data passed to dangerous function",
		Functions:   []string{"$_REQUEST", "exec"},
		Severity:    "critical",
		Score:       100,
	},
	{
		Name:        "File Write from Input",
		Description: "Writing user input to file",
		Functions:   []string{"$_POST", "file_put_contents"},
		Severity:    "high",
		Score:       80,
	},
	{
		Name:        "Dynamic Function Call",
		Description: "Dynamic function creation and call",
		Functions:   []string{"create_function", "call_user_func"},
		Severity:    "high",
		Score:       75,
	},
	{
		Name:        "Serialization Attack",
		Description: "Unserialize with user input",
		Functions:   []string{"unserialize", "$_"},
		Severity:    "high",
		Score:       80,
	},
	{
		Name:        "Preg Replace Execution",
		Description: "Preg replace with /e modifier potential",
		Functions:   []string{"preg_replace", "eval"},
		Severity:    "high",
		Score:       85,
	},
	{
		Name:        "Assert Execution",
		Description: "Assert with string evaluation",
		Functions:   []string{"assert", "$_"},
		Severity:    "high",
		Score:       85,
	},
	{
		Name:        "Mail Header Injection",
		Description: "User input in mail headers",
		Functions:   []string{"mail", "$_GET"},
		Severity:    "medium",
		Score:       60,
	},
	{
		Name:        "SQL with User Input",
		Description: "Direct SQL query with user input",
		Functions:   []string{"mysql_query", "$_"},
		Severity:    "high",
		Score:       75,
	},
}

// CombinationMatch represents a found suspicious combination
type CombinationMatch struct {
	Combination SuspiciousCombination
	FoundFuncs  []string
	Positions   map[string]int
}

// CombinationAnalyzer analyzes code for suspicious function combinations
type CombinationAnalyzer struct {
	patterns map[string]*regexp.Regexp
}

// NewCombinationAnalyzer creates a new analyzer
func NewCombinationAnalyzer() *CombinationAnalyzer {
	ca := &CombinationAnalyzer{
		patterns: make(map[string]*regexp.Regexp),
	}

	// Pre-compile patterns for each function
	funcs := []string{
		"eval", "exec", "system", "passthru", "shell_exec", "popen",
		"file_get_contents", "file_put_contents", "fopen", "fwrite",
		"include", "require", "include_once", "require_once",
		"base64_decode", "gzinflate", "gzuncompress", "str_rot13",
		"curl_exec", "curl_init", "mail", "unserialize",
		"create_function", "call_user_func", "call_user_func_array",
		"preg_replace", "assert", "mysql_query", "mysqli_query",
		`\$_GET`, `\$_POST`, `\$_REQUEST`, `\$_COOKIE`, `\$_`,
	}

	for _, f := range funcs {
		pattern := regexp.MustCompile(`(?i)` + regexp.QuoteMeta(f) + `\s*[\(\[]`)
		ca.patterns[f] = pattern
	}

	// Special patterns for superglobals
	ca.patterns["$_GET"] = regexp.MustCompile(`\$_GET\s*\[`)
	ca.patterns["$_POST"] = regexp.MustCompile(`\$_POST\s*\[`)
	ca.patterns["$_REQUEST"] = regexp.MustCompile(`\$_REQUEST\s*\[`)
	ca.patterns["$_COOKIE"] = regexp.MustCompile(`\$_COOKIE\s*\[`)
	ca.patterns["$_"] = regexp.MustCompile(`\$_(GET|POST|REQUEST|COOKIE|SERVER)\s*\[`)

	return ca
}

// Analyze checks content for suspicious combinations
func (ca *CombinationAnalyzer) Analyze(content string) []CombinationMatch {
	var matches []CombinationMatch

	// Find all present functions
	presentFuncs := make(map[string]int) // function -> position
	for name, pattern := range ca.patterns {
		loc := pattern.FindStringIndex(content)
		if loc != nil {
			presentFuncs[name] = loc[0]
		}
	}

	// Check each combination
	for _, combo := range suspiciousCombinations {
		allPresent := true
		foundFuncs := make([]string, 0)
		positions := make(map[string]int)

		for _, reqFunc := range combo.Functions {
			found := false
			// Check exact match first
			if pos, ok := presentFuncs[reqFunc]; ok {
				found = true
				foundFuncs = append(foundFuncs, reqFunc)
				positions[reqFunc] = pos
			} else if reqFunc == "$_" {
				// Check any superglobal
				for f, pos := range presentFuncs {
					if strings.HasPrefix(f, "$_") {
						found = true
						foundFuncs = append(foundFuncs, f)
						positions[f] = pos
						break
					}
				}
			}

			if !found {
				allPresent = false
				break
			}
		}

		if allPresent {
			matches = append(matches, CombinationMatch{
				Combination: combo,
				FoundFuncs:  foundFuncs,
				Positions:   positions,
			})
		}
	}

	return matches
}

// GetHighestScore returns the highest risk score from matches
func GetHighestScore(matches []CombinationMatch) int {
	maxScore := 0
	for _, m := range matches {
		if m.Combination.Score > maxScore {
			maxScore = m.Combination.Score
		}
	}
	return maxScore
}

// GetCriticalMatches returns only critical severity matches
func GetCriticalMatches(matches []CombinationMatch) []CombinationMatch {
	var critical []CombinationMatch
	for _, m := range matches {
		if m.Combination.Severity == "critical" {
			critical = append(critical, m)
		}
	}
	return critical
}
