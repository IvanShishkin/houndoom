package heuristic

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/IvanShishkin/houndoom/pkg/models"
)

// DataFlowAnalyzer detects dangerous data flows from user input to dangerous functions
// Based on Bitrix XScan's data flow analysis
type DataFlowAnalyzer struct {
	contextDetector *ContextDetector
	scoringRules    *models.ScoringRuleSet
}

// DataFlowFinding represents a detected dangerous data flow
type DataFlowFinding struct {
	SourceType      string   // Type of input source (GET, POST, etc)
	SourceVar       string   // Variable name receiving input
	TargetFunction  string   // Dangerous function being called
	FlowPath        []string // Path of data flow
	RiskScore       *models.RiskScore
	Position        int
	CodeSnippet     string
}

// NewDataFlowAnalyzer creates a new data flow analyzer
func NewDataFlowAnalyzer() *DataFlowAnalyzer {
	return &DataFlowAnalyzer{
		contextDetector: NewContextDetector(),
		scoringRules:    models.NewScoringRuleSet(),
	}
}

// Analyze performs data flow analysis on PHP code
func (dfa *DataFlowAnalyzer) Analyze(content string) []*DataFlowFinding {
	findings := make([]*DataFlowFinding, 0)

	// Track variable assignments from user input
	userInputVars := dfa.trackUserInputVars(content)

	// Track dangerous function calls
	dangerousCalls := dfa.trackDangerousCalls(content)

	// Find flows: user input -> dangerous function
	flows := dfa.findDataFlows(content, userInputVars, dangerousCalls)
	findings = append(findings, flows...)

	// Find direct flows: dangerous_function($_GET[...])
	directFlows := dfa.findDirectFlows(content)
	findings = append(findings, directFlows...)

	return findings
}

// UserInputVar tracks a variable that receives user input
type UserInputVar struct {
	VarName    string
	SourceType string // GET, POST, REQUEST, COOKIE, FILES
	Position   int
	Line       string
}

// DangerousCall tracks a call to a dangerous function
type DangerousCall struct {
	Function string
	Args     []string
	Position int
	Line     string
}

// trackUserInputVars finds all variables assigned from user input
func (dfa *DataFlowAnalyzer) trackUserInputVars(content string) []UserInputVar {
	vars := make([]UserInputVar, 0)

	// Pattern: $var = $_GET[...] or similar
	pattern := regexp.MustCompile(`\$([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*\$_(GET|POST|REQUEST|COOKIE|FILES|SERVER)\s*\[`)

	lines := strings.Split(content, "\n")
	position := 0

	for _, line := range lines {
		if matches := pattern.FindStringSubmatch(line); matches != nil {
			vars = append(vars, UserInputVar{
				VarName:    matches[1],
				SourceType: matches[2],
				Position:   position,
				Line:       line,
			})
		}
		position += len(line) + 1
	}

	return vars
}

// trackDangerousCalls finds all calls to dangerous functions
func (dfa *DataFlowAnalyzer) trackDangerousCalls(content string) []DangerousCall {
	calls := make([]DangerousCall, 0)

	dangerousFuncs := []string{
		"eval", "assert", "create_function",
		"exec", "system", "passthru", "shell_exec", "popen", "proc_open",
		"file_put_contents", "fwrite", "file_get_contents",
		"include", "require", "include_once", "require_once",
		"mysql_query", "mysqli_query",
		"unserialize",
		"mail",
	}

	lines := strings.Split(content, "\n")
	position := 0

	for _, line := range lines {
		for _, fn := range dangerousFuncs {
			// Pattern: function_name($arg1, $arg2, ...)
			pattern := regexp.MustCompile(`(?i)\b` + fn + `\s*\(([^)]*)\)`)
			if matches := pattern.FindStringSubmatch(line); matches != nil {
				// Extract arguments
				args := strings.Split(matches[1], ",")
				for i, arg := range args {
					args[i] = strings.TrimSpace(arg)
				}

				calls = append(calls, DangerousCall{
					Function: fn,
					Args:     args,
					Position: position + strings.Index(line, fn),
					Line:     line,
				})
			}
		}
		position += len(line) + 1
	}

	return calls
}

// findDataFlows identifies flows from user input vars to dangerous functions
func (dfa *DataFlowAnalyzer) findDataFlows(content string, userVars []UserInputVar, calls []DangerousCall) []*DataFlowFinding {
	findings := make([]*DataFlowFinding, 0)

	// Simple flow detection: check if user input variable is used in dangerous call
	for _, userVar := range userVars {
		varPattern := `\$` + regexp.QuoteMeta(userVar.VarName) + `\b`
		varRegex := regexp.MustCompile(varPattern)

		for _, call := range calls {
			// Check if the variable appears in the function arguments
			argsStr := strings.Join(call.Args, " ")
			if varRegex.MatchString(argsStr) {
				// Found a flow!
				finding := &DataFlowFinding{
					SourceType:     userVar.SourceType,
					SourceVar:      userVar.VarName,
					TargetFunction: call.Function,
					FlowPath: []string{
						fmt.Sprintf("$_%s -> $%s", userVar.SourceType, userVar.VarName),
						fmt.Sprintf("$%s -> %s()", userVar.VarName, call.Function),
					},
					Position:    call.Position,
					CodeSnippet: call.Line,
					RiskScore:   dfa.calculateFlowRisk(userVar.SourceType, call.Function),
				}

				findings = append(findings, finding)
			}
		}
	}

	return findings
}

// findDirectFlows identifies direct user input usage in dangerous functions
func (dfa *DataFlowAnalyzer) findDirectFlows(content string) []*DataFlowFinding {
	findings := make([]*DataFlowFinding, 0)

	dangerousFuncs := []string{
		"eval", "assert", "create_function",
		"exec", "system", "passthru", "shell_exec",
		"file_put_contents", "fwrite",
		"include", "require", "include_once", "require_once",
		"mysql_query", "mysqli_query",
		"unserialize",
	}

	lines := strings.Split(content, "\n")
	position := 0

	for _, line := range lines {
		for _, fn := range dangerousFuncs {
			// Pattern: function($_GET[...]) or similar
			pattern := regexp.MustCompile(`(?i)\b` + fn + `\s*\([^)]*\$_(GET|POST|REQUEST|COOKIE|FILES)`)
			if matches := pattern.FindStringSubmatch(line); matches != nil {
				sourceType := matches[1]

				finding := &DataFlowFinding{
					SourceType:     sourceType,
					SourceVar:      "_" + sourceType,
					TargetFunction: fn,
					FlowPath: []string{
						fmt.Sprintf("$_%s -> %s() [DIRECT]", sourceType, fn),
					},
					Position:    position + strings.Index(line, fn),
					CodeSnippet: strings.TrimSpace(line),
					RiskScore:   dfa.calculateFlowRisk(sourceType, fn),
				}

				findings = append(findings, finding)
			}
		}
		position += len(line) + 1
	}

	return findings
}

// calculateFlowRisk calculates risk score for a specific data flow
func (dfa *DataFlowAnalyzer) calculateFlowRisk(sourceType, targetFunc string) *models.RiskScore {
	score := models.NewRiskScore()

	// User input context
	score.Contexts[models.ContextUserInput] = true

	// Determine target context and add rules
	switch strings.ToLower(targetFunc) {
	case "eval", "assert", "create_function":
		// CRITICAL: User input to code execution
		score.Contexts[models.ContextEval] = true

		// Add eval rule with UserInput context
		if rule := dfa.scoringRules.GetRule("300"); rule != nil {
			score.AddRule(rule, models.ContextUserInput)
		}

		// Add additional weight for direct user input
		score.TotalWeight += 1.2 // Extra critical

	case "exec", "system", "passthru", "shell_exec", "popen", "proc_open":
		// CRITICAL: User input to system command
		score.Contexts[models.ContextSystemCall] = true

		if rule := dfa.scoringRules.GetRule("300-cmd"); rule != nil {
			score.AddRule(rule, models.ContextUserInput)
		}

		score.TotalWeight += 1.2

	case "mysql_query", "mysqli_query":
		// HIGH: SQL injection potential
		score.Contexts[models.ContextDatabaseOperation] = true

		if rule := dfa.scoringRules.GetRule("298"); rule != nil {
			score.AddRule(rule, models.ContextUserInput)
		}

		score.TotalWeight += 0.9

	case "file_put_contents", "fwrite":
		// HIGH: User input to file write
		score.Contexts[models.ContextFileOperation] = true

		if rule := dfa.scoringRules.GetRule("302-file"); rule != nil {
			score.AddRule(rule, models.ContextUserInput)
		}

		score.TotalWeight += 0.8

	case "include", "require", "include_once", "require_once":
		// CRITICAL: File inclusion with user input
		score.Contexts[models.ContextFileOperation] = true

		if rule := dfa.scoringRules.GetRule("302-file"); rule != nil {
			score.AddRule(rule, models.ContextUserInput)
		}

		score.TotalWeight += 1.1

	case "unserialize":
		// HIGH: Deserialization with user input
		if rule := dfa.scoringRules.GetRule("665"); rule != nil {
			score.AddRule(rule, models.ContextUserInput)
		}

		score.TotalWeight += 0.9

	case "mail":
		// MEDIUM: Mail header injection potential
		if rule := dfa.scoringRules.GetRule("299"); rule != nil {
			score.AddRule(rule, models.ContextUserInput)
		}

		score.TotalWeight += 0.6

	default:
		// General suspicious flow
		score.TotalWeight += 0.5
	}

	// Calculate final normalized score
	score.Calculate()

	return score
}

// GetFlowDescription returns human-readable flow description
func GetFlowDescription(finding *DataFlowFinding) string {
	if len(finding.FlowPath) == 1 && strings.Contains(finding.FlowPath[0], "DIRECT") {
		return fmt.Sprintf("Direct user input ($_[%s]) passed to %s()",
			finding.SourceType, finding.TargetFunction)
	}

	return fmt.Sprintf("User input from $_[%s] flows through $%s into %s()",
		finding.SourceType, finding.SourceVar, finding.TargetFunction)
}
