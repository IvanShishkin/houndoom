package heuristic

import (
	"context"
	"fmt"

	"github.com/IvanShishkin/houndoom/internal/detectors"
	"github.com/IvanShishkin/houndoom/pkg/models"
)

// HeuristicDetector performs heuristic analysis on files
type HeuristicDetector struct {
	*detectors.BaseDetector
	entropyEnabled      bool
	combinationEnabled  bool
	variableEnabled     bool
	structureEnabled    bool
	dataFlowEnabled     bool // NEW: Data flow analysis
	combinationAnalyzer *CombinationAnalyzer
	variableAnalyzer    *VariableAnalyzer
	dataFlowAnalyzer    *DataFlowAnalyzer    // NEW
	contextDetector     *ContextDetector     // NEW
	scoringRules        *models.ScoringRuleSet // NEW
}

// NewHeuristicDetector creates a new heuristic detector
func NewHeuristicDetector() *HeuristicDetector {
	return &HeuristicDetector{
		BaseDetector: detectors.NewBaseDetector(
			"heuristic",
			50, // Lower priority than signature-based
			[]string{"php", "php3", "php4", "php5", "phtml", "inc"},
		),
		entropyEnabled:      true,
		combinationEnabled:  true,
		variableEnabled:     true,
		structureEnabled:    true,
		dataFlowEnabled:     true, // NEW: Enable data flow analysis
		combinationAnalyzer: NewCombinationAnalyzer(),
		variableAnalyzer:    NewVariableAnalyzer(),
		dataFlowAnalyzer:    NewDataFlowAnalyzer(),    // NEW
		contextDetector:     NewContextDetector(),     // NEW
		scoringRules:        models.NewScoringRuleSet(), // NEW
	}
}

// Detect performs heuristic analysis
func (hd *HeuristicDetector) Detect(ctx context.Context, file *models.File) ([]*models.Finding, error) {
	var findings []*models.Finding
	content := string(file.Content)

	// Skip small files
	if len(content) < 100 {
		return findings, nil
	}

	// 1. Entropy analysis
	if hd.entropyEnabled {
		entropyFindings := hd.analyzeEntropy(file, content)
		findings = append(findings, entropyFindings...)
	}

	// 2. Suspicious combinations
	if hd.combinationEnabled {
		comboFindings := hd.analyzeCombinations(file, content)
		findings = append(findings, comboFindings...)
	}

	// 3. Variable patterns
	if hd.variableEnabled {
		varFindings := hd.analyzeVariables(file, content)
		findings = append(findings, varFindings...)
	}

	// 4. Code structure
	if hd.structureEnabled {
		structFindings := hd.analyzeStructure(file, content)
		findings = append(findings, structFindings...)
	}

	// 5. Data flow analysis (NEW - CRITICAL!)
	if hd.dataFlowEnabled {
		dataFlowFindings := hd.analyzeDataFlow(file, content)
		findings = append(findings, dataFlowFindings...)
	}

	return findings, nil
}

func (hd *HeuristicDetector) analyzeEntropy(file *models.File, content string) []*models.Finding {
	var findings []*models.Finding

	analysis := AnalyzeEntropy(content)

	if analysis.IsObfuscated {
		// NEW: Use weighted scoring system
		riskScore := models.NewRiskScore()

		// Detect contexts
		contexts := hd.contextDetector.DetectContexts(content)
		riskScore.Contexts = contexts
		primaryContext := hd.contextDetector.GetPrimaryContext(contexts)

		// Add obfuscated code rule
		if rule := hd.scoringRules.GetRule("610"); rule != nil {
			riskScore.AddRule(rule, primaryContext)
		}

		// Add encoded code rule if entropy is very high
		if analysis.Overall > 5.5 {
			if rule := hd.scoringRules.GetRule("665"); rule != nil {
				riskScore.AddRule(rule, primaryContext)
			}
		}

		// Calculate final score
		riskScore.Calculate()
		severity := riskScore.GetSeverity()

		finding := &models.Finding{
			File:          file,
			Type:          models.ThreatPHPObfuscated,
			Severity:      severity,
			SignatureID:   "HEUR-001",
			SignatureName: "High Entropy Content",
			Description:   fmt.Sprintf("File has high entropy (%.2f) indicating possible obfuscation", analysis.Overall),
			Confidence:    analysis.Confidence, // Legacy
			RiskScore:     riskScore,           // NEW
			Snippet:       fmt.Sprintf("Entropy: %.2f (threshold: %.2f)", analysis.Overall, EntropyObfuscated),
			Metadata: map[string]interface{}{
				"entropy":      analysis.Overall,
				"max_chunk":    analysis.Max,
				"is_heuristic": true,
				"contexts":     GetContextDescription(contexts),
				"weight":       riskScore.TotalWeight,
			},
		}
		findings = append(findings, finding)
	}

	return findings
}

func (hd *HeuristicDetector) analyzeCombinations(file *models.File, content string) []*models.Finding {
	var findings []*models.Finding

	matches := hd.combinationAnalyzer.Analyze(content)

	// Detect contexts for weighted scoring
	contexts := hd.contextDetector.DetectContexts(content)
	primaryContext := hd.contextDetector.GetPrimaryContext(contexts)

	for _, match := range matches {
		// NEW: Use weighted scoring
		riskScore := models.NewRiskScore()
		riskScore.Contexts = contexts

		// Map combination to scoring rules
		funcNames := match.FoundFuncs
		for _, fn := range funcNames {
			var ruleID string
			switch fn {
			case "eval":
				ruleID = "300"
			case "create_function":
				ruleID = "303"
			case "base64_decode":
				ruleID = "321"
			case "mysql_query", "mysqli_query":
				ruleID = "298"
			case "mail":
				ruleID = "299"
			case "exec", "system", "passthru", "shell_exec":
				ruleID = "300-cmd"
			case "file_get_contents", "file_put_contents", "fopen", "fwrite":
				ruleID = "302-file"
			}

			if ruleID != "" {
				if rule := hd.scoringRules.GetRule(ruleID); rule != nil {
					riskScore.AddRule(rule, primaryContext)
				}
			}
		}

		// Add combination bonus weight
		comboWeight := float64(match.Combination.Score) / 100.0
		riskScore.TotalWeight += comboWeight

		// Calculate final score
		riskScore.Calculate()
		severity := riskScore.GetSeverity()

		// Find first position for reporting
		position := 0
		for _, pos := range match.Positions {
			if position == 0 || pos < position {
				position = pos
			}
		}

		finding := &models.Finding{
			File:          file,
			Type:          models.ThreatPHPSuspicious,
			Severity:      severity,
			SignatureID:   "HEUR-002",
			SignatureName: match.Combination.Name,
			Description:   match.Combination.Description,
			Position:      position,
			Confidence:    match.Combination.Score, // Legacy
			RiskScore:     riskScore,               // NEW
			Snippet:       fmt.Sprintf("Found: %v", match.FoundFuncs),
			Metadata: map[string]interface{}{
				"functions":    match.FoundFuncs,
				"risk_score":   match.Combination.Score,
				"is_heuristic": true,
				"contexts":     GetContextDescription(contexts),
				"weight":       riskScore.TotalWeight,
			},
		}
		findings = append(findings, finding)
	}

	return findings
}

func (hd *HeuristicDetector) analyzeVariables(file *models.File, content string) []*models.Finding {
	var findings []*models.Finding

	analysis := hd.variableAnalyzer.Analyze(content)

	// Detect contexts
	contexts := hd.contextDetector.DetectContexts(content)
	primaryContext := hd.contextDetector.GetPrimaryContext(contexts)

	// Only report if significant obfuscation detected
	if analysis.ObfuscationScore >= 50 && analysis.SuspiciousCount >= 3 {
		// NEW: Use weighted scoring
		riskScore := models.NewRiskScore()
		riskScore.Contexts = contexts

		// Add strange vars rule
		if rule := hd.scoringRules.GetRule("610"); rule != nil {
			riskScore.AddRule(rule, primaryContext)
		}

		// Add additional weight based on obfuscation score
		riskScore.TotalWeight += float64(analysis.ObfuscationScore) / 200.0

		riskScore.Calculate()
		severity := riskScore.GetSeverity()

		finding := &models.Finding{
			File:          file,
			Type:          models.ThreatPHPObfuscated,
			Severity:      severity,
			SignatureID:   "HEUR-003",
			SignatureName: "Suspicious Variable Names",
			Description:   fmt.Sprintf("Found %d suspicious variable naming patterns", analysis.SuspiciousCount),
			Confidence:    analysis.ObfuscationScore,
			RiskScore:     riskScore, // NEW
			Snippet:       hd.formatSuspiciousVars(analysis.SuspiciousVars),
			Metadata: map[string]interface{}{
				"suspicious_count": analysis.SuspiciousCount,
				"total_vars":       analysis.TotalVariables,
				"patterns":         analysis.UniquePatterns,
				"is_heuristic":     true,
				"contexts":         GetContextDescription(contexts),
				"weight":           riskScore.TotalWeight,
			},
		}
		findings = append(findings, finding)
	}

	// Long strings detection - encoded payloads
	if analysis.LongStrings >= 5 {
		riskScore := models.NewRiskScore()
		riskScore.Contexts = contexts

		// Add long line rule
		if rule := hd.scoringRules.GetRule("630"); rule != nil {
			riskScore.AddRule(rule, primaryContext)
		}

		// Add encoded code rule if many long strings
		if analysis.LongStrings >= 10 {
			if rule := hd.scoringRules.GetRule("665"); rule != nil {
				riskScore.AddRule(rule, primaryContext)
			}
		}

		riskScore.Calculate()

		finding := &models.Finding{
			File:          file,
			Type:          models.ThreatPHPObfuscated,
			Severity:      riskScore.GetSeverity(),
			SignatureID:   "HEUR-004",
			SignatureName: "Long Encoded Strings",
			Description:   fmt.Sprintf("Found %d very long strings (possible encoded payloads)", analysis.LongStrings),
			Confidence:    50 + analysis.LongStrings*5,
			RiskScore:     riskScore, // NEW
			Metadata: map[string]interface{}{
				"long_string_count": analysis.LongStrings,
				"is_heuristic":      true,
				"contexts":          GetContextDescription(contexts),
				"weight":            riskScore.TotalWeight,
			},
		}
		findings = append(findings, finding)
	}

	return findings
}

func (hd *HeuristicDetector) analyzeStructure(file *models.File, content string) []*models.Finding {
	var findings []*models.Finding

	analysis := AnalyzeCodeStructure(content)

	if analysis.IsMinified && analysis.Score >= 70 {
		// NEW: Use weighted scoring
		contexts := hd.contextDetector.DetectContexts(content)
		primaryContext := hd.contextDetector.GetPrimaryContext(contexts)

		riskScore := models.NewRiskScore()
		riskScore.Contexts = contexts

		// Add long line rule for minified code
		if rule := hd.scoringRules.GetRule("630"); rule != nil {
			riskScore.AddRule(rule, primaryContext)
		}

		// Minified code is often obfuscated - add additional context
		if analysis.MaxLineLength > 1000 {
			if rule := hd.scoringRules.GetRule("610"); rule != nil {
				riskScore.AddRule(rule, primaryContext)
			}
		}

		riskScore.Calculate()

		finding := &models.Finding{
			File:          file,
			Type:          models.ThreatPHPSuspicious,
			Severity:      riskScore.GetSeverity(),
			SignatureID:   "HEUR-005",
			SignatureName: "Minified/Compressed Code",
			Description:   fmt.Sprintf("Code appears minified (max line: %d chars)", analysis.MaxLineLength),
			Confidence:    analysis.Score,
			RiskScore:     riskScore, // NEW
			Metadata: map[string]interface{}{
				"max_line_length": analysis.MaxLineLength,
				"avg_line_length": analysis.AverageLineLength,
				"total_lines":     analysis.TotalLines,
				"is_heuristic":    true,
				"contexts":        GetContextDescription(contexts),
				"weight":          riskScore.TotalWeight,
			},
		}
		findings = append(findings, finding)
	}

	return findings
}

func (hd *HeuristicDetector) formatSuspiciousVars(vars []SuspiciousVariable) string {
	if len(vars) == 0 {
		return ""
	}

	maxShow := 5
	if len(vars) < maxShow {
		maxShow = len(vars)
	}

	result := ""
	for i := 0; i < maxShow; i++ {
		if i > 0 {
			result += ", "
		}
		result += "$" + vars[i].Name
	}

	if len(vars) > maxShow {
		result += fmt.Sprintf(" ... and %d more", len(vars)-maxShow)
	}

	return result
}

// analyzeDataFlow performs data flow analysis to detect dangerous flows
// This is one of the most critical heuristics from Bitrix XScan
func (hd *HeuristicDetector) analyzeDataFlow(file *models.File, content string) []*models.Finding {
	var findings []*models.Finding

	// Perform data flow analysis
	dataFlows := hd.dataFlowAnalyzer.Analyze(content)

	for _, flow := range dataFlows {
		// Use the calculated risk score from flow analysis
		severity := flow.RiskScore.GetSeverity()

		finding := &models.Finding{
			File:          file,
			Type:          models.ThreatPHPInjection,
			Severity:      severity,
			SignatureID:   "HEUR-DF-001",
			SignatureName: fmt.Sprintf("Dangerous Data Flow: %s to %s", flow.SourceType, flow.TargetFunction),
			Description:   GetFlowDescription(flow),
			Position:      flow.Position,
			Confidence:    flow.RiskScore.NormalizedScore, // Legacy field
			RiskScore:     flow.RiskScore,                 // NEW: Weighted risk score
			Snippet:       flow.CodeSnippet,
			Metadata: map[string]interface{}{
				"source_type":    flow.SourceType,
				"source_var":     flow.SourceVar,
				"target_function": flow.TargetFunction,
				"flow_path":      flow.FlowPath,
				"is_heuristic":   true,
				"is_data_flow":   true,
				"contexts":       GetContextDescription(flow.RiskScore.Contexts),
				"weight":         flow.RiskScore.TotalWeight,
				"applied_rules":  flow.RiskScore.Rules,
			},
		}

		findings = append(findings, finding)
	}

	return findings
}
