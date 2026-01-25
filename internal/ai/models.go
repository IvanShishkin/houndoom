package ai

import "time"

// Verdict represents the AI's classification of a finding
type Verdict string

const (
	VerdictMalicious    Verdict = "malicious"
	VerdictSuspicious   Verdict = "suspicious"
	VerdictFalsePositive Verdict = "false_positive"
	VerdictBenign       Verdict = "benign"
	VerdictUnknown      Verdict = "unknown"
)

// AnalysisRequest contains data sent to the AI for analysis
type AnalysisRequest struct {
	FindingID     string `json:"finding_id"`
	SignatureName string `json:"signature_name"`
	SignatureID   string `json:"signature_id"`
	Description   string `json:"description"`
	FilePath      string `json:"file_path"`
	LineNumber    int    `json:"line_number"`
	CodeFragment  string `json:"code_fragment"`
	Severity      string `json:"severity"`
	ThreatType    string `json:"threat_type"`
	Confidence    int    `json:"confidence"`
	CMSContext    string `json:"cms_context,omitempty"`
}

// AnalysisResponse contains the AI's analysis result
type AnalysisResponse struct {
	FindingID    string   `json:"finding_id"`
	Verdict      Verdict  `json:"verdict"`
	Confidence   int      `json:"confidence"`    // 0-100
	Explanation  string   `json:"explanation"`
	Remediation  string   `json:"remediation,omitempty"`
	Indicators   []string `json:"indicators,omitempty"`
	RiskLevel    string   `json:"risk_level"` // critical, high, medium, low
	TokensUsed   int      `json:"tokens_used"`
}

// QuickFilterResult contains the result of Haiku pre-filtering
type QuickFilterResult struct {
	FindingID     string  `json:"finding_id"`
	NeedsAnalysis bool    `json:"needs_analysis"`
	Reason        string  `json:"reason"`
	Confidence    int     `json:"confidence"`
	TokensUsed    int     `json:"tokens_used"`
}

// AIReport contains aggregated AI analysis results
type AIReport struct {
	Model            string             `json:"model"`
	Language         string             `json:"language"`
	AnalyzedCount    int                `json:"analyzed_count"`
	FilteredCount    int                `json:"filtered_count"`
	StartTime        time.Time          `json:"start_time"`
	EndTime          time.Time          `json:"end_time"`
	Duration         time.Duration      `json:"duration"`
	TotalTokensUsed  int                `json:"total_tokens_used"`
	Results          []*AnalysisResponse `json:"results"`
	FilterResults    []*QuickFilterResult `json:"filter_results,omitempty"`

	// Verdict statistics
	MaliciousCount    int `json:"malicious_count"`
	SuspiciousCount   int `json:"suspicious_count"`
	FalsePositiveCount int `json:"false_positive_count"`
	BenignCount       int `json:"benign_count"`
	UnknownCount      int `json:"unknown_count"`

	// Smart mode stats
	IsSmartMode      bool `json:"is_smart_mode,omitempty"`
	UniqueSignatures int  `json:"unique_signatures,omitempty"`
	SampledFindings  int  `json:"sampled_findings,omitempty"`

	// Errors
	Errors []string `json:"errors,omitempty"`
}

// GetResultByFindingID returns the analysis result for a specific finding
func (r *AIReport) GetResultByFindingID(findingID string) *AnalysisResponse {
	for _, result := range r.Results {
		if result.FindingID == findingID {
			return result
		}
	}
	return nil
}

// GetVerdictColor returns the CSS color class for a verdict
func GetVerdictColor(v Verdict) string {
	switch v {
	case VerdictMalicious:
		return "critical"
	case VerdictSuspicious:
		return "high"
	case VerdictFalsePositive:
		return "low"
	case VerdictBenign:
		return "info"
	default:
		return "medium"
	}
}

// GetVerdictEmoji returns the emoji for a verdict
func GetVerdictEmoji(v Verdict) string {
	switch v {
	case VerdictMalicious:
		return "🔴"
	case VerdictSuspicious:
		return "🟠"
	case VerdictFalsePositive:
		return "🟢"
	case VerdictBenign:
		return "🔵"
	default:
		return "⚪"
	}
}


// CostEstimate represents estimated API costs for AI analysis
type CostEstimate struct {
	Model            string
	FindingsCount    int
	QuickFilter      bool
	SmartMode        bool
	EstimatedTokens  int
	EstimatedCostUSD float64
	SampledCount     int // Number of findings to analyze after smart mode sampling
}

// TokenPricing contains pricing per million tokens for each model
type TokenPricing struct {
	InputPerMillion  float64
	OutputPerMillion float64
}

// ModelPricing returns pricing for a model
func ModelPricing(model string) TokenPricing {
	switch model {
	case "haiku", "claude-3-haiku", "claude-3-5-haiku-latest":
		return TokenPricing{InputPerMillion: 0.25, OutputPerMillion: 1.25}
	case "opus", "claude-3-opus":
		return TokenPricing{InputPerMillion: 15.0, OutputPerMillion: 75.0}
	default: // sonnet
		return TokenPricing{InputPerMillion: 3.0, OutputPerMillion: 15.0}
	}
}

// EstimateCost calculates estimated cost for AI analysis
func EstimateCost(model string, findingsCount int, quickFilter bool) *CostEstimate {
	return EstimateCostWithModes(model, findingsCount, quickFilter, false, 0)
}

// EstimateCostWithModes calculates estimated cost with smart mode
func EstimateCostWithModes(model string, findingsCount int, quickFilter, smartMode bool, uniqueSignatures int) *CostEstimate {
	// Average tokens per finding (based on actual prompts)
	const (
		deepInputTokens   = 1950 // system + user prompt
		deepOutputTokens  = 400  // response
		haikuInputTokens  = 900  // quick filter prompt
		haikuOutputTokens = 75   // quick filter response
		filterRate        = 0.65 // ~65% filtered out by Haiku

		// Smart mode - samples per signature
		samplesPerSignature = 3
	)

	estimate := &CostEstimate{
		Model:         model,
		FindingsCount: findingsCount,
		QuickFilter:   quickFilter,
		SmartMode:     smartMode,
	}

	pricing := ModelPricing(model)
	var totalCost float64

	if smartMode {
		// Smart mode: sample N findings per signature
		sampledCount := uniqueSignatures * samplesPerSignature
		if sampledCount > findingsCount {
			sampledCount = findingsCount
		}
		if sampledCount < 1 {
			sampledCount = 1
		}
		estimate.SampledCount = sampledCount

		if quickFilter && sampledCount > 5 {
			// Haiku quick filter for sampled
			haikuPricing := ModelPricing("haiku")
			haikuInputTotal := float64(sampledCount * haikuInputTokens)
			haikuOutputTotal := float64(sampledCount * haikuOutputTokens)
			haikuCost := (haikuInputTotal/1_000_000)*haikuPricing.InputPerMillion +
				(haikuOutputTotal/1_000_000)*haikuPricing.OutputPerMillion

			// Deep analysis for remaining
			remainingFindings := int(float64(sampledCount) * (1 - filterRate))
			if remainingFindings < 1 {
				remainingFindings = 1
			}
			deepInputTotal := float64(remainingFindings * deepInputTokens)
			deepOutputTotal := float64(remainingFindings * deepOutputTokens)
			deepCost := (deepInputTotal/1_000_000)*pricing.InputPerMillion +
				(deepOutputTotal/1_000_000)*pricing.OutputPerMillion

			estimate.EstimatedTokens = int(haikuInputTotal + haikuOutputTotal + deepInputTotal + deepOutputTotal)
			totalCost = haikuCost + deepCost
		} else {
			// Direct deep analysis for sampled
			inputTotal := float64(sampledCount * deepInputTokens)
			outputTotal := float64(sampledCount * deepOutputTokens)
			estimate.EstimatedTokens = int(inputTotal + outputTotal)
			totalCost = (inputTotal/1_000_000)*pricing.InputPerMillion +
				(outputTotal/1_000_000)*pricing.OutputPerMillion
		}
	} else if quickFilter && findingsCount > 5 {
		// Standard mode with quick filter
		haikuPricing := ModelPricing("haiku")
		haikuInputTotal := float64(findingsCount * haikuInputTokens)
		haikuOutputTotal := float64(findingsCount * haikuOutputTokens)
		haikuCost := (haikuInputTotal/1_000_000)*haikuPricing.InputPerMillion +
			(haikuOutputTotal/1_000_000)*haikuPricing.OutputPerMillion

		remainingFindings := int(float64(findingsCount) * (1 - filterRate))
		if remainingFindings < 1 {
			remainingFindings = 1
		}
		deepInputTotal := float64(remainingFindings * deepInputTokens)
		deepOutputTotal := float64(remainingFindings * deepOutputTokens)
		deepCost := (deepInputTotal/1_000_000)*pricing.InputPerMillion +
			(deepOutputTotal/1_000_000)*pricing.OutputPerMillion

		estimate.EstimatedTokens = int(haikuInputTotal + haikuOutputTotal + deepInputTotal + deepOutputTotal)
		estimate.SampledCount = remainingFindings
		totalCost = haikuCost + deepCost
	} else {
		// Direct deep analysis for all
		inputTotal := float64(findingsCount * deepInputTokens)
		outputTotal := float64(findingsCount * deepOutputTokens)
		estimate.EstimatedTokens = int(inputTotal + outputTotal)
		estimate.SampledCount = findingsCount
		totalCost = (inputTotal/1_000_000)*pricing.InputPerMillion +
			(outputTotal/1_000_000)*pricing.OutputPerMillion
	}

	estimate.EstimatedCostUSD = totalCost
	return estimate
}
