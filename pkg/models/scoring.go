package models

import "math"

// ScoringContext represents the context where a threat was detected
// Different contexts have different risk weights
type ScoringContext int

const (
	// ContextDefault - default/base context
	ContextDefault ScoringContext = iota
	// ContextUserInput - code handles user input ($_GET, $_POST, etc)
	ContextUserInput
	// ContextFileOperation - file operations
	ContextFileOperation
	// ContextNetworkOperation - network operations
	ContextNetworkOperation
	// ContextEval - code contains eval/assert/create_function
	ContextEval
	// ContextDatabaseOperation - database operations
	ContextDatabaseOperation
	// ContextSystemCall - system calls
	ContextSystemCall
	// ContextObfuscated - obfuscated code
	ContextObfuscated
	// ContextEncoded - encoded content
	ContextEncoded
)

// WeightedRule represents a scoring rule with context-dependent weights
// Based on Bitrix XScan scoring system where each rule can have multiple weights
type WeightedRule struct {
	ID          string             // Rule identifier (e.g., "[300] eval")
	Name        string             // Human-readable name
	Description string             // Rule description
	Weights     map[ScoringContext]float64 // Weight per context (0.0-1.0)
	BaseWeight  float64            // Default weight if context not found
}

// RiskScore accumulates risk from multiple rules and contexts
type RiskScore struct {
	TotalWeight    float64                    // Accumulated weight (0.0+)
	NormalizedScore int                       // Normalized score (0-100)
	Rules          []string                   // Applied rule IDs
	Contexts       map[ScoringContext]bool    // Detected contexts
	Details        map[string]float64         // Rule ID -> contributed weight
}

// NewRiskScore creates a new risk score accumulator
func NewRiskScore() *RiskScore {
	return &RiskScore{
		TotalWeight:    0.0,
		NormalizedScore: 0,
		Rules:          make([]string, 0),
		Contexts:       make(map[ScoringContext]bool),
		Details:        make(map[string]float64),
	}
}

// AddRule adds a weighted rule to the risk score
func (rs *RiskScore) AddRule(rule *WeightedRule, context ScoringContext) {
	weight := rule.BaseWeight

	// Use context-specific weight if available
	if w, ok := rule.Weights[context]; ok {
		weight = w
	}

	rs.TotalWeight += weight
	rs.Rules = append(rs.Rules, rule.ID)
	rs.Contexts[context] = true
	rs.Details[rule.ID] = weight
}

// Calculate normalizes the total weight to 0-100 score
// Uses sigmoid function for smooth normalization
func (rs *RiskScore) Calculate() int {
	// Sigmoid normalization: score = 100 / (1 + e^(-k*(weight-offset)))
	// k = 2 (sensitivity), offset = 1.5 (midpoint)
	k := 2.0
	offset := 1.5

	normalized := 100.0 / (1.0 + math.Exp(-k*(rs.TotalWeight-offset)))

	// Ensure bounds
	if normalized > 100 {
		normalized = 100
	} else if normalized < 0 {
		normalized = 0
	}

	rs.NormalizedScore = int(math.Round(normalized))
	return rs.NormalizedScore
}

// IsCritical returns true if score indicates critical threat
func (rs *RiskScore) IsCritical() bool {
	return rs.TotalWeight >= 2.0 || rs.NormalizedScore >= 90
}

// IsHigh returns true if score indicates high risk
func (rs *RiskScore) IsHigh() bool {
	return rs.TotalWeight >= 1.5 || rs.NormalizedScore >= 75
}

// IsMedium returns true if score indicates medium risk
func (rs *RiskScore) IsMedium() bool {
	return rs.TotalWeight >= 0.8 || rs.NormalizedScore >= 50
}

// GetSeverity returns severity based on accumulated score
func (rs *RiskScore) GetSeverity() Severity {
	if rs.IsCritical() {
		return SeverityCritical
	} else if rs.IsHigh() {
		return SeverityHigh
	} else if rs.IsMedium() {
		return SeverityMedium
	} else if rs.TotalWeight > 0 {
		return SeverityLow
	}
	return SeverityInfo
}

// ScoringRuleSet manages a collection of weighted rules
// Based on Bitrix XScan $scoring array
type ScoringRuleSet struct {
	rules map[string]*WeightedRule
}

// NewScoringRuleSet creates a new rule set with Bitrix-inspired rules
func NewScoringRuleSet() *ScoringRuleSet {
	rs := &ScoringRuleSet{
		rules: make(map[string]*WeightedRule),
	}

	// Initialize with Bitrix XScan scoring rules
	rs.initializeBitrixRules()

	return rs
}

// initializeBitrixRules initializes the scoring rules based on Bitrix XScan
func (rs *ScoringRuleSet) initializeBitrixRules() {
	// [300] eval - critical, but weight depends on context
	rs.AddRule(&WeightedRule{
		ID:          "300",
		Name:        "eval",
		Description: "Use of eval() function",
		BaseWeight:  1.0,
		Weights: map[ScoringContext]float64{
			ContextDefault:          1.0,
			ContextUserInput:        0.4, // Lower weight with user input (will be combined later)
			ContextFileOperation:    0.1,
			ContextNetworkOperation: 1.0,
			ContextEval:             0.8,
			ContextDatabaseOperation: 0.3,
			ContextSystemCall:       0.7,
			ContextObfuscated:       0.8,
			ContextEncoded:          0.9,
		},
	})

	// [303] create_function - dangerous function
	rs.AddRule(&WeightedRule{
		ID:          "303",
		Name:        "create_function",
		Description: "Use of create_function()",
		BaseWeight:  0.8,
		Weights: map[ScoringContext]float64{
			ContextDefault:          0.8,
			ContextUserInput:        0.8,
			ContextFileOperation:    0.1,
			ContextNetworkOperation: 1.0,
			ContextEval:             0.8,
			ContextDatabaseOperation: 0.3,
			ContextSystemCall:       0.7,
			ContextObfuscated:       0.8,
			ContextEncoded:          0.8,
		},
	})

	// [307] danger method - critical Bitrix methods
	rs.AddRule(&WeightedRule{
		ID:          "307",
		Name:        "danger method",
		Description: "Dangerous Bitrix method call",
		BaseWeight:  1.0,
		Weights: map[ScoringContext]float64{
			ContextDefault:          1.0,
			ContextUserInput:        0.4,
			ContextFileOperation:    0.1,
			ContextNetworkOperation: 1.0,
			ContextEval:             0.8,
			ContextDatabaseOperation: 0.3,
			ContextSystemCall:       0.7,
			ContextObfuscated:       0.8,
			ContextEncoded:          0.9,
		},
	})

	// [321] base64_encoded code
	rs.AddRule(&WeightedRule{
		ID:          "321",
		Name:        "base64_encoded code",
		Description: "Base64 encoded code detected",
		BaseWeight:  0.8,
	})

	// [337] strings from black list
	rs.AddRule(&WeightedRule{
		ID:          "337",
		Name:        "strings from black list",
		Description: "Known malicious strings",
		BaseWeight:  0.9,
	})

	// [610] strange vars
	rs.AddRule(&WeightedRule{
		ID:          "610",
		Name:        "strange vars",
		Description: "Obfuscated variable names",
		BaseWeight:  0.5,
	})

	// [630] long line
	rs.AddRule(&WeightedRule{
		ID:          "630",
		Name:        "long line",
		Description: "Suspiciously long line",
		BaseWeight:  0.4,
	})

	// [640] strange exif
	rs.AddRule(&WeightedRule{
		ID:          "640",
		Name:        "strange exif",
		Description: "Suspicious EXIF data",
		BaseWeight:  0.6,
	})

	// [650] variable as a function
	rs.AddRule(&WeightedRule{
		ID:          "650",
		Name:        "variable as a function",
		Description: "Variable used as function name",
		BaseWeight:  0.9,
		Weights: map[ScoringContext]float64{
			ContextDefault:          0.9,
			ContextUserInput:        0.8,
			ContextFileOperation:    0.1,
			ContextNetworkOperation: 1.0,
			ContextEval:             0.8,
			ContextDatabaseOperation: 0.3,
			ContextSystemCall:       0.5,
			ContextObfuscated:       0.8,
			ContextEncoded:          0.8,
		},
	})

	// [660] array member as a function
	rs.AddRule(&WeightedRule{
		ID:          "660",
		Name:        "array member as a function",
		Description: "Array element used as function",
		BaseWeight:  0.9,
		Weights: map[ScoringContext]float64{
			ContextDefault:          0.9,
			ContextUserInput:        0.8,
			ContextFileOperation:    0.1,
			ContextNetworkOperation: 1.0,
			ContextEval:             0.8,
			ContextDatabaseOperation: 0.3,
			ContextSystemCall:       0.5,
			ContextObfuscated:       0.8,
			ContextEncoded:          0.8,
		},
	})

	// [662] function return as a function
	rs.AddRule(&WeightedRule{
		ID:          "662",
		Name:        "function return as a function",
		Description: "Function return value used as function",
		BaseWeight:  0.9,
		Weights: map[ScoringContext]float64{
			ContextDefault:          0.9,
			ContextUserInput:        0.8,
			ContextFileOperation:    0.1,
			ContextNetworkOperation: 1.0,
			ContextEval:             1.0,
			ContextDatabaseOperation: 0.3,
			ContextSystemCall:       0.7,
			ContextObfuscated:       0.7,
			ContextEncoded:          0.8,
		},
	})

	// [663] strange function
	rs.AddRule(&WeightedRule{
		ID:          "663",
		Name:        "strange function",
		Description: "Suspicious function pattern",
		BaseWeight:  1.0,
		Weights: map[ScoringContext]float64{
			ContextDefault:          1.0,
			ContextUserInput:        1.0,
			ContextFileOperation:    0.1,
			ContextNetworkOperation: 1.0,
			ContextEval:             1.0,
			ContextDatabaseOperation: 0.8,
			ContextSystemCall:       0.7,
			ContextObfuscated:       0.8,
			ContextEncoded:          0.9,
		},
	})

	// [665] encoded code
	rs.AddRule(&WeightedRule{
		ID:          "665",
		Name:        "encoded code",
		Description: "Encoded/encrypted code",
		BaseWeight:  0.8,
	})

	// [500] php wrapper
	rs.AddRule(&WeightedRule{
		ID:          "500",
		Name:        "php wrapper",
		Description: "PHP stream wrapper usage",
		BaseWeight:  0.7,
	})

	// [302] preg_replace_eval
	rs.AddRule(&WeightedRule{
		ID:          "302",
		Name:        "preg_replace_eval",
		Description: "preg_replace with /e modifier",
		BaseWeight:  0.9,
	})

	// [298] mysql function
	rs.AddRule(&WeightedRule{
		ID:          "298",
		Name:        "mysql function",
		Description: "Direct MySQL function usage",
		BaseWeight:  0.6,
		Weights: map[ScoringContext]float64{
			ContextDefault:          0.6,
			ContextUserInput:        0.8,
			ContextFileOperation:    0.1,
			ContextNetworkOperation: 1.0,
			ContextEval:             0.8,
			ContextDatabaseOperation: 0.9,
			ContextSystemCall:       0.7,
			ContextObfuscated:       0.8,
			ContextEncoded:          0.8,
		},
	})

	// [299] mail function
	rs.AddRule(&WeightedRule{
		ID:          "299",
		Name:        "mail function",
		Description: "Mail function usage",
		BaseWeight:  0.6,
		Weights: map[ScoringContext]float64{
			ContextDefault:          0.6,
			ContextUserInput:        0.8,
			ContextFileOperation:    0.1,
			ContextNetworkOperation: 1.0,
			ContextEval:             0.8,
			ContextDatabaseOperation: 0.3,
			ContextSystemCall:       0.7,
			ContextObfuscated:       0.8,
			ContextEncoded:          0.8,
		},
	})

	// [300] command injection
	rs.AddRule(&WeightedRule{
		ID:          "300-cmd",
		Name:        "command injection",
		Description: "System command execution",
		BaseWeight:  1.0,
		Weights: map[ScoringContext]float64{
			ContextDefault:          1.0,
			ContextUserInput:        0.7,
			ContextFileOperation:    0.1,
			ContextNetworkOperation: 1.0,
			ContextEval:             0.8,
			ContextDatabaseOperation: 0.6,
			ContextSystemCall:       0.7,
			ContextObfuscated:       0.8,
			ContextEncoded:          0.9,
		},
	})

	// [301] file operations (low risk)
	rs.AddRule(&WeightedRule{
		ID:          "301",
		Name:        "file operations",
		Description: "File operation functions",
		BaseWeight:  0.5,
		Weights: map[ScoringContext]float64{
			ContextDefault:          0.5,
			ContextUserInput:        0.4,
			ContextFileOperation:    0.1,
			ContextNetworkOperation: 1.0,
			ContextEval:             0.8,
			ContextDatabaseOperation: 0.3,
			ContextSystemCall:       0.7,
			ContextObfuscated:       0.8,
			ContextEncoded:          0.8,
		},
	})

	// [302] file operations (high risk)
	rs.AddRule(&WeightedRule{
		ID:          "302-file",
		Name:        "file operations (dangerous)",
		Description: "Dangerous file operations",
		BaseWeight:  0.8,
		Weights: map[ScoringContext]float64{
			ContextDefault:          0.8,
			ContextUserInput:        0.4,
			ContextFileOperation:    0.1,
			ContextNetworkOperation: 1.0,
			ContextEval:             0.8,
			ContextDatabaseOperation: 0.3,
			ContextSystemCall:       0.7,
			ContextObfuscated:       0.8,
			ContextEncoded:          0.8,
		},
	})

	// [304] filter_callback
	rs.AddRule(&WeightedRule{
		ID:          "304",
		Name:        "filter_callback",
		Description: "filter_var with callback",
		BaseWeight:  0.6,
		Weights: map[ScoringContext]float64{
			ContextDefault:          0.6,
			ContextUserInput:        0.8,
			ContextFileOperation:    0.1,
			ContextNetworkOperation: 1.0,
			ContextEval:             0.8,
			ContextDatabaseOperation: 0.3,
			ContextSystemCall:       0.7,
			ContextObfuscated:       0.8,
			ContextEncoded:          0.8,
		},
	})

	// [305] strange function and eval
	rs.AddRule(&WeightedRule{
		ID:          "305",
		Name:        "strange function and eval",
		Description: "Suspicious function combined with eval",
		BaseWeight:  0.8,
		Weights: map[ScoringContext]float64{
			ContextDefault:          0.8,
			ContextUserInput:        0.8,
			ContextFileOperation:    0.1,
			ContextNetworkOperation: 1.0,
			ContextEval:             0.8,
			ContextDatabaseOperation: 0.3,
			ContextSystemCall:       0.7,
			ContextObfuscated:       0.8,
			ContextEncoded:          0.8,
		},
	})

	// [400] bitrix auth
	rs.AddRule(&WeightedRule{
		ID:          "400",
		Name:        "bitrix auth",
		Description: "Bitrix authentication bypass",
		BaseWeight:  0.9,
		Weights: map[ScoringContext]float64{
			ContextDefault:          0.9,
			ContextUserInput:        0.8,
			ContextFileOperation:    1.0,
			ContextNetworkOperation: 1.0,
			ContextEval:             0.8,
			ContextDatabaseOperation: 0.3,
			ContextSystemCall:       0.7,
			ContextObfuscated:       0.8,
			ContextEncoded:          0.8,
		},
	})

	// [887] backticks (shell execution)
	rs.AddRule(&WeightedRule{
		ID:          "887",
		Name:        "backticks",
		Description: "Backtick shell execution",
		BaseWeight:  1.0,
		Weights: map[ScoringContext]float64{
			ContextDefault:          1.0,
			ContextUserInput:        0.8,
			ContextFileOperation:    0.1,
			ContextNetworkOperation: 1.0,
			ContextEval:             0.8,
			ContextDatabaseOperation: 0.3,
			ContextSystemCall:       0.7,
			ContextObfuscated:       0.8,
			ContextEncoded:          0.8,
		},
	})
}

// AddRule adds a weighted rule to the set
func (rs *ScoringRuleSet) AddRule(rule *WeightedRule) {
	rs.rules[rule.ID] = rule
}

// GetRule retrieves a rule by ID
func (rs *ScoringRuleSet) GetRule(id string) *WeightedRule {
	return rs.rules[id]
}

// GetAllRules returns all rules
func (rs *ScoringRuleSet) GetAllRules() map[string]*WeightedRule {
	return rs.rules
}
