package models

import "time"

// Finding represents a detected threat or issue
type Finding struct {
	File          *File          // Reference to the scanned file
	Type          ThreatType     // Type of threat
	Severity      Severity       // Severity level
	SignatureID   string         // Signature ID that matched
	SignatureName string         // Human-readable signature name
	Description   string         // Description of the finding
	Position      int            // Position in file where threat was found
	LineNumber    int            // Line number
	Snippet       string         // Code snippet around the finding
	Fragment      string         // Formatted fragment with markers
	Confidence    int            // Confidence level (0-100) - legacy, use RiskScore instead
	RiskScore     *RiskScore     // New weighted risk scoring system
	Timestamp     time.Time      // When the finding was detected
	Metadata      map[string]any // Additional metadata
}

// ThreatType represents the type of threat detected
type ThreatType string

const (
	ThreatPHPBackdoor      ThreatType = "php_backdoor"
	ThreatPHPShell         ThreatType = "php_shell"
	ThreatPHPMalware       ThreatType = "php_malware"
	ThreatPHPInjection     ThreatType = "php_injection"
	ThreatPHPObfuscated    ThreatType = "php_obfuscated"
	ThreatPHPSuspicious    ThreatType = "php_suspicious"
	ThreatJSVirus          ThreatType = "js_virus"
	ThreatJSMalware        ThreatType = "js_malware"
	ThreatJSObfuscated     ThreatType = "js_obfuscated"
	ThreatJSSuspicious     ThreatType = "js_suspicious"
	ThreatXSS              ThreatType = "xss"
	ThreatIframe           ThreatType = "iframe_injection"
	ThreatPhishing         ThreatType = "phishing"
	ThreatAdware           ThreatType = "adware"
	ThreatSpam             ThreatType = "spam_links"
	ThreatDoorway          ThreatType = "doorway"
	ThreatRedirect         ThreatType = "redirect"
	ThreatExecutable       ThreatType = "unix_executable"
	ThreatSuspicious       ThreatType = "suspicious"
	ThreatVulnerability    ThreatType = "vulnerability"
	ThreatObfuscated       ThreatType = "obfuscated"
	ThreatHiddenFile       ThreatType = "hidden_file"
	ThreatSymlink          ThreatType = "symlink"
	ThreatModified         ThreatType = "modified_file"
	ThreatUnknown          ThreatType = "unknown"
)

// Severity represents the severity level of a finding
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// GetSeverityPriority returns numeric priority for severity (higher = more severe)
func GetSeverityPriority(s Severity) int {
	switch s {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	case SeverityInfo:
		return 1
	default:
		return 0
	}
}
