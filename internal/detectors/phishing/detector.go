package phishing

import (
	"context"
	"regexp"
	"strings"
	"time"

	"github.com/IvanShishkin/houndoom/internal/detectors"
	"github.com/IvanShishkin/houndoom/internal/signatures"
	"github.com/IvanShishkin/houndoom/pkg/models"
)

// Detector detects phishing pages and fake login forms
type Detector struct {
	*detectors.BaseDetector
	matcher          *signatures.Matcher
	level            models.SignatureLevel
	loginFormRe      *regexp.Regexp
	brandKeywordsRe  *regexp.Regexp
	suspiciousFormRe *regexp.Regexp
	credFieldsRe     *regexp.Regexp
}

// Known brand names commonly targeted by phishing
var brandKeywords = `(?i)\b(paypal|facebook|google|microsoft|apple|amazon|netflix|instagram|twitter|linkedin|dropbox|yahoo|outlook|hotmail|gmail|icloud|chase|wellsfargo|bankofamerica|citibank|hsbc|barclays|santander|coinbase|binance|blockchain|metamask)\b`

// Login form patterns
var loginFormPatterns = `(?i)<form[^>]*>.*?(?:` +
	`<input[^>]+type\s*=\s*["']?password["']?|` +
	`<input[^>]+name\s*=\s*["']?(?:pass|pwd|password|passwd)["']?` +
	`).*?</form>`

// Suspicious form action patterns (sending to external/suspicious URLs)
var suspiciousFormPatterns = `(?i)<form[^>]+action\s*=\s*["'](?:` +
	`https?://[^"']*(?:\.tk|\.ml|\.ga|\.cf|\.gq|\.xyz|\.top|\.pw|\.cc)|` +
	`https?://\d+\.\d+\.\d+\.\d+|` +
	`[^"']*(?:login|signin|verify|secure|update|confirm)[^"']*\.php` +
	`)["']`

// Credential field patterns
var credFieldPatterns = `(?i)<input[^>]+(?:` +
	`name\s*=\s*["']?(?:card|cvv|ccv|cvc|expir|ssn|social|pin|account|routing|iban|swift|bic)["']?|` +
	`type\s*=\s*["']?(?:password)["']?[^>]+(?:placeholder|name)\s*=\s*["'][^"']*(?:card|cvv|pin|ssn)` +
	`)`

// NewDetector creates a new phishing detector
func NewDetector(matcher *signatures.Matcher, level models.SignatureLevel) *Detector {
	return &Detector{
		BaseDetector:     detectors.NewBaseDetector("phishing", 85, []string{
			"php", "html", "htm",
		}),
		matcher:          matcher,
		level:            level,
		loginFormRe:      regexp.MustCompile(loginFormPatterns),
		brandKeywordsRe:  regexp.MustCompile(brandKeywords),
		suspiciousFormRe: regexp.MustCompile(suspiciousFormPatterns),
		credFieldsRe:     regexp.MustCompile(credFieldPatterns),
	}
}

// Detect scans a file for phishing indicators
func (d *Detector) Detect(ctx context.Context, file *models.File) ([]*models.Finding, error) {
	var findings []*models.Finding
	content := string(file.Content)
	contentLower := strings.ToLower(content)

	// 1. Check signature database
	matches := d.matcher.Match(file.Content, file.Extension, d.level)
	for _, match := range matches {
		if match.Signature.Category == models.ThreatPhishing {
			fragment, lineNumber := signatures.GetFragment(file.Content, match.Position, 100)
			findings = append(findings, &models.Finding{
				File:          file,
				Type:          models.ThreatPhishing,
				Severity:      match.Signature.Severity,
				SignatureID:   match.Signature.ID,
				SignatureName: match.Signature.Name,
				Description:   match.Signature.Description,
				Position:      match.Position,
				LineNumber:    lineNumber,
				Snippet:       match.Matched,
				Fragment:      fragment,
				Confidence:    75,
				Timestamp:     time.Now(),
			})
		}
	}

	// 2. Check for login forms with brand keywords (possible fake login)
	hasLoginForm := d.loginFormRe.MatchString(content)
	brandMatches := d.brandKeywordsRe.FindAllStringIndex(content, -1)

	if hasLoginForm && len(brandMatches) > 0 {
		// Check if file path doesn't match the brand (likely phishing)
		pathLower := strings.ToLower(file.Path)
		for _, match := range brandMatches {
			brand := strings.ToLower(content[match[0]:match[1]])
			// If brand is mentioned but path doesn't contain official domain
			if !strings.Contains(pathLower, brand) {
				fragment, lineNumber := signatures.GetFragment(file.Content, match[0], 100)
				findings = append(findings, &models.Finding{
					File:          file,
					Type:          models.ThreatPhishing,
					Severity:      models.SeverityHigh,
					SignatureID:   "PHISH-BRAND-LOGIN",
					SignatureName: "Suspected Fake Login Page",
					Description:   "Login form with brand keyword '" + brand + "' detected - possible phishing page",
					Position:      match[0],
					LineNumber:    lineNumber,
					Snippet:       content[match[0]:min(match[1]+50, len(content))],
					Fragment:      fragment,
					Confidence:    70,
					Timestamp:     time.Now(),
				})
				break // One finding per file for brand detection
			}
		}
	}

	// 3. Check for suspicious form actions
	if matches := d.suspiciousFormRe.FindAllStringIndex(content, -1); matches != nil {
		for _, match := range matches {
			fragment, lineNumber := signatures.GetFragment(file.Content, match[0], 100)
			findings = append(findings, &models.Finding{
				File:          file,
				Type:          models.ThreatPhishing,
				Severity:      models.SeverityCritical,
				SignatureID:   "PHISH-SUSP-ACTION",
				SignatureName: "Suspicious Form Action",
				Description:   "Form submitting to suspicious URL (IP address, free domain, or suspicious PHP file)",
				Position:      match[0],
				LineNumber:    lineNumber,
				Snippet:       content[match[0]:min(match[1], match[0]+200)],
				Fragment:      fragment,
				Confidence:    85,
				Timestamp:     time.Now(),
			})
		}
	}

	// 4. Check for credential harvesting fields
	if matches := d.credFieldsRe.FindAllStringIndex(content, -1); matches != nil {
		// Only flag if there's also a form
		if strings.Contains(contentLower, "<form") {
			for _, match := range matches {
				fragment, lineNumber := signatures.GetFragment(file.Content, match[0], 100)
				findings = append(findings, &models.Finding{
					File:          file,
					Type:          models.ThreatPhishing,
					Severity:      models.SeverityHigh,
					SignatureID:   "PHISH-CRED-HARVEST",
					SignatureName: "Credential Harvesting Field",
					Description:   "Form field collecting sensitive data (card numbers, SSN, PIN, etc.)",
					Position:      match[0],
					LineNumber:    lineNumber,
					Snippet:       content[match[0]:min(match[1], match[0]+150)],
					Fragment:      fragment,
					Confidence:    80,
					Timestamp:     time.Now(),
				})
			}
		}
	}

	// 5. Check for phishing kit indicators
	phishingKitIndicators := []string{
		"scam page", "phishing kit", "card details", "verify your account",
		"update your information", "confirm your identity", "suspended account",
		"unusual activity", "verify your payment",
	}

	for _, indicator := range phishingKitIndicators {
		if idx := strings.Index(contentLower, indicator); idx != -1 {
			// Only flag if combined with a form
			if strings.Contains(contentLower, "<form") {
				fragment, lineNumber := signatures.GetFragment(file.Content, idx, 100)
				findings = append(findings, &models.Finding{
					File:          file,
					Type:          models.ThreatPhishing,
					Severity:      models.SeverityMedium,
					SignatureID:   "PHISH-KIT-TEXT",
					SignatureName: "Phishing Kit Text Pattern",
					Description:   "Common phishing text pattern detected: '" + indicator + "'",
					Position:      idx,
					LineNumber:    lineNumber,
					Snippet:       content[idx:min(idx+len(indicator)+50, len(content))],
					Fragment:      fragment,
					Confidence:    65,
					Timestamp:     time.Now(),
				})
				break // One finding per indicator type
			}
		}
	}

	return findings, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
