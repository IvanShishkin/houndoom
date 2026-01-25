package javascript

import (
	"context"
	"regexp"
	"time"

	"github.com/IvanShishkin/houndoom/internal/detectors"
	"github.com/IvanShishkin/houndoom/internal/signatures"
	"github.com/IvanShishkin/houndoom/pkg/models"
)

// XSS attack patterns
var xssPatterns = []struct {
	pattern     string
	name        string
	description string
	severity    models.Severity
}{
	// Event handlers in attributes
	{
		pattern:     `(?i)<[^>]+\s+on(load|error|click|mouseover|mouseout|focus|blur|submit|change|keyup|keydown|keypress)\s*=`,
		name:        "Event Handler XSS",
		description: "Potential XSS via inline event handler attribute",
		severity:    models.SeverityHigh,
	},
	// JavaScript in href/src (actual HTML context, not string literals)
	{
		pattern:     `(?i)(?:href|src|action)\s*=\s*["']?\s*javascript:`,
		name:        "JavaScript Protocol XSS",
		description: "JavaScript protocol in href/src attribute",
		severity:    models.SeverityHigh, // Lowered from Critical - needs context check
	},
	// Data URI with script
	{
		pattern:     `(?i)(?:href|src)\s*=\s*["']?\s*data:[^,]*;base64,`,
		name:        "Data URI Injection",
		description: "Data URI that may contain encoded malicious content",
		severity:    models.SeverityHigh,
	},
	// SVG XSS vectors
	{
		pattern:     `(?i)<svg[^>]*\s+on\w+\s*=`,
		name:        "SVG Event Handler XSS",
		description: "SVG element with inline event handler",
		severity:    models.SeverityCritical,
	},
	{
		pattern:     `(?i)<svg[^>]*>.*?<script`,
		name:        "SVG Script Injection",
		description: "Script tag embedded within SVG element",
		severity:    models.SeverityCritical,
	},
	// Dangerous DOM sinks
	{
		pattern:     `(?i)\.innerHTML\s*=\s*[^;]*(?:location|document\.URL|document\.referrer|window\.name)`,
		name:        "DOM-based XSS (innerHTML)",
		description: "Untrusted source assigned to innerHTML",
		severity:    models.SeverityCritical,
	},
	{
		pattern:     `(?i)document\.write\s*\([^)]*(?:location|document\.URL|document\.referrer)`,
		name:        "DOM-based XSS (document.write)",
		description: "Untrusted source used in document.write",
		severity:    models.SeverityCritical,
	},
	{
		pattern:     `(?i)eval\s*\(\s*(?:location|document\.URL|window\.name|decodeURI)`,
		name:        "DOM-based XSS (eval)",
		description: "Untrusted source passed to eval",
		severity:    models.SeverityCritical,
	},
	// URL parameter injection
	{
		pattern:     `(?i)(?:location\.search|location\.hash|window\.location)[^;]*\.(?:innerHTML|outerHTML|insertAdjacentHTML)`,
		name:        "URL Parameter to DOM XSS",
		description: "URL parameters inserted into DOM without sanitization",
		severity:    models.SeverityCritical,
	},
	// jQuery XSS sinks
	{
		pattern:     `(?i)\$\([^)]*(?:location|document\.URL|document\.referrer)\)`,
		name:        "jQuery Selector XSS",
		description: "Untrusted input in jQuery selector",
		severity:    models.SeverityHigh,
	},
	{
		pattern:     `(?i)\.(?:html|append|prepend|after|before)\s*\(\s*[^)]*(?:location|window\.name)`,
		name:        "jQuery DOM Manipulation XSS",
		description: "Untrusted input in jQuery DOM manipulation",
		severity:    models.SeverityHigh,
	},
	// Template injection patterns - only in actual template contexts
	// Note: This pattern is very noisy, so we skip it in heuristic detection
	// Real template injection is better caught by signature-based detection
	/*
	{
		pattern:     `(?i)\{\{[^}]*\}\}`,
		name:        "Template Expression",
		description: "Template expression that may be vulnerable to injection",
		severity:    models.SeverityLow,
	},
	*/
	// Expression attributes
	{
		pattern:     `(?i)<[^>]+\s+(?:ng-bind-html|v-html)\s*=`,
		name:        "Framework HTML Binding",
		description: "Angular/Vue HTML binding - potential XSS if user input",
		severity:    models.SeverityMedium,
	},
	// Object/embed tags
	{
		pattern:     `(?i)<(?:object|embed|applet)[^>]*>`,
		name:        "Embedded Object",
		description: "Object/embed/applet tag - can load malicious content",
		severity:    models.SeverityMedium,
	},
	// Form action manipulation
	{
		pattern:     `(?i)<form[^>]*action\s*=\s*["']?\s*javascript:`,
		name:        "Form Action XSS",
		description: "JavaScript in form action attribute",
		severity:    models.SeverityCritical,
	},
	// Base tag injection
	{
		pattern:     `(?i)<base[^>]*href\s*=`,
		name:        "Base Tag Injection",
		description: "Base tag can redirect relative URLs",
		severity:    models.SeverityMedium,
	},
	// Style-based XSS
	{
		pattern:     `(?i)style\s*=\s*["'][^"']*expression\s*\(`,
		name:        "CSS Expression XSS",
		description: "CSS expression() - IE-specific XSS vector",
		severity:    models.SeverityHigh,
	},
	{
		pattern:     `(?i)style\s*=\s*["'][^"']*url\s*\(\s*["']?\s*javascript:`,
		name:        "CSS JavaScript URL",
		description: "JavaScript URL in CSS",
		severity:    models.SeverityHigh,
	},
	// Meta refresh with JavaScript
	{
		pattern:     `(?i)<meta[^>]*http-equiv\s*=\s*["']?refresh["']?[^>]*javascript:`,
		name:        "Meta Refresh XSS",
		description: "JavaScript in meta refresh",
		severity:    models.SeverityCritical,
	},
}

// XSSDetector detects XSS vulnerabilities
type XSSDetector struct {
	*detectors.BaseDetector
	matcher          *signatures.Matcher
	level            models.SignatureLevel
	compiledPatterns []struct {
		regex       *regexp.Regexp
		name        string
		description string
		severity    models.Severity
	}
}

// NewXSSDetector creates a new XSS detector
func NewXSSDetector(matcher *signatures.Matcher, level models.SignatureLevel) *XSSDetector {
	d := &XSSDetector{
		BaseDetector: detectors.NewBaseDetector("js_xss", 93, []string{
			"html", "htm", "php", "phtml", "js", "jsx", "vue", "svelte",
			"asp", "aspx", "jsp", "erb", "ejs", "hbs", "handlebars",
		}),
		matcher: matcher,
		level:   level,
	}

	// Compile patterns
	for _, p := range xssPatterns {
		compiled := struct {
			regex       *regexp.Regexp
			name        string
			description string
			severity    models.Severity
		}{
			regex:       regexp.MustCompile(p.pattern),
			name:        p.name,
			description: p.description,
			severity:    p.severity,
		}
		d.compiledPatterns = append(d.compiledPatterns, compiled)
	}

	return d
}

// Detect scans a file for XSS vulnerabilities
func (d *XSSDetector) Detect(ctx context.Context, file *models.File) ([]*models.Finding, error) {
	var findings []*models.Finding
	content := string(file.Content)

	// 1. Check for XSS patterns
	for _, pattern := range d.compiledPatterns {
		// Skip low severity in fast mode
		if d.level == models.LevelBasic && pattern.severity == models.SeverityLow {
			continue
		}

		matches := pattern.regex.FindAllStringIndex(content, -1)
		for _, match := range matches {
			fragment, lineNumber := signatures.GetFragment(file.Content, match[0], 120)
			matched := content[match[0]:match[1]]

			// Adjust severity and confidence based on context
			severity := pattern.severity
			confidence := calculateXSSConfidence(pattern.severity)

			// Check if this is in a localization file or string literal
			if isInLocalizationContext(file, content, match[0]) {
				// Lower severity for localization files - likely just message templates
				if severity == models.SeverityCritical {
					severity = models.SeverityMedium
				} else if severity == models.SeverityHigh {
					severity = models.SeverityLow
				}
				confidence = 40 // Much lower confidence
			}

			findings = append(findings, &models.Finding{
				File:          file,
				Type:          models.ThreatXSS,
				Severity:      severity,
				SignatureID:   "XSS-" + sanitizeName(pattern.name),
				SignatureName: pattern.name,
				Description:   pattern.description,
				Position:      match[0],
				LineNumber:    lineNumber,
				Snippet:       truncateXSS(matched, 80),
				Fragment:      fragment,
				Confidence:    confidence,
				Timestamp:     time.Now(),
				Metadata: map[string]any{
					"detector": "xss_heuristic",
					"category": "xss",
				},
			})
		}
	}

	// 2. Match signatures from database
	sigMatches := d.matcher.Match(file.Content, file.Extension, d.level)
	for _, match := range sigMatches {
		// Include JS malware signatures as they often contain XSS
		if !isXSSRelated(match.Signature.Category) {
			continue
		}

		fragment, lineNumber := signatures.GetFragment(file.Content, match.Position, 100)

		findings = append(findings, &models.Finding{
			File:          file,
			Type:          models.ThreatXSS,
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
			Metadata: map[string]any{
				"pattern":  match.Signature.Pattern,
				"is_regex": match.Signature.IsRegex,
				"detector": "xss_signature",
			},
		})
	}

	return findings, nil
}

// isXSSRelated checks if threat type is XSS-related
func isXSSRelated(category models.ThreatType) bool {
	switch category {
	case models.ThreatXSS, models.ThreatJSMalware, models.ThreatJSObfuscated:
		return true
	default:
		return false
	}
}

// sanitizeName creates a valid ID from a name
func sanitizeName(name string) string {
	result := ""
	for _, c := range name {
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') {
			result += string(c)
		} else if c == ' ' || c == '-' || c == '_' || c == '(' || c == ')' {
			result += "-"
		}
	}
	return result
}

// truncateXSS truncates a string for XSS findings
func truncateXSS(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// calculateXSSConfidence returns confidence based on severity
func calculateXSSConfidence(severity models.Severity) int {
	switch severity {
	case models.SeverityCritical:
		return 90
	case models.SeverityHigh:
		return 80
	case models.SeverityMedium:
		return 70
	case models.SeverityLow:
		return 50
	default:
		return 60
	}
}

// isInLocalizationContext checks if the finding is in a localization file or string literal
func isInLocalizationContext(file *models.File, content string, position int) bool {
	// Check if file is a localization file
	localizationPatterns := []string{
		`/lang/`,
		`/locale/`,
		`/i18n/`,
		`/translations/`,
		`/messages/`,
		`.lang.`,
		`_lang.`,
	}

	for _, pattern := range localizationPatterns {
		if regexp.MustCompile(`(?i)` + pattern).MatchString(file.Path) {
			return true
		}
	}

	// Check if it's inside a PHP string assignment (localization pattern)
	// Look backwards from position to find if we're in a string literal
	start := position - 200
	if start < 0 {
		start = 0
	}
	end := position + 100
	if end > len(content) {
		end = len(content)
	}

	context := content[start:end]

	// Check for PHP message/localization patterns
	if regexp.MustCompile(`(?i)\$MESS\[`).MatchString(context) {
		return true
	}
	if regexp.MustCompile(`(?i)\$LANG\[`).MatchString(context) {
		return true
	}
	if regexp.MustCompile(`(?i)(?:getMessage|__)\s*\(`).MatchString(context) {
		return true
	}

	// Check if inside a PHP string literal
	beforeMatch := content[start:position]
	afterMatch := content[position:end]

	// Count quotes before and after - if odd number, we're inside a string
	singleQuotesBefore := len(regexp.MustCompile(`(?:[^\\]|^)'`).FindAllString(beforeMatch, -1))
	doubleQuotesBefore := len(regexp.MustCompile(`(?:[^\\]|^)"`).FindAllString(beforeMatch, -1))
	singleQuotesAfter := len(regexp.MustCompile(`(?:[^\\]|^)'`).FindAllString(afterMatch, -1))
	doubleQuotesAfter := len(regexp.MustCompile(`(?:[^\\]|^)"`).FindAllString(afterMatch, -1))

	// If we have matching quotes on both sides, we're in a string literal
	if (singleQuotesBefore > 0 && singleQuotesAfter > 0) || (doubleQuotesBefore > 0 && doubleQuotesAfter > 0) {
		return true
	}

	return false
}
