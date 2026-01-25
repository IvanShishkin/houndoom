package javascript

import (
	"context"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/IvanShishkin/houndoom/internal/detectors"
	"github.com/IvanShishkin/houndoom/internal/signatures"
	"github.com/IvanShishkin/houndoom/pkg/models"
)

// Suspicious TLDs commonly used in malware
var suspiciousTLDs = []string{
	".tk", ".ml", ".ga", ".cf", ".gq", // Free TLDs often abused
	".top", ".xyz", ".work", ".click", ".link",
	".bid", ".trade", ".loan", ".date", ".racing",
}

// Known malicious domains (sample - in production would be much larger)
var knownMaliciousDomains = []string{
	"coinhive.com", "coin-hive.com", "jsecoin.com",
	"mataharirama.xyz", "googletagmanager.eu",
}

// IFRAME hiding techniques
var iframeHidingPatterns = []struct {
	pattern     string
	name        string
	description string
	severity    models.Severity
}{
	{
		pattern:     `(?i)<iframe[^>]*style\s*=\s*["'][^"']*display\s*:\s*none`,
		name:        "Hidden IFRAME (display:none)",
		description: "IFRAME hidden using display:none style",
		severity:    models.SeverityCritical,
	},
	{
		pattern:     `(?i)<iframe[^>]*style\s*=\s*["'][^"']*visibility\s*:\s*hidden`,
		name:        "Hidden IFRAME (visibility:hidden)",
		description: "IFRAME hidden using visibility:hidden style",
		severity:    models.SeverityCritical,
	},
	{
		pattern:     `(?i)<iframe[^>]*(?:width|height)\s*=\s*["']?0["']?`,
		name:        "Zero-Size IFRAME",
		description: "IFRAME with zero width or height",
		severity:    models.SeverityCritical,
	},
	{
		pattern:     `(?i)<iframe[^>]*style\s*=\s*["'][^"']*(?:width|height)\s*:\s*0`,
		name:        "Zero-Size IFRAME (CSS)",
		description: "IFRAME with zero dimensions via CSS",
		severity:    models.SeverityCritical,
	},
	{
		pattern:     `(?i)<iframe[^>]*style\s*=\s*["'][^"']*position\s*:\s*absolute[^"']*(?:left|top)\s*:\s*-\d+`,
		name:        "Off-Screen IFRAME",
		description: "IFRAME positioned outside visible area",
		severity:    models.SeverityCritical,
	},
	{
		pattern:     `(?i)<iframe[^>]*style\s*=\s*["'][^"']*opacity\s*:\s*0`,
		name:        "Transparent IFRAME",
		description: "IFRAME with zero opacity",
		severity:    models.SeverityHigh,
	},
	{
		pattern:     `(?i)document\.write\s*\([^)]*<iframe`,
		name:        "Dynamic IFRAME Injection",
		description: "IFRAME dynamically inserted via document.write",
		severity:    models.SeverityHigh,
	},
	{
		pattern:     `(?i)createElement\s*\(\s*["']iframe["']\s*\)`,
		name:        "JavaScript IFRAME Creation",
		description: "IFRAME created programmatically via JavaScript",
		severity:    models.SeverityMedium,
	},
	{
		pattern:     `(?i)innerHTML\s*[+]?=\s*["'][^"']*<iframe`,
		name:        "IFRAME via innerHTML",
		description: "IFRAME injected via innerHTML modification",
		severity:    models.SeverityHigh,
	},
}

// IframeDetector detects malicious IFRAME injections
type IframeDetector struct {
	*detectors.BaseDetector
	matcher          *signatures.Matcher
	level            models.SignatureLevel
	compiledPatterns []struct {
		regex       *regexp.Regexp
		name        string
		description string
		severity    models.Severity
	}
	srcRegex *regexp.Regexp
}

// NewIframeDetector creates a new IFRAME detector
func NewIframeDetector(matcher *signatures.Matcher, level models.SignatureLevel) *IframeDetector {
	d := &IframeDetector{
		BaseDetector: detectors.NewBaseDetector("js_iframe", 92, []string{
			"html", "htm", "php", "phtml", "js", "asp", "aspx", "jsp",
		}),
		matcher:  matcher,
		level:    level,
		srcRegex: regexp.MustCompile(`(?i)<iframe[^>]*src\s*=\s*["']([^"']+)["']`),
	}

	// Compile patterns
	for _, p := range iframeHidingPatterns {
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

// Detect scans a file for malicious IFRAMEs
func (d *IframeDetector) Detect(ctx context.Context, file *models.File) ([]*models.Finding, error) {
	var findings []*models.Finding
	content := string(file.Content)

	// 1. Check for hidden IFRAME patterns
	for _, pattern := range d.compiledPatterns {
		matches := pattern.regex.FindAllStringIndex(content, -1)
		for _, match := range matches {
			fragment, lineNumber := signatures.GetFragment(file.Content, match[0], 150)
			matched := content[match[0]:match[1]]

			findings = append(findings, &models.Finding{
				File:          file,
				Type:          models.ThreatIframe,
				Severity:      pattern.severity,
				SignatureID:   "IFRAME-HIDDEN",
				SignatureName: pattern.name,
				Description:   pattern.description,
				Position:      match[0],
				LineNumber:    lineNumber,
				Snippet:       truncateStr(matched, 100),
				Fragment:      fragment,
				Confidence:    90,
				Timestamp:     time.Now(),
				Metadata: map[string]any{
					"detector": "iframe_heuristic",
					"hiding":   true,
				},
			})
		}
	}

	// 2. Check IFRAME sources for suspicious domains
	srcMatches := d.srcRegex.FindAllStringSubmatch(content, -1)
	for _, match := range srcMatches {
		if len(match) < 2 {
			continue
		}

		src := match[1]
		isSuspicious, reason := d.checkSuspiciousSource(src)

		if isSuspicious {
			pos := strings.Index(content, match[0])
			if pos < 0 {
				continue
			}

			fragment, lineNumber := signatures.GetFragment(file.Content, pos, 150)

			severity := models.SeverityHigh
			confidence := 80

			// Higher severity for known malicious domains
			if strings.Contains(reason, "known malicious") {
				severity = models.SeverityCritical
				confidence = 95
			}

			findings = append(findings, &models.Finding{
				File:          file,
				Type:          models.ThreatIframe,
				Severity:      severity,
				SignatureID:   "IFRAME-SUSPICIOUS-SRC",
				SignatureName: "Suspicious IFRAME Source",
				Description:   reason,
				Position:      pos,
				LineNumber:    lineNumber,
				Snippet:       truncateStr(match[0], 100),
				Fragment:      fragment,
				Confidence:    confidence,
				Timestamp:     time.Now(),
				Metadata: map[string]any{
					"detector": "iframe_source_check",
					"src":      src,
					"reason":   reason,
				},
			})
		}
	}

	// 3. Match signatures from database (filter by iframe category)
	sigMatches := d.matcher.Match(file.Content, file.Extension, d.level)
	for _, match := range sigMatches {
		if match.Signature.Category != models.ThreatIframe {
			continue
		}

		fragment, lineNumber := signatures.GetFragment(file.Content, match.Position, 100)

		findings = append(findings, &models.Finding{
			File:          file,
			Type:          models.ThreatIframe,
			Severity:      match.Signature.Severity,
			SignatureID:   match.Signature.ID,
			SignatureName: match.Signature.Name,
			Description:   match.Signature.Description,
			Position:      match.Position,
			LineNumber:    lineNumber,
			Snippet:       match.Matched,
			Fragment:      fragment,
			Confidence:    85,
			Timestamp:     time.Now(),
			Metadata: map[string]any{
				"pattern":  match.Signature.Pattern,
				"is_regex": match.Signature.IsRegex,
				"detector": "iframe_signature",
			},
		})
	}

	return findings, nil
}

// checkSuspiciousSource checks if an IFRAME source is suspicious
func (d *IframeDetector) checkSuspiciousSource(src string) (bool, string) {
	src = strings.TrimSpace(src)
	srcLower := strings.ToLower(src)

	// Check for data: URLs (can contain malicious content)
	if strings.HasPrefix(srcLower, "data:") {
		return true, "Data URI in IFRAME source - may contain embedded malicious content"
	}

	// Check for javascript: URLs
	if strings.HasPrefix(srcLower, "javascript:") {
		return true, "JavaScript URI in IFRAME - potential XSS vector"
	}

	// Parse URL
	parsed, err := url.Parse(src)
	if err != nil {
		return false, ""
	}

	host := strings.ToLower(parsed.Host)
	if host == "" {
		return false, ""
	}

	// Check for known malicious domains
	for _, domain := range knownMaliciousDomains {
		if strings.Contains(host, domain) {
			return true, "IFRAME points to known malicious domain: " + domain
		}
	}

	// Check for suspicious TLDs
	for _, tld := range suspiciousTLDs {
		if strings.HasSuffix(host, tld) {
			return true, "IFRAME source uses suspicious TLD: " + tld
		}
	}

	// Check for IP address URLs (often malicious)
	if regexp.MustCompile(`^\d+\.\d+\.\d+\.\d+`).MatchString(host) {
		return true, "IFRAME source is an IP address - suspicious"
	}

	// Check for encoded URLs (potential obfuscation)
	if strings.Contains(src, "%") && strings.Count(src, "%") > 5 {
		return true, "IFRAME source contains heavy URL encoding - potential obfuscation"
	}

	return false, ""
}

// truncateStr truncates a string to max length
func truncateStr(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
