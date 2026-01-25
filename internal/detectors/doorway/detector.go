package doorway

import (
	"context"
	"regexp"
	"strings"
	"time"

	"github.com/IvanShishkin/houndoom/internal/detectors"
	"github.com/IvanShishkin/houndoom/internal/signatures"
	"github.com/IvanShishkin/houndoom/pkg/models"
)

// Detector detects doorway pages and auto-generated SEO spam
type Detector struct {
	*detectors.BaseDetector
	matcher           *signatures.Matcher
	level             models.SignatureLevel
	autoGenRe         *regexp.Regexp
	cloakingRe        *regexp.Regexp
	redirectRe        *regexp.Regexp
	templateMarkersRe *regexp.Regexp
}

// Auto-generated content patterns
var autoGenPatterns = `(?i)(?:` +
	`\{\{[a-z_]+\}\}|` +                                    // Template variables {{var}}
	`\{%\s*[a-z]+.*?%\}|` +                                 // Template tags {% tag %}
	`\$\{[a-z_]+\}|` +                                      // Variable substitution ${var}
	`<!--\s*(?:auto|generated|doorway|template)\s*-->|` +   // Generator comments
	`<\?(?:php)?\s*echo\s+\$(?:keyword|text|content)\s*;` + // PHP variable output
	`)`

// Cloaking patterns (showing different content to bots vs users)
var cloakingPatterns = `(?i)(?:` +
	`(?:google|yandex|bing|bot|crawler|spider).*?(?:redirect|header|location)|` +
	`\$_SERVER\s*\[\s*['"]HTTP_USER_AGENT['"]\s*\].*?(?:google|bot|crawler)|` +
	`preg_match\s*\([^)]*(?:google|yandex|bot)[^)]*\$_SERVER|` +
	`if\s*\([^)]*(?:is_bot|isBot|isCrawler|isSearchEngine)` +
	`)`

// Redirect patterns for doorways
var redirectPatterns = `(?i)(?:` +
	`<meta[^>]+http-equiv\s*=\s*["']?refresh["']?[^>]+url\s*=|` +
	`window\.location\s*=|` +
	`document\.location\s*=|` +
	`location\.(?:href|replace)\s*=|` +
	`header\s*\(\s*['"]Location:|` +
	`<script[^>]*>.*?(?:top|parent|self)\.location` +
	`)`

// Template/generator markers
var templateMarkerPatterns = `(?i)(?:` +
	`generated\s+by|auto[- ]?generated|` +
	`doorway\s*(?:page|generator)|` +
	`seo\s*(?:tool|generator|template)|` +
	`<!--\s*\d+\s*keywords?\s*-->|` +
	`created\s+with\s+(?:doorway|seo|generator)` +
	`)`

// NewDetector creates a new doorway detector
func NewDetector(matcher *signatures.Matcher, level models.SignatureLevel) *Detector {
	return &Detector{
		BaseDetector:      detectors.NewBaseDetector("doorway", 75, []string{
			"php", "html", "htm",
		}),
		matcher:           matcher,
		level:             level,
		autoGenRe:         regexp.MustCompile(autoGenPatterns),
		cloakingRe:        regexp.MustCompile(cloakingPatterns),
		redirectRe:        regexp.MustCompile(redirectPatterns),
		templateMarkersRe: regexp.MustCompile(templateMarkerPatterns),
	}
}

// Detect scans a file for doorway page indicators
func (d *Detector) Detect(ctx context.Context, file *models.File) ([]*models.Finding, error) {
	var findings []*models.Finding
	content := string(file.Content)
	contentLower := strings.ToLower(content)

	// Calculate suspicion score
	score := 0
	var indicators []string

	// 1. Check for cloaking (most suspicious)
	if matches := d.cloakingRe.FindAllStringIndex(content, -1); matches != nil {
		score += 40
		indicators = append(indicators, "cloaking")
		for _, match := range matches {
			fragment, lineNumber := signatures.GetFragment(file.Content, match[0], 100)
			findings = append(findings, &models.Finding{
				File:          file,
				Type:          models.ThreatDoorway,
				Severity:      models.SeverityCritical,
				SignatureID:   "DOOR-CLOAK",
				SignatureName: "Cloaking Detected",
				Description:   "Bot/crawler detection with different behavior - classic cloaking technique",
				Position:      match[0],
				LineNumber:    lineNumber,
				Snippet:       content[match[0]:min(match[1], match[0]+200)],
				Fragment:      fragment,
				Confidence:    90,
				Timestamp:     time.Now(),
			})
		}
	}

	// 2. Check for auto-generated content markers
	autoGenMatches := d.autoGenRe.FindAllStringIndex(content, -1)
	if len(autoGenMatches) > 5 { // Multiple template variables = likely generated
		score += 25
		indicators = append(indicators, "auto-generated markers")
	}

	// 3. Check for template/generator markers
	if matches := d.templateMarkersRe.FindAllStringIndex(content, -1); matches != nil {
		score += 20
		indicators = append(indicators, "generator markers")
		for _, match := range matches {
			fragment, lineNumber := signatures.GetFragment(file.Content, match[0], 100)
			findings = append(findings, &models.Finding{
				File:          file,
				Type:          models.ThreatDoorway,
				Severity:      models.SeverityMedium,
				SignatureID:   "DOOR-GENERATOR",
				SignatureName: "Doorway Generator Marker",
				Description:   "Auto-generation or doorway tool marker detected",
				Position:      match[0],
				LineNumber:    lineNumber,
				Snippet:       content[match[0]:min(match[1], match[0]+100)],
				Fragment:      fragment,
				Confidence:    75,
				Timestamp:     time.Now(),
			})
		}
	}

	// 4. Check for redirect combined with minimal content
	redirectMatches := d.redirectRe.FindAllStringIndex(content, -1)
	hasMinimalContent := len(strings.TrimSpace(stripTags(content))) < 200

	if len(redirectMatches) > 0 && hasMinimalContent {
		score += 30
		indicators = append(indicators, "redirect with minimal content")
		for _, match := range redirectMatches {
			fragment, lineNumber := signatures.GetFragment(file.Content, match[0], 100)
			findings = append(findings, &models.Finding{
				File:          file,
				Type:          models.ThreatDoorway,
				Severity:      models.SeverityHigh,
				SignatureID:   "DOOR-REDIRECT",
				SignatureName: "Doorway Redirect Page",
				Description:   "Page with redirect and minimal content - likely doorway",
				Position:      match[0],
				LineNumber:    lineNumber,
				Snippet:       content[match[0]:min(match[1], match[0]+150)],
				Fragment:      fragment,
				Confidence:    80,
				Timestamp:     time.Now(),
			})
		}
	}

	// 5. Check for keyword stuffing (many repeated words)
	if hasKeywordStuffing(contentLower) {
		score += 15
		indicators = append(indicators, "keyword stuffing")
	}

	// 6. Check for suspicious file naming patterns
	pathLower := strings.ToLower(file.Path)
	doorwayPathPatterns := []string{
		"/go/", "/out/", "/redirect/", "/r/", "/click/",
		"-buy-", "-cheap-", "-online-", "-free-",
	}
	for _, pattern := range doorwayPathPatterns {
		if strings.Contains(pathLower, pattern) {
			score += 10
			indicators = append(indicators, "suspicious path")
			break
		}
	}

	// 7. Add combined finding if score is high enough
	if score >= 50 && len(findings) == 0 {
		findings = append(findings, &models.Finding{
			File:          file,
			Type:          models.ThreatDoorway,
			Severity:      getSeverityByScore(score),
			SignatureID:   "DOOR-COMBINED",
			SignatureName: "Suspected Doorway Page",
			Description:   "Multiple doorway indicators: " + strings.Join(indicators, ", "),
			Position:      0,
			LineNumber:    1,
			Snippet:       "",
			Fragment:      "",
			Confidence:    min(score, 100),
			Timestamp:     time.Now(),
			Metadata: map[string]any{
				"score":      score,
				"indicators": indicators,
			},
		})
	}

	return findings, nil
}

// stripTags removes HTML tags from content
func stripTags(content string) string {
	re := regexp.MustCompile(`<[^>]*>`)
	return re.ReplaceAllString(content, " ")
}

// hasKeywordStuffing checks for repeated keywords
func hasKeywordStuffing(content string) bool {
	words := strings.Fields(content)
	if len(words) < 50 {
		return false
	}

	wordCount := make(map[string]int)
	for _, word := range words {
		if len(word) > 3 {
			wordCount[word]++
		}
	}

	// Check if any word appears more than 3% of total words
	threshold := len(words) * 3 / 100
	if threshold < 5 {
		threshold = 5
	}

	for _, count := range wordCount {
		if count > threshold {
			return true
		}
	}
	return false
}

func getSeverityByScore(score int) models.Severity {
	if score >= 80 {
		return models.SeverityCritical
	} else if score >= 60 {
		return models.SeverityHigh
	} else if score >= 40 {
		return models.SeverityMedium
	}
	return models.SeverityLow
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
