package adware

import (
	"context"
	"regexp"
	"time"

	"github.com/IvanShishkin/houndoom/internal/detectors"
	"github.com/IvanShishkin/houndoom/internal/signatures"
	"github.com/IvanShishkin/houndoom/pkg/models"
)

// Detector detects adware, spam links, and black-SEO patterns
type Detector struct {
	*detectors.BaseDetector
	matcher         *signatures.Matcher
	level           models.SignatureLevel
	hiddenLinkRe    *regexp.Regexp
	seoSpamRe       *regexp.Regexp
	linkNetworksRe  *regexp.Regexp
}

// Hidden link patterns (display:none, visibility:hidden, position:absolute with negative coords)
var hiddenLinkPatterns = `(?i)<a[^>]+style\s*=\s*["'][^"']*(?:display\s*:\s*none|visibility\s*:\s*hidden|position\s*:\s*absolute[^"']*(?:left|top)\s*:\s*-\d{3,})[^"']*["'][^>]*>`

// SEO spam patterns - focused on actual spam, not legitimate UI elements
var seoSpamPatterns = `(?i)(?:` +
	`<!--\s*(?:links?|seo|spam)\s*-->.*?<!--\s*/(?:links?|seo|spam)\s*-->|` +
	`<noscript>.*?<a\s+href\s*=.*?</noscript>` +
	`)`

// Link network domains (common SEO spam networks)
var linkNetworkPatterns = `(?i)(?:` +
	`sape\.ru|trustlink\.ru|linkfeed|mainlink\.ru|gogetlinks|` +
	`miralinks|rotapost|blogun|seozavr|webeffector|` +
	`promopult|seopult|megaindex|userator|rookee` +
	`)`

// NewDetector creates a new adware detector
func NewDetector(matcher *signatures.Matcher, level models.SignatureLevel) *Detector {
	return &Detector{
		BaseDetector: detectors.NewBaseDetector("adware", 80, []string{
			"php", "html", "htm", "js", "htaccess",
		}),
		matcher:        matcher,
		level:          level,
		hiddenLinkRe:   regexp.MustCompile(hiddenLinkPatterns),
		seoSpamRe:      regexp.MustCompile(seoSpamPatterns),
		linkNetworksRe: regexp.MustCompile(linkNetworkPatterns),
	}
}

// Detect scans a file for adware and spam links
func (d *Detector) Detect(ctx context.Context, file *models.File) ([]*models.Finding, error) {
	var findings []*models.Finding
	content := string(file.Content)

	// 1. Check signature database
	matches := d.matcher.Match(file.Content, file.Extension, d.level)
	for _, match := range matches {
		if match.Signature.Category == models.ThreatAdware ||
		   match.Signature.Category == models.ThreatSpam {
			fragment, lineNumber := signatures.GetFragment(file.Content, match.Position, 100)
			findings = append(findings, &models.Finding{
				File:          file,
				Type:          match.Signature.Category,
				Severity:      match.Signature.Severity,
				SignatureID:   match.Signature.ID,
				SignatureName: match.Signature.Name,
				Description:   match.Signature.Description,
				Position:      match.Position,
				LineNumber:    lineNumber,
				Snippet:       match.Matched,
				Fragment:      fragment,
				Confidence:    70,
				Timestamp:     time.Now(),
			})
		}
	}

	// 2. Check for hidden links
	if matches := d.hiddenLinkRe.FindAllStringIndex(content, -1); matches != nil {
		for _, match := range matches {
			fragment, lineNumber := signatures.GetFragment(file.Content, match[0], 100)
			findings = append(findings, &models.Finding{
				File:          file,
				Type:          models.ThreatAdware,
				Severity:      models.SeverityMedium,
				SignatureID:   "ADW-HIDDEN-LINK",
				SignatureName: "Hidden Link Detected",
				Description:   "Link hidden using CSS (display:none, visibility:hidden, or off-screen positioning)",
				Position:      match[0],
				LineNumber:    lineNumber,
				Snippet:       content[match[0]:min(match[1], match[0]+200)],
				Fragment:      fragment,
				Confidence:    80,
				Timestamp:     time.Now(),
			})
		}
	}

	// 3. Check for SEO spam blocks (comment-marked spam and noscript links)
	if matches := d.seoSpamRe.FindAllStringIndex(content, -1); matches != nil {
		for _, match := range matches {
			fragment, lineNumber := signatures.GetFragment(file.Content, match[0], 100)
			findings = append(findings, &models.Finding{
				File:          file,
				Type:          models.ThreatSpam,
				Severity:      models.SeverityMedium,
				SignatureID:   "ADW-SEO-SPAM",
				SignatureName: "SEO Spam Block",
				Description:   "Hidden SEO spam block detected (comment-marked spam section or noscript links)",
				Position:      match[0],
				LineNumber:    lineNumber,
				Snippet:       content[match[0]:min(match[1], match[0]+200)],
				Fragment:      fragment,
				Confidence:    85,
				Timestamp:     time.Now(),
			})
		}
	}

	// 4. Check for suspicious hidden content (display:none with links - potential spam)
	hiddenContentFindings := d.detectSuspiciousHiddenContent(file, content)
	findings = append(findings, hiddenContentFindings...)

	// 5. Check for link network references
	if matches := d.linkNetworksRe.FindAllStringIndex(content, -1); matches != nil {
		for _, match := range matches {
			fragment, lineNumber := signatures.GetFragment(file.Content, match[0], 100)
			findings = append(findings, &models.Finding{
				File:          file,
				Type:          models.ThreatAdware,
				Severity:      models.SeverityHigh,
				SignatureID:   "ADW-LINK-NETWORK",
				SignatureName: "Link Network Reference",
				Description:   "Reference to known SEO link network detected",
				Position:      match[0],
				LineNumber:    lineNumber,
				Snippet:       content[match[0]:min(match[1], match[0]+100)],
				Fragment:      fragment,
				Confidence:    85,
				Timestamp:     time.Now(),
			})
		}
	}

	return findings, nil
}

// detectSuspiciousHiddenContent detects hidden divs that contain multiple links (likely spam)
// Legitimate hidden elements (error messages, modals, etc.) usually don't contain many links
func (d *Detector) detectSuspiciousHiddenContent(file *models.File, content string) []*models.Finding {
	var findings []*models.Finding

	// Pattern to find hidden divs
	hiddenDivRe := regexp.MustCompile(`(?i)<div[^>]+style\s*=\s*["'][^"']*(?:display\s*:\s*none|visibility\s*:\s*hidden)[^"']*["'][^>]*>(.*?)</div>`)

	matches := hiddenDivRe.FindAllStringSubmatchIndex(content, -1)
	for _, match := range matches {
		if len(match) < 4 {
			continue
		}

		// Get the content inside the div
		divContent := content[match[2]:match[3]]

		// Check if it's a legitimate UI element (error, success, alert, modal, tooltip)
		if isLegitimateHiddenElement(content[match[0]:match[1]]) {
			continue
		}

		// Count links in the hidden content
		linkCount := regexp.MustCompile(`(?i)<a\s+[^>]*href`).FindAllStringIndex(divContent, -1)

		// Only flag if there are multiple links (2+) - likely spam
		// Single link could be legitimate (e.g., "click here to reload")
		if len(linkCount) >= 2 {
			fragment, lineNumber := signatures.GetFragment(file.Content, match[0], 100)
			findings = append(findings, &models.Finding{
				File:          file,
				Type:          models.ThreatSpam,
				Severity:      models.SeverityMedium,
				SignatureID:   "ADW-HIDDEN-SPAM-LINKS",
				SignatureName: "Hidden Spam Links",
				Description:   "Hidden div containing multiple links (likely SEO spam)",
				Position:      match[0],
				LineNumber:    lineNumber,
				Snippet:       content[match[0]:min(match[1], match[0]+150)],
				Fragment:      fragment,
				Confidence:    80,
				Timestamp:     time.Now(),
			})
		}
	}

	return findings
}

// isLegitimateHiddenElement checks if a hidden element is likely a legitimate UI component
func isLegitimateHiddenElement(element string) bool {
	// Check for common legitimate patterns in id/class names
	legitimatePatterns := []string{
		`(?i)id\s*=\s*["'][^"']*(error|success|alert|message|notification|modal|tooltip|popup|dialog|warning|info)`,
		`(?i)class\s*=\s*["'][^"']*(error|success|alert|message|notification|modal|tooltip|popup|dialog|warning|info)`,
		`(?i)role\s*=\s*["'](alert|dialog|tooltip)`,
		`(?i)aria-hidden\s*=\s*["']true["']`,
	}

	for _, pattern := range legitimatePatterns {
		if regexp.MustCompile(pattern).MatchString(element) {
			return true
		}
	}

	return false
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
