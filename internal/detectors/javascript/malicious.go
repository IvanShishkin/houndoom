package javascript

import (
	"context"
	"time"

	"github.com/IvanShishkin/houndoom/internal/detectors"
	"github.com/IvanShishkin/houndoom/internal/signatures"
	"github.com/IvanShishkin/houndoom/pkg/models"
)

// MaliciousDetector detects malicious JavaScript
type MaliciousDetector struct {
	*detectors.BaseDetector
	matcher *signatures.Matcher
	level   models.SignatureLevel
}

// NewMaliciousDetector creates a new JavaScript malicious detector
func NewMaliciousDetector(matcher *signatures.Matcher, level models.SignatureLevel) *MaliciousDetector {
	return &MaliciousDetector{
		BaseDetector: detectors.NewBaseDetector("javascript_malicious", 90, []string{
			"js", "html", "htm", "svg",
		}),
		matcher: matcher,
		level:   level,
	}
}

// Detect scans a file for malicious JavaScript
func (d *MaliciousDetector) Detect(ctx context.Context, file *models.File) ([]*models.Finding, error) {
	var findings []*models.Finding

	// Match signatures
	matches := d.matcher.Match(file.Content, file.Extension, d.level)

	for _, match := range matches {
		// Get fragment
		fragment, lineNumber := signatures.GetFragment(file.Content, match.Position, 100)

		finding := &models.Finding{
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
			Confidence:    calculateConfidence(match),
			Timestamp:     time.Now(),
			Metadata: map[string]any{
				"pattern": match.Signature.Pattern,
			},
		}

		findings = append(findings, finding)
	}

	return findings, nil
}

// calculateConfidence calculates confidence level for a match
func calculateConfidence(match *signatures.MatchResult) int {
	confidence := 70

	if match.Signature.Severity == models.SeverityCritical {
		confidence += 20
	}

	if match.Signature.Category == models.ThreatIframe {
		confidence += 10 // IFRAME injections are usually malicious
	}

	if confidence > 100 {
		confidence = 100
	}

	return confidence
}
