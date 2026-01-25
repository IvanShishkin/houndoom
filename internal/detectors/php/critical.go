package php

import (
	"context"
	"time"

	"github.com/IvanShishkin/houndoom/internal/detectors"
	"github.com/IvanShishkin/houndoom/internal/signatures"
	"github.com/IvanShishkin/houndoom/pkg/models"
)

// CriticalDetector detects critical PHP threats
type CriticalDetector struct {
	*detectors.BaseDetector
	matcher *signatures.Matcher
	level   models.SignatureLevel
}

// NewCriticalDetector creates a new PHP critical detector
func NewCriticalDetector(matcher *signatures.Matcher, level models.SignatureLevel) *CriticalDetector {
	return &CriticalDetector{
		BaseDetector: detectors.NewBaseDetector("php_critical", 100, []string{
			"php", "php3", "php4", "php5", "php6", "php7",
			"phtml", "pht", "htaccess",
		}),
		matcher: matcher,
		level:   level,
	}
}

// Detect scans a file for critical PHP threats
func (d *CriticalDetector) Detect(ctx context.Context, file *models.File) ([]*models.Finding, error) {
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
				"is_regex": match.Signature.IsRegex,
			},
		}

		findings = append(findings, finding)
	}

	return findings, nil
}

// calculateConfidence calculates confidence level for a match
func calculateConfidence(match *signatures.MatchResult) int {
	confidence := 70 // Base confidence

	// Higher confidence for critical severity
	if match.Signature.Severity == models.SeverityCritical {
		confidence += 20
	}

	// Higher confidence for specific patterns
	if match.Signature.IsRegex {
		confidence += 10
	}

	if confidence > 100 {
		confidence = 100
	}

	return confidence
}
