package signatures

import (
	"bytes"
	"strings"

	"github.com/IvanShishkin/houndoom/pkg/models"
)

// Matcher matches content against signatures
type Matcher struct {
	db *models.SignatureDatabase
}

// NewMatcher creates a new signature matcher
func NewMatcher(db *models.SignatureDatabase) *Matcher {
	return &Matcher{db: db}
}

// Match matches content against all signatures
func (m *Matcher) Match(content []byte, extension string, level models.SignatureLevel) []*MatchResult {
	var results []*MatchResult

	// Get signatures for current level and lower
	var signatures []*models.Signature
	for l := models.LevelBasic; l <= level; l++ {
		signatures = append(signatures, m.db.GetByLevel(l)...)
	}

	contentStr := string(content)
	contentLower := strings.ToLower(contentStr)

	for _, sig := range signatures {
		if !sig.Enabled {
			continue
		}

		// Check if signature supports this extension
		if !m.supportsExtension(sig, extension) {
			continue
		}

		// Match signature
		if sig.IsRegex {
			// Regex matching
			if match := sig.CompiledRe.FindStringIndex(contentStr); match != nil {
				results = append(results, &MatchResult{
					Signature: sig,
					Position:  match[0],
					Length:    match[1] - match[0],
					Matched:   contentStr[match[0]:match[1]],
				})
			}
		} else {
			// String matching (case-insensitive)
			patternLower := strings.ToLower(sig.Pattern)
			if pos := strings.Index(contentLower, patternLower); pos != -1 {
				length := len(sig.Pattern)
				results = append(results, &MatchResult{
					Signature: sig,
					Position:  pos,
					Length:    length,
					Matched:   contentStr[pos : pos+length],
				})
			}
		}
	}

	return results
}

// MatchResult represents a signature match
type MatchResult struct {
	Signature *models.Signature
	Position  int
	Length    int
	Matched   string
}

// supportsExtension checks if signature supports the file extension
func (m *Matcher) supportsExtension(sig *models.Signature, extension string) bool {
	for _, ext := range sig.Extensions {
		if ext == "*" || ext == extension {
			return true
		}
	}
	return false
}

// GetFragment extracts a code fragment around the match
func GetFragment(content []byte, position int, maxLen int) (fragment string, lineNumber int) {
	if maxLen <= 0 {
		maxLen = 100
	}

	// Calculate line number
	lineNumber = 1 + bytes.Count(content[:position], []byte("\n"))

	// Extract fragment
	start := position - maxLen
	if start < 0 {
		start = 0
	}

	end := position + maxLen
	if end > len(content) {
		end = len(content)
	}

	fragment = string(content[start:end])

	// Clean up fragment
	fragment = strings.ReplaceAll(fragment, "\r", "")
	fragment = strings.ReplaceAll(fragment, "\n", " ")
	fragment = strings.ReplaceAll(fragment, "\t", " ")

	// Add markers
	markerPos := position - start
	if markerPos > 0 && markerPos < len(fragment) {
		fragment = fragment[:markerPos] + ">>>" + fragment[markerPos:]
	}

	return fragment, lineNumber
}
