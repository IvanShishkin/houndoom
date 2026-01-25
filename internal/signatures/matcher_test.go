package signatures

import (
	"testing"

	"github.com/IvanShishkin/houndoom/pkg/models"
)

func TestMatcher_Match(t *testing.T) {
	// Create test signature database
	db := models.NewSignatureDatabase()

	// Add test signatures
	db.AddSignature(&models.Signature{
		ID:          "TEST-001",
		Name:        "Test Eval",
		Category:    models.ThreatPHPBackdoor,
		Severity:    models.SeverityHigh,
		Pattern:     `eval\s*\(`,
		Description: "Dangerous eval function",
		Level:       models.LevelBasic,
		IsRegex:     true,
		Enabled:     true,
		Extensions:  []string{"php"},
	})

	db.AddSignature(&models.Signature{
		ID:          "TEST-002",
		Name:        "Test Base64",
		Category:    models.ThreatPHPObfuscated,
		Severity:    models.SeverityMedium,
		Pattern:     `base64_decode`,
		Description: "Base64 decoding",
		Level:       models.LevelExpert,
		IsRegex:     true,
		Enabled:     true,
		Extensions:  []string{"php"},
	})

	db.AddSignature(&models.Signature{
		ID:          "TEST-003",
		Name:        "Test Shell Exec",
		Category:    models.ThreatPHPBackdoor,
		Severity:    models.SeverityCritical,
		Pattern:     `shell_exec\s*\(`,
		Description: "Shell execution",
		Level:       models.LevelBasic,
		IsRegex:     true,
		Enabled:     true,
		Extensions:  []string{"php"},
	})

	matcher := NewMatcher(db)

	tests := []struct {
		name          string
		content       string
		extension     string
		level         models.SignatureLevel
		expectedCount int
		expectedIDs   []string
	}{
		{
			name:          "Match eval",
			content:       "<?php eval($_GET['cmd']); ?>",
			extension:     "php",
			level:         models.LevelBasic,
			expectedCount: 1,
			expectedIDs:   []string{"TEST-001"},
		},
		{
			name:          "Match base64",
			content:       "<?php base64_decode('test'); ?>",
			extension:     "php",
			level:         models.LevelExpert,
			expectedCount: 1,
			expectedIDs:   []string{"TEST-002"},
		},
		{
			name:          "Match shell_exec",
			content:       "<?php shell_exec('ls'); ?>",
			extension:     "php",
			level:         models.LevelBasic,
			expectedCount: 1,
			expectedIDs:   []string{"TEST-003"},
		},
		{
			name:          "Match multiple",
			content:       "<?php eval(base64_decode('test')); ?>",
			extension:     "php",
			level:         models.LevelBasic,
			expectedCount: 1, // Only eval matches at Basic level
			expectedIDs:   []string{"TEST-001"},
		},
		{
			name:          "No match",
			content:       "<?php echo 'hello'; ?>",
			extension:     "php",
			level:         models.LevelBasic,
			expectedCount: 0,
			expectedIDs:   []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := matcher.Match([]byte(tt.content), tt.extension, tt.level)

			if len(matches) != tt.expectedCount {
				t.Errorf("Match() returned %d matches, want %d", len(matches), tt.expectedCount)
			}

			if len(matches) > 0 {
				for i, expectedID := range tt.expectedIDs {
					if i >= len(matches) {
						break
					}
					if matches[i].Signature.ID != expectedID {
						t.Errorf("Match[%d] ID = %s, want %s", i, matches[i].Signature.ID, expectedID)
					}
				}
			}
		})
	}
}

func TestMatcher_EmptyDatabase(t *testing.T) {
	db := models.NewSignatureDatabase()
	matcher := NewMatcher(db)

	matches := matcher.Match([]byte("<?php eval('test'); ?>"), "php", models.LevelBasic)

	if len(matches) != 0 {
		t.Errorf("Match() with empty DB returned %d matches, want 0", len(matches))
	}
}

func TestMatcher_InvalidRegex(t *testing.T) {
	db := models.NewSignatureDatabase()

	// Try to add invalid signature (should fail in AddSignature)
	err := db.AddSignature(&models.Signature{
		ID:          "TEST-BAD",
		Name:        "Bad Pattern",
		Category:    models.ThreatPHPBackdoor,
		Severity:    models.SeverityHigh,
		Pattern:     `[invalid(regex`,
		Description: "Invalid regex pattern",
		Level:       models.LevelBasic,
		IsRegex:     true,
		Enabled:     true,
		Extensions:  []string{"php"},
	})

	// Should return error for invalid regex
	if err == nil {
		t.Error("AddSignature() with invalid regex should return error")
	}
}
