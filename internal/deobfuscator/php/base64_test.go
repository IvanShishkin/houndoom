package php

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestBase64Deobfuscator_Name(t *testing.T) {
	d := NewBase64Deobfuscator()
	if d.Name() != "base64_php" {
		t.Errorf("Name() = %q, want %q", d.Name(), "base64_php")
	}
}

func TestBase64Deobfuscator_CanDeobfuscate(t *testing.T) {
	d := NewBase64Deobfuscator()

	tests := []struct {
		name     string
		content  string
		expected bool
	}{
		{
			name:     "Long base64 string (20+ chars) with double quotes",
			content:  `<?php echo base64_decode("ZWNobyAnSGVsbG8nOw=="); ?>`,
			expected: true,
		},
		{
			name:     "Long base64 string with single quotes",
			content:  `<?php echo base64_decode('ZWNobyAnSGVsbG8nOw=='); ?>`,
			expected: true,
		},
		{
			name:     "Short base64 string (less than 20 chars)",
			content:  `<?php base64_decode("short"); ?>`,
			expected: false,
		},
		{
			name:     "No base64_decode",
			content:  `<?php echo "Hello"; ?>`,
			expected: false,
		},
		{
			name:     "base64_decode with variable (not literal)",
			content:  `<?php base64_decode($var); ?>`,
			expected: false,
		},
		{
			name:     "Empty content",
			content:  "",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := d.CanDeobfuscate(tt.content); got != tt.expected {
				t.Errorf("CanDeobfuscate() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestBase64Deobfuscator_Deobfuscate(t *testing.T) {
	d := NewBase64Deobfuscator()

	// Helper to encode string
	encode := func(s string) string {
		return base64.StdEncoding.EncodeToString([]byte(s))
	}

	tests := []struct {
		name        string
		content     string
		shouldMatch string // substring that should be in result
	}{
		{
			name:        "Decodes base64 content",
			content:     `<?php echo base64_decode("` + encode("Hello World") + `"); ?>`,
			shouldMatch: "Hello World",
		},
		{
			name:        "Decodes with single quotes",
			content:     `<?php echo base64_decode('` + encode("Test String Here") + `'); ?>`,
			shouldMatch: "Test String Here",
		},
		{
			name:        "Decodes nested PHP code",
			content:     `<?php eval(base64_decode("` + encode("echo 'pwned';") + `")); ?>`,
			shouldMatch: "echo 'pwned';",
		},
		{
			name:        "No base64 to decode - unchanged",
			content:     `<?php echo "Hello"; ?>`,
			shouldMatch: `echo "Hello"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := d.Deobfuscate(tt.content)
			if err != nil {
				t.Fatalf("Deobfuscate() error = %v", err)
			}
			if !strings.Contains(got, tt.shouldMatch) {
				t.Errorf("Deobfuscate() result doesn't contain %q, got: %q", tt.shouldMatch, got)
			}
		})
	}
}

func TestBase64Deobfuscator_RealWorldSamples(t *testing.T) {
	d := NewBase64Deobfuscator()

	tests := []struct {
		name            string
		content         string
		shouldDeobfuscate bool
		containsAfter   string
	}{
		{
			name: "Typical malware pattern",
			content: `<?php eval(base64_decode("ZWNobyAnSGVsbG8nOw==")); ?>`,
			shouldDeobfuscate: true,
			containsAfter: "echo 'Hello';",
		},
		{
			name: "Obfuscated shell command",
			content: `<?php $cmd = base64_decode("c3lzdGVtKCRfR0VUWydjbWQnXSk7"); eval($cmd); ?>`,
			shouldDeobfuscate: true,
			containsAfter: "system($_GET['cmd']);",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			canDeobf := d.CanDeobfuscate(tt.content)
			if canDeobf != tt.shouldDeobfuscate {
				t.Errorf("CanDeobfuscate() = %v, want %v", canDeobf, tt.shouldDeobfuscate)
			}

			if tt.shouldDeobfuscate {
				got, err := d.Deobfuscate(tt.content)
				if err != nil {
					t.Fatalf("Deobfuscate() error = %v", err)
				}
				if !containsString(got, tt.containsAfter) {
					t.Errorf("Deobfuscate() result doesn't contain %q, got: %q", tt.containsAfter, got)
				}
			}
		})
	}
}

func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && findSubstring(s, substr)))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
