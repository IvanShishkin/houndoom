package php

import (
	"encoding/base64"
	"regexp"
)

// Base64Deobfuscator deobfuscates base64 encoded PHP code
type Base64Deobfuscator struct{}

// NewBase64Deobfuscator creates a new Base64 deobfuscator
func NewBase64Deobfuscator() *Base64Deobfuscator {
	return &Base64Deobfuscator{}
}

// Name returns the deobfuscator name
func (d *Base64Deobfuscator) Name() string {
	return "base64_php"
}

// CanDeobfuscate checks if content can be deobfuscated
func (d *Base64Deobfuscator) CanDeobfuscate(content string) bool {
	// Look for base64_decode patterns
	patterns := []string{
		`base64_decode\s*\(\s*['"]([A-Za-z0-9+/=]{20,})['"]`,
		`base64_decode\s*\(\s*"([A-Za-z0-9+/=]{20,})"`,
	}

	for _, pattern := range patterns {
		if matched, _ := regexp.MatchString(pattern, content); matched {
			return true
		}
	}

	return false
}

// Deobfuscate deobfuscates base64 encoded content
func (d *Base64Deobfuscator) Deobfuscate(content string) (string, error) {
	// Pattern to find base64_decode with literal string
	re := regexp.MustCompile(`base64_decode\s*\(\s*['"]([A-Za-z0-9+/=]+)['"]`)

	result := re.ReplaceAllStringFunc(content, func(match string) string {
		// Extract base64 string
		submatches := re.FindStringSubmatch(match)
		if len(submatches) < 2 {
			return match
		}

		encoded := submatches[1]

		// Decode base64
		decoded, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return match
		}

		// Return decoded content in quotes
		return `"` + string(decoded) + `"`
	})

	return result, nil
}
