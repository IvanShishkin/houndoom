package php

import (
	"encoding/base64"
	"regexp"
	"strings"
)

// ByteRunDeobfuscator deobfuscates ByteRun obfuscated PHP code
type ByteRunDeobfuscator struct {
	// Pattern to detect ByteRun obfuscation
	detectPattern *regexp.Regexp
	extractPattern *regexp.Regexp
}

// NewByteRunDeobfuscator creates a new ByteRun deobfuscator
func NewByteRunDeobfuscator() *ByteRunDeobfuscator {
	return &ByteRunDeobfuscator{
		// ByteRun signature pattern from reference
		detectPattern:  regexp.MustCompile(`(?i)\$_F=__FILE__;\$_X='([^']+)';`),
		extractPattern: regexp.MustCompile(`(?i)\$_F=__FILE__;\$_X='([^']+)';\s*eval\s*\(\s*\$?\w{1,60}\s*\(\s*['"][^'"]+['"]\s*\)\s*\)\s*;`),
	}
}

// Name returns the deobfuscator name
func (d *ByteRunDeobfuscator) Name() string {
	return "byterun"
}

// CanDeobfuscate checks if content can be deobfuscated by ByteRun
func (d *ByteRunDeobfuscator) CanDeobfuscate(content string) bool {
	return d.detectPattern.MatchString(content)
}

// Deobfuscate deobfuscates ByteRun obfuscated code
func (d *ByteRunDeobfuscator) Deobfuscate(content string) (string, error) {
	// Find the encoded content
	matches := d.extractPattern.FindStringSubmatch(content)
	if len(matches) < 2 {
		// Try simpler pattern
		matches = d.detectPattern.FindStringSubmatch(content)
		if len(matches) < 2 {
			return content, nil
		}
	}

	encoded := matches[1]

	// Decode base64
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return content, nil
	}

	// ByteRun uses character translation: '123456aouie' <-> 'aouie123456'
	// So we translate 'aouie123456' -> '123456aouie'
	translated := strings.Map(func(r rune) rune {
		switch r {
		case 'a':
			return '1'
		case 'o':
			return '2'
		case 'u':
			return '3'
		case 'i':
			return '4'
		case 'e':
			return '5'
		case '1':
			return 'a'
		case '2':
			return 'o'
		case '3':
			return 'u'
		case '4':
			return 'i'
		case '5':
			return 'e'
		case '6':
			return '6' // stays same
		default:
			return r
		}
	}, string(decoded))

	// Replace the matched content with decoded
	result := d.extractPattern.ReplaceAllString(content, translated)
	if result == content {
		// If extract pattern didn't match, try simpler replacement
		result = "<?php " + translated + " ?>"
	}

	return result, nil
}
