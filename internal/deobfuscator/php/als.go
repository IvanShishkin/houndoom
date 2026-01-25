package php

import (
	"encoding/base64"
	"regexp"
	"strings"
)

// ALSDeobfuscator deobfuscates ALS-Fullsite obfuscated PHP code
type ALSDeobfuscator struct {
	// Pattern to detect ALS obfuscation
	detectPattern *regexp.Regexp
	layer1Pattern *regexp.Regexp
	layer2Pattern *regexp.Regexp
}

// NewALSDeobfuscator creates a new ALS deobfuscator
func NewALSDeobfuscator() *ALSDeobfuscator {
	return &ALSDeobfuscator{
		// ALS-Fullsite signature pattern from reference
		detectPattern: regexp.MustCompile(`(?i)__FILE__;\$[O0]+=[0-9a-fx]+;eval\(\$[O0]+\('([^']+)'\)\);return;`),
		layer1Pattern: regexp.MustCompile(`(?i)__FILE__;\$[O0]+=[0-9a-fx]+;eval\(\$[O0]+\('([^']+)'\)\);return;`),
		layer2Pattern: regexp.MustCompile(`(?i)\$[O0]+=\(\$[O0]+\)+\$[O0]+,[0-9a-fx]+\),'([^']+)','([^']+)'\)\);eval\(`),
	}
}

// Name returns the deobfuscator name
func (d *ALSDeobfuscator) Name() string {
	return "als"
}

// CanDeobfuscate checks if content can be deobfuscated by ALS
func (d *ALSDeobfuscator) CanDeobfuscate(content string) bool {
	return d.detectPattern.MatchString(content)
}

// Deobfuscate deobfuscates ALS-Fullsite obfuscated code
func (d *ALSDeobfuscator) Deobfuscate(content string) (string, error) {
	// Find layer1 match
	layer1Match := d.layer1Pattern.FindStringSubmatch(content)
	if len(layer1Match) < 2 {
		return content, nil
	}

	// Decode first layer (base64)
	layer1Decoded, err := base64.StdEncoding.DecodeString(layer1Match[1])
	if err != nil {
		return content, nil
	}

	// Find layer2 patterns (translation tables)
	layer2Match := d.layer2Pattern.FindStringSubmatch(string(layer1Decoded))
	if len(layer2Match) < 3 {
		return content, nil
	}

	fromChars := layer2Match[1]
	toChars := layer2Match[2]

	// Split by ?> to get encoded data
	parts := strings.Split(content, "?>")
	if len(parts) < 2 || len(parts[len(parts)-1]) <= 380 {
		return content, nil
	}

	// Get encoded data (skip first 380 bytes)
	encodedData := parts[len(parts)-1]
	if len(encodedData) <= 380 {
		return content, nil
	}
	encodedData = encodedData[380:]

	// Translate using character mapping
	translated := strings.Map(func(r rune) rune {
		idx := strings.IndexRune(fromChars, r)
		if idx >= 0 && idx < len(toChars) {
			return rune(toChars[idx])
		}
		return r
	}, encodedData)

	// Decode final base64
	decoded, err := base64.StdEncoding.DecodeString(translated)
	if err != nil {
		return content, nil
	}

	return "<?php " + string(decoded) + " ?>", nil
}
