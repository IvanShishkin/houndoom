package php

import (
	"encoding/base64"
	"regexp"
	"strconv"
	"strings"
)

// LockItDeobfuscator deobfuscates LockIt! obfuscated PHP code
type LockItDeobfuscator struct {
	// Pattern to detect LockIt! obfuscation
	detectPattern *regexp.Regexp
	hexPattern    *regexp.Regexp
	needlePattern *regexp.Regexp
}

// NewLockItDeobfuscator creates a new LockIt! deobfuscator
func NewLockItDeobfuscator() *LockItDeobfuscator {
	return &LockItDeobfuscator{
		// LockIt! signature pattern from reference
		detectPattern: regexp.MustCompile(`(?i)\$[O0]*=urldecode\('%66%67%36%73%62%65%68%70%72%61%34%63%6f%5f%74%6e%64'\);\s*\$GLOBALS\['[O0]*'\]=\$[O0]*`),
		hexPattern:    regexp.MustCompile(`0x[a-fA-F0-9]{1,8}`),
		needlePattern: regexp.MustCompile(`'([^']*)'`),
	}
}

// Name returns the deobfuscator name
func (d *LockItDeobfuscator) Name() string {
	return "lockit"
}

// CanDeobfuscate checks if content can be deobfuscated by LockIt!
func (d *LockItDeobfuscator) CanDeobfuscate(content string) bool {
	return d.detectPattern.MatchString(content)
}

// Deobfuscate deobfuscates LockIt! obfuscated code
func (d *LockItDeobfuscator) Deobfuscate(content string) (string, error) {
	// Get eval code
	evalCode := d.getEvalCode(content)
	if evalCode == "" {
		return content, nil
	}

	// Get text inside quotes from eval
	textInQuotes := d.getTextInsideQuotes(evalCode)
	if textInQuotes == "" {
		return content, nil
	}

	// Decode base64
	phpCode, err := base64.StdEncoding.DecodeString(textInQuotes)
	if err != nil {
		return content, nil
	}

	// Get hex values
	hexValues := d.getHexValues(string(phpCode))
	tmpPoint := d.getHexValues(content)

	if len(tmpPoint) == 0 || len(hexValues) < 2 {
		return content, nil
	}

	// Parse pointers
	pointer1 := d.hexToInt(tmpPoint[0])
	pointer2 := d.hexToInt(hexValues[0])
	pointer3 := d.hexToInt(hexValues[1])

	// Get needles
	needles := d.getNeedles(string(phpCode))
	if len(needles) < 2 {
		return content, nil
	}

	needle := needles[len(needles)-2]
	beforeNeedle := needles[len(needles)-1]

	// Calculate substring position
	start := pointer2 + pointer3
	end := start + pointer1
	if end > len(content) {
		end = len(content)
	}
	if start >= len(content) || start >= end {
		return content, nil
	}

	// Extract and transform
	substr := content[start:end]
	translated := strings.Map(func(r rune) rune {
		idx := strings.IndexRune(needle, r)
		if idx >= 0 && idx < len(beforeNeedle) {
			return rune(beforeNeedle[idx])
		}
		return r
	}, substr)

	// Decode final base64
	decoded, err := base64.StdEncoding.DecodeString(translated)
	if err != nil {
		return content, nil
	}

	return "<?php " + string(decoded) + " ?>", nil
}

// getEvalCode extracts eval code from string
func (d *LockItDeobfuscator) getEvalCode(str string) string {
	re := regexp.MustCompile(`eval\((.*?)\);`)
	matches := re.FindStringSubmatch(str)
	if len(matches) < 2 {
		return ""
	}
	return matches[1]
}

// getTextInsideQuotes extracts text inside quotes
func (d *LockItDeobfuscator) getTextInsideQuotes(str string) string {
	// Try double quotes first
	re := regexp.MustCompile(`"([^"]*)"`)
	matches := re.FindStringSubmatch(str)
	if len(matches) >= 2 {
		return matches[1]
	}

	// Try single quotes
	re = regexp.MustCompile(`'([^']*)'`)
	matches = re.FindStringSubmatch(str)
	if len(matches) >= 2 {
		return matches[1]
	}

	return ""
}

// getHexValues extracts hex values from string
func (d *LockItDeobfuscator) getHexValues(str string) []string {
	return d.hexPattern.FindAllString(str, -1)
}

// getNeedles extracts needle strings from code
func (d *LockItDeobfuscator) getNeedles(str string) []string {
	matches := d.needlePattern.FindAllStringSubmatch(str, -1)
	var needles []string
	for _, m := range matches {
		if len(m) >= 2 {
			needles = append(needles, m[1])
		}
	}
	return needles
}

// hexToInt converts hex string to int
func (d *LockItDeobfuscator) hexToInt(hex string) int {
	hex = strings.TrimPrefix(hex, "0x")
	hex = strings.TrimPrefix(hex, "0X")
	val, err := strconv.ParseInt(hex, 16, 64)
	if err != nil {
		return 0
	}
	return int(val)
}
