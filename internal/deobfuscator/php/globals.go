package php

import (
	"encoding/base64"
	"regexp"
	"strconv"
	"strings"
)

// GlobalsDeobfuscator deobfuscates Bitrix-style GLOBALS obfuscation
type GlobalsDeobfuscator struct {
	detectPattern1   *regexp.Regexp
	detectPattern2   *regexp.Regexp
	globalsArrayPat  *regexp.Regexp
	globalsAccessPat *regexp.Regexp
	functionPat      *regexp.Regexp
	base64Pat        *regexp.Regexp
	concatPat        *regexp.Regexp
}

// NewGlobalsDeobfuscator creates a new GLOBALS deobfuscator
func NewGlobalsDeobfuscator() *GlobalsDeobfuscator {
	return &GlobalsDeobfuscator{
		// Detection patterns from reference
		detectPattern1:   regexp.MustCompile(`(?i)\$GLOBALS\[\s*['"]_+\w{1,60}['"]\s*\]\s*=\s*\s*array\s*\(\s*base64_decode\s*\(`),
		detectPattern2:   regexp.MustCompile(`(?i)function\s*_+\d+\s*\(\s*\$i\s*\)\s*\{\s*\$a\s*=\s*Array`),
		globalsArrayPat:  regexp.MustCompile(`(?i)\$GLOBALS\['([^']+)'\]\s*=\s*Array\(([^;]+)\);`),
		globalsAccessPat: regexp.MustCompile(`\$GLOBALS\['([^']+)'\]\[(\d+)\]`),
		functionPat:      regexp.MustCompile(`(?i)function\s*(\w{1,60})\(\$\w+\)\s*\{\s*\$\w{1,60}\s*=\s*Array\(([^}]+)\);[^}]+\}`),
		base64Pat:        regexp.MustCompile(`base64_decode\(['"]([^'"]+)['"]\)`),
		concatPat:        regexp.MustCompile(`['"]s*\.\s*['"]`),
	}
}

// Name returns the deobfuscator name
func (d *GlobalsDeobfuscator) Name() string {
	return "globals"
}

// CanDeobfuscate checks if content can be deobfuscated
func (d *GlobalsDeobfuscator) CanDeobfuscate(content string) bool {
	return d.detectPattern1.MatchString(content) || d.detectPattern2.MatchString(content)
}

// Deobfuscate deobfuscates GLOBALS-based obfuscation
func (d *GlobalsDeobfuscator) Deobfuscate(content string) (string, error) {
	result := content

	// Remove empty string concatenations
	result = d.concatPat.ReplaceAllString(result, "")

	// Decode base64 strings
	result = d.base64Pat.ReplaceAllStringFunc(result, func(match string) string {
		submatches := d.base64Pat.FindStringSubmatch(match)
		if len(submatches) < 2 {
			return match
		}
		decoded, err := base64.StdEncoding.DecodeString(submatches[1])
		if err != nil {
			return match
		}
		return `'` + string(decoded) + `'`
	})

	// Try to decode quoted base64 strings
	result = d.decodeQuotedBase64(result)

	// Build GLOBALS arrays map
	globalsMap := make(map[string][]string)
	globalsMatches := d.globalsArrayPat.FindAllStringSubmatch(result, -1)
	for _, match := range globalsMatches {
		if len(match) >= 3 {
			varName := match[1]
			arrayContent := match[2]
			// Parse array values
			values := d.parseArrayValues(arrayContent)
			globalsMap[varName] = values
		}
	}

	// Replace GLOBALS array accesses
	for varName, values := range globalsMap {
		pattern := regexp.MustCompile(`\$GLOBALS\['` + regexp.QuoteMeta(varName) + `'\]\[(\d+)\]`)
		result = pattern.ReplaceAllStringFunc(result, func(match string) string {
			submatches := pattern.FindStringSubmatch(match)
			if len(submatches) < 2 {
				return match
			}
			idx, err := strconv.Atoi(submatches[1])
			if err != nil || idx >= len(values) {
				return match
			}
			return values[idx]
		})
	}

	// Process function-based string arrays
	funcMatches := d.functionPat.FindAllStringSubmatch(result, -1)
	for _, match := range funcMatches {
		if len(match) >= 3 {
			funcName := match[1]
			arrayContent := match[2]
			values := d.parseArrayValues(arrayContent)

			// Replace function calls with values
			funcCallPat := regexp.MustCompile(regexp.QuoteMeta(funcName) + `\((\d+)\)`)
			result = funcCallPat.ReplaceAllStringFunc(result, func(call string) string {
				submatches := funcCallPat.FindStringSubmatch(call)
				if len(submatches) < 2 {
					return call
				}
				idx, err := strconv.Atoi(submatches[1])
				if err != nil || idx >= len(values) {
					return call
				}
				return values[idx]
			})
		}
	}

	// Clean up empty PHP tags
	result = regexp.MustCompile(`<\?(php)?\s*\?>`).ReplaceAllString(result, "")

	return result, nil
}

// parseArrayValues parses PHP array values
func (d *GlobalsDeobfuscator) parseArrayValues(arrayContent string) []string {
	var values []string
	// Simple comma split (doesn't handle nested arrays)
	parts := strings.Split(arrayContent, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		// Remove quotes
		part = strings.Trim(part, `'"`)
		values = append(values, part)
	}
	return values
}

// decodeQuotedBase64 tries to decode base64 strings in quotes
func (d *GlobalsDeobfuscator) decodeQuotedBase64(content string) string {
	quotePat := regexp.MustCompile(`['"]([A-Za-z0-9+/=]{20,})['"]`)
	return quotePat.ReplaceAllStringFunc(content, func(match string) string {
		submatches := quotePat.FindStringSubmatch(match)
		if len(submatches) < 2 {
			return match
		}
		encoded := submatches[1]
		decoded, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return match
		}
		// Check if decoded content is printable
		decodedStr := string(decoded)
		if base64.StdEncoding.EncodeToString(decoded) == encoded && isPrintable(decodedStr) {
			return `'` + decodedStr + `'`
		}
		return match
	})
}

// isPrintable checks if string contains only printable characters
func isPrintable(s string) bool {
	for _, r := range s {
		if r < 32 || r > 126 {
			if r != '\n' && r != '\r' && r != '\t' {
				return false
			}
		}
	}
	return true
}
