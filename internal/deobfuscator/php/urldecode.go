package php

import (
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// URLDecodeDeobfuscator deobfuscates urldecode-based GLOBALS obfuscation
type URLDecodeDeobfuscator struct {
	detectPattern  *regexp.Regexp
	extractPattern *regexp.Regexp
	varAccessPat   *regexp.Regexp
	globalsPat     *regexp.Regexp
}

// NewURLDecodeDeobfuscator creates a new URLDecode deobfuscator
func NewURLDecodeDeobfuscator() *URLDecodeDeobfuscator {
	return &URLDecodeDeobfuscator{
		// Detection pattern - simplified (Go regexp doesn't support backreferences)
		detectPattern:  regexp.MustCompile(`(?i)(\$[O0_]+)=urldecode\("([%0-9a-f]+)"\);`),
		extractPattern: regexp.MustCompile(`(?i)(\$[O0_]+)=urldecode\("([%0-9a-f]+)"\);((\$[O0_]+=(\$[O0_]+\{\d+\}\.?)+;)+)`),
		varAccessPat:   regexp.MustCompile(`(\$[O0_]+)\{(\d+)\}\.?`),
		globalsPat:     regexp.MustCompile(`\$\{"GLOBALS"\}\["([^"]+)"\]`),
	}
}

// Name returns the deobfuscator name
func (d *URLDecodeDeobfuscator) Name() string {
	return "urldecode"
}

// CanDeobfuscate checks if content can be deobfuscated
func (d *URLDecodeDeobfuscator) CanDeobfuscate(content string) bool {
	return d.detectPattern.MatchString(content)
}

// Deobfuscate deobfuscates urldecode-based obfuscation
func (d *URLDecodeDeobfuscator) Deobfuscate(content string) (string, error) {
	result := content

	// Find the main pattern
	matches := d.extractPattern.FindStringSubmatch(content)
	if len(matches) < 4 {
		return content, nil
	}

	varName := matches[1]      // e.g., $O00O0O
	encodedAlph := matches[2]  // URL-encoded alphabet
	funcsBlock := matches[3]   // Variable definitions

	// Decode the alphabet
	alphabet, err := url.QueryUnescape(encodedAlph)
	if err != nil {
		return content, nil
	}

	// Build variable access pattern for this specific variable
	varAccessPat := regexp.MustCompile(regexp.QuoteMeta(varName) + `\{(\d+)\}\.?`)

	// Replace character accesses in funcs block
	decodedFuncs := varAccessPat.ReplaceAllStringFunc(funcsBlock, func(match string) string {
		submatches := varAccessPat.FindStringSubmatch(match)
		if len(submatches) < 2 {
			return match
		}
		idx, err := strconv.Atoi(submatches[1])
		if err != nil || idx >= len(alphabet) {
			return match
		}
		return string(alphabet[idx])
	})

	// Replace funcs block in result
	result = strings.Replace(result, funcsBlock, decodedFuncs, 1)

	// Build function name to value map
	funcMap := make(map[string]string)
	funcPat := regexp.MustCompile(`\$([O0_]+)=([^;]+);`)
	funcMatches := funcPat.FindAllStringSubmatch(decodedFuncs, -1)
	for _, m := range funcMatches {
		if len(m) >= 3 {
			funcMap[m[1]] = m[2]
		}
	}

	// Replace GLOBALS accesses
	result = d.globalsPat.ReplaceAllStringFunc(result, func(match string) string {
		submatches := d.globalsPat.FindStringSubmatch(match)
		if len(submatches) < 2 {
			return match
		}
		funcName := submatches[1]
		if val, ok := funcMap[funcName]; ok {
			return val
		}
		return match
	})

	// Also replace direct character accesses in the rest of the code
	result = varAccessPat.ReplaceAllStringFunc(result, func(match string) string {
		submatches := varAccessPat.FindStringSubmatch(match)
		if len(submatches) < 2 {
			return match
		}
		idx, err := strconv.Atoi(submatches[1])
		if err != nil || idx >= len(alphabet) {
			return match
		}
		return string(alphabet[idx])
	})

	return result, nil
}
