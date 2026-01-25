package php

import (
	"compress/zlib"
	"encoding/base64"
	"io"
	"regexp"
	"strings"
)

// EvalDeobfuscator deobfuscates eval() wrapped code
type EvalDeobfuscator struct{}

// NewEvalDeobfuscator creates a new Eval deobfuscator
func NewEvalDeobfuscator() *EvalDeobfuscator {
	return &EvalDeobfuscator{}
}

// Name returns the deobfuscator name
func (d *EvalDeobfuscator) Name() string {
	return "eval_php"
}

// CanDeobfuscate checks if content can be deobfuscated
func (d *EvalDeobfuscator) CanDeobfuscate(content string) bool {
	// Look for eval patterns with encoding functions
	patterns := []string{
		`eval\s*\(\s*base64_decode`,
		`eval\s*\(\s*gzinflate`,
		`eval\s*\(\s*str_rot13`,
		`eval\s*\(\s*strrev`,
		`eval\s*\(\s*gzuncompress`,
	}

	for _, pattern := range patterns {
		if matched, _ := regexp.MatchString(pattern, content); matched {
			return true
		}
	}

	return false
}

// Deobfuscate deobfuscates eval wrapped code
func (d *EvalDeobfuscator) Deobfuscate(content string) (string, error) {
	result := content

	// Try to unwrap common eval patterns
	result = d.unwrapEvalBase64(result)
	result = d.unwrapEvalGzinflate(result)
	result = d.unwrapEvalStrRot13(result)
	result = d.unwrapEvalStrrev(result)

	return result, nil
}

// unwrapEvalBase64 unwraps eval(base64_decode(...))
func (d *EvalDeobfuscator) unwrapEvalBase64(content string) string {
	re := regexp.MustCompile(`eval\s*\(\s*base64_decode\s*\(\s*['"]([A-Za-z0-9+/=]+)['"]\s*\)\s*\)`)

	return re.ReplaceAllStringFunc(content, func(match string) string {
		submatches := re.FindStringSubmatch(match)
		if len(submatches) < 2 {
			return match
		}

		decoded, err := base64.StdEncoding.DecodeString(submatches[1])
		if err != nil {
			return match
		}

		return string(decoded)
	})
}

// unwrapEvalGzinflate unwraps eval(gzinflate(base64_decode(...)))
func (d *EvalDeobfuscator) unwrapEvalGzinflate(content string) string {
	re := regexp.MustCompile(`eval\s*\(\s*gzinflate\s*\(\s*base64_decode\s*\(\s*['"]([A-Za-z0-9+/=]+)['"]\s*\)\s*\)\s*\)`)

	return re.ReplaceAllStringFunc(content, func(match string) string {
		submatches := re.FindStringSubmatch(match)
		if len(submatches) < 2 {
			return match
		}

		// Decode base64
		decoded, err := base64.StdEncoding.DecodeString(submatches[1])
		if err != nil {
			return match
		}

		// Decompress
		decompressed, err := gzinflateString(string(decoded))
		if err != nil {
			return match
		}

		return decompressed
	})
}

// unwrapEvalStrRot13 unwraps eval(str_rot13(...))
func (d *EvalDeobfuscator) unwrapEvalStrRot13(content string) string {
	re := regexp.MustCompile(`eval\s*\(\s*str_rot13\s*\(\s*['"]([^'"]+)['"]\s*\)\s*\)`)

	return re.ReplaceAllStringFunc(content, func(match string) string {
		submatches := re.FindStringSubmatch(match)
		if len(submatches) < 2 {
			return match
		}

		return rot13(submatches[1])
	})
}

// unwrapEvalStrrev unwraps eval(strrev(...))
func (d *EvalDeobfuscator) unwrapEvalStrrev(content string) string {
	re := regexp.MustCompile(`eval\s*\(\s*strrev\s*\(\s*['"]([^'"]+)['"]\s*\)\s*\)`)

	return re.ReplaceAllStringFunc(content, func(match string) string {
		submatches := re.FindStringSubmatch(match)
		if len(submatches) < 2 {
			return match
		}

		return reverse(submatches[1])
	})
}

// gzinflateString decompresses a gzinflate string
func gzinflateString(data string) (string, error) {
	reader, err := zlib.NewReader(strings.NewReader(data))
	if err != nil {
		return "", err
	}
	defer reader.Close()

	decompressed, err := io.ReadAll(reader)
	if err != nil {
		return "", err
	}

	return string(decompressed), nil
}

// rot13 performs ROT13 transformation
func rot13(s string) string {
	var result strings.Builder
	for _, r := range s {
		switch {
		case r >= 'A' && r <= 'Z':
			result.WriteRune('A' + (r-'A'+13)%26)
		case r >= 'a' && r <= 'z':
			result.WriteRune('a' + (r-'a'+13)%26)
		default:
			result.WriteRune(r)
		}
	}
	return result.String()
}

// reverse reverses a string
func reverse(s string) string {
	runes := []rune(s)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	return string(runes)
}
