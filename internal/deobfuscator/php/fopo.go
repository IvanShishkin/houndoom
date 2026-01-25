package php

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"io"
	"regexp"
	"strings"
)

// FOPODeobfuscator deobfuscates FOPO obfuscated PHP code
type FOPODeobfuscator struct {
	detectPattern *regexp.Regexp
	evalPattern   *regexp.Regexp
	quotePattern  *regexp.Regexp
}

// NewFOPODeobfuscator creates a new FOPO deobfuscator
func NewFOPODeobfuscator() *FOPODeobfuscator {
	return &FOPODeobfuscator{
		// FOPO signature pattern from reference
		detectPattern: regexp.MustCompile(`(?i)\$\w+="(\\x?[0-9a-f]+){13}";@eval\(\$\w+\(`),
		evalPattern:   regexp.MustCompile(`(?i)eval\s*\(([^;]+)\);`),
		quotePattern:  regexp.MustCompile(`['"]([^'"]+)['"]`),
	}
}

// Name returns the deobfuscator name
func (d *FOPODeobfuscator) Name() string {
	return "fopo"
}

// CanDeobfuscate checks if content can be deobfuscated by FOPO
func (d *FOPODeobfuscator) CanDeobfuscate(content string) bool {
	return d.detectPattern.MatchString(content)
}

// Deobfuscate deobfuscates FOPO obfuscated code
func (d *FOPODeobfuscator) Deobfuscate(content string) (string, error) {
	// Format PHP - remove <?php and ?>, normalize
	phpCode := d.formatPHP(content)

	// Get eval code
	evalCode := d.getEvalCode(phpCode)
	if evalCode == "" {
		return content, nil
	}

	// Get text inside quotes
	textInQuotes := d.getTextInsideQuotes(evalCode)
	if textInQuotes == "" {
		return content, nil
	}

	// First decode: base64
	decoded1, err := base64.StdEncoding.DecodeString(textInQuotes)
	if err != nil {
		return content, nil
	}

	// Split by ":" and get last part
	parts := strings.Split(string(decoded1), ":")
	if len(parts) == 0 {
		return content, nil
	}
	lastPart := d.getTextInsideQuotes(parts[len(parts)-1])
	if lastPart == "" {
		lastPart = parts[len(parts)-1]
	}

	// Apply rot13
	rotated := rot13(lastPart)

	// Decode base64
	decoded2, err := base64.StdEncoding.DecodeString(rotated)
	if err != nil {
		return content, nil
	}

	// Decompress (gzinflate)
	decompressed, err := gzinflate(decoded2)
	if err != nil {
		return content, nil
	}

	// Check if more layers need to be unwrapped
	result := string(decompressed)
	maxIterations := 10
	for i := 0; i < maxIterations && strings.Contains(result, "@eval($"); i++ {
		oldResult := result
		result = d.unwrapLayer(result)
		if result == oldResult {
			break
		}
	}

	// Skip first 2 characters if present (usually whitespace)
	if len(result) > 2 {
		result = result[2:]
	}

	return result, nil
}

// unwrapLayer unwraps one layer of FOPO encoding
func (d *FOPODeobfuscator) unwrapLayer(code string) string {
	// Count semicolons to determine encoding type
	funcs := strings.Split(code, ";")

	evalCode := d.getEvalCode(code)
	textInQuotes := d.getTextInsideQuotes(evalCode)
	if textInQuotes == "" {
		return code
	}

	var decoded []byte
	var err error

	if len(funcs) == 5 {
		// gzinflate(base64_decode(str_rot13(...)))
		rotated := rot13(textInQuotes)
		decodedB64, err := base64.StdEncoding.DecodeString(rotated)
		if err != nil {
			return code
		}
		decoded, err = gzinflate(decodedB64)
		if err != nil {
			return code
		}
	} else if len(funcs) == 4 {
		// gzinflate(base64_decode(...))
		decodedB64, err := base64.StdEncoding.DecodeString(textInQuotes)
		if err != nil {
			return code
		}
		decoded, err = gzinflate(decodedB64)
		if err != nil {
			return code
		}
	} else {
		return code
	}

	if err != nil {
		return code
	}

	return string(decoded)
}

// formatPHP removes PHP tags and normalizes code
func (d *FOPODeobfuscator) formatPHP(code string) string {
	code = strings.ReplaceAll(code, "<?php", "")
	code = strings.ReplaceAll(code, "?>", "")
	code = strings.ReplaceAll(code, "\n", "")
	code = strings.ReplaceAll(code, "\r", "")
	return code
}

// getEvalCode extracts eval code
func (d *FOPODeobfuscator) getEvalCode(code string) string {
	matches := d.evalPattern.FindStringSubmatch(code)
	if len(matches) < 2 {
		return ""
	}
	return matches[1]
}

// getTextInsideQuotes extracts text inside quotes
func (d *FOPODeobfuscator) getTextInsideQuotes(code string) string {
	matches := d.quotePattern.FindStringSubmatch(code)
	if len(matches) < 2 {
		return ""
	}
	return matches[1]
}

// gzinflate decompresses data using DEFLATE
func gzinflate(data []byte) ([]byte, error) {
	reader := flate.NewReader(bytes.NewReader(data))
	defer reader.Close()

	var result bytes.Buffer
	_, err := io.Copy(&result, reader)
	if err != nil {
		return nil, err
	}

	return result.Bytes(), nil
}
