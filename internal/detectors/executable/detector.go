package executable

import (
	"bytes"
	"context"
	"strings"
	"time"

	"github.com/IvanShishkin/houndoom/internal/detectors"
	"github.com/IvanShishkin/houndoom/pkg/models"
)

// Detector detects executable files, binaries, and scripts
type Detector struct {
	*detectors.BaseDetector
}

// Magic bytes for different executable formats
var magicBytes = map[string][]byte{
	"ELF":     {0x7f, 0x45, 0x4c, 0x46},          // ELF binary (Linux)
	"PE":      {0x4d, 0x5a},                       // PE/MZ (Windows exe)
	"MachO32": {0xfe, 0xed, 0xfa, 0xce},          // Mach-O 32-bit
	"MachO64": {0xfe, 0xed, 0xfa, 0xcf},          // Mach-O 64-bit
	"MachOFat":{0xca, 0xfe, 0xba, 0xbe},          // Mach-O Fat binary
	"Java":    {0xca, 0xfe, 0xba, 0xbe},          // Java class file
	"DEX":     {0x64, 0x65, 0x78, 0x0a},          // Android DEX
}

// Shebang interpreters that indicate executable scripts
var shebangInterpreters = []string{
	"#!/bin/sh", "#!/bin/bash", "#!/usr/bin/env bash",
	"#!/usr/bin/perl", "#!/usr/bin/env perl",
	"#!/usr/bin/python", "#!/usr/bin/env python",
	"#!/usr/bin/ruby", "#!/usr/bin/env ruby",
	"#!/usr/bin/php", "#!/usr/bin/env php",
	"#!/usr/bin/node", "#!/usr/bin/env node",
}

// Suspicious script patterns
var suspiciousScriptPatterns = []struct {
	pattern string
	name    string
	desc    string
}{
	{"rm -rf /", "Destructive rm", "Potentially destructive rm -rf / command"},
	{"rm -rf /*", "Destructive rm", "Potentially destructive rm -rf /* command"},
	{"dd if=/dev/zero", "Disk wipe", "Disk wipe command detected"},
	{":(){ :|:& };:", "Fork bomb", "Fork bomb pattern detected"},
	{"mkfs.", "Filesystem format", "Filesystem format command detected"},
	{"> /dev/sda", "Direct disk write", "Direct write to disk device detected"},
	{"chmod 777 /", "Dangerous chmod", "Dangerous recursive chmod on root"},
	{"wget ", "Remote download", "wget command for remote file download"},
	{"curl ", "Remote download", "curl command for remote file download"},
	{"nc -e", "Netcat shell", "Netcat reverse shell pattern"},
	{"bash -i >& /dev/tcp", "Reverse shell", "Bash reverse shell pattern"},
	{"/dev/tcp/", "TCP device", "Bash TCP device access (possible reverse shell)"},
	{"base64 -d", "Base64 decode", "Base64 decoding in script"},
	{"eval $(", "Eval execution", "Eval with command substitution"},
}

// NewDetector creates a new executable detector
func NewDetector() *Detector {
	return &Detector{
		BaseDetector: detectors.NewBaseDetector("executable", 60, []string{
			"sh", "bash", "pl", "py", "rb", "cgi", "so", "o", "bin", "exe", "*",
		}),
	}
}

// Detect scans a file for executable indicators
func (d *Detector) Detect(ctx context.Context, file *models.File) ([]*models.Finding, error) {
	var findings []*models.Finding

	// 1. Check for binary magic bytes
	for name, magic := range magicBytes {
		if len(file.Content) >= len(magic) && bytes.HasPrefix(file.Content, magic) {
			findings = append(findings, &models.Finding{
				File:          file,
				Type:          models.ThreatExecutable,
				Severity:      models.SeverityHigh,
				SignatureID:   "EXEC-BINARY-" + name,
				SignatureName: name + " Binary Detected",
				Description:   "Binary executable file detected (" + name + " format)",
				Position:      0,
				LineNumber:    1,
				Snippet:       "", // Don't show binary content
				Fragment:      "",
				Confidence:    95,
				Timestamp:     time.Now(),
				Metadata: map[string]any{
					"format": name,
				},
			})
			return findings, nil // Binary found, no need to check further
		}
	}

	// 2. Check content for script analysis
	content := string(file.Content)
	contentLines := strings.Split(content, "\n")

	// Detect if file has shebang (used later for suspicious pattern check)
	hasShebang := false
	if len(contentLines) > 0 {
		firstLine := strings.TrimSpace(contentLines[0])
		for _, shebang := range shebangInterpreters {
			if strings.HasPrefix(firstLine, shebang) || strings.HasPrefix(firstLine, strings.ReplaceAll(shebang, " ", "\t")) {
				hasShebang = true
				break
			}
		}
	}
	// Note: We don't report shebang scripts as threats anymore - only suspicious patterns

	// 3. Check for suspicious script patterns (only for scripts or shell-like extensions)
	ext := strings.ToLower(file.Extension)
	isScript := ext == "sh" || ext == "bash" || ext == "pl" || ext == "py" || ext == "rb" || ext == "cgi"

	if isScript || hasShebang {
		contentLower := strings.ToLower(content)
		for _, pattern := range suspiciousScriptPatterns {
			if idx := strings.Index(contentLower, strings.ToLower(pattern.pattern)); idx != -1 {
				lineNumber := countLines(content[:idx]) + 1
				findings = append(findings, &models.Finding{
					File:          file,
					Type:          models.ThreatExecutable,
					Severity:      models.SeverityCritical,
					SignatureID:   "EXEC-MALICIOUS",
					SignatureName: pattern.name,
					Description:   pattern.desc,
					Position:      idx,
					LineNumber:    lineNumber,
					Snippet:       content[idx:min(idx+len(pattern.pattern)+50, len(content))],
					Fragment:      getContext(content, idx, 100),
					Confidence:    85,
					Timestamp:     time.Now(),
				})
			}
		}
	}

	// 4. Check for CGI scripts in web directories
	if ext == "cgi" || ext == "pl" {
		pathLower := strings.ToLower(file.Path)
		if strings.Contains(pathLower, "cgi-bin") || strings.Contains(pathLower, "cgi") {
			// Check for dangerous operations in CGI
			dangerousCGI := []string{"system(", "exec(", "`", "open(|", "qx{"}
			for _, danger := range dangerousCGI {
				if idx := strings.Index(content, danger); idx != -1 {
					lineNumber := countLines(content[:idx]) + 1
					findings = append(findings, &models.Finding{
						File:          file,
						Type:          models.ThreatExecutable,
						Severity:      models.SeverityHigh,
						SignatureID:   "EXEC-CGI-DANGER",
						SignatureName: "Dangerous CGI Operation",
						Description:   "CGI script with potentially dangerous operation: " + danger,
						Position:      idx,
						LineNumber:    lineNumber,
						Snippet:       content[idx:min(idx+100, len(content))],
						Fragment:      getContext(content, idx, 100),
						Confidence:    80,
						Timestamp:     time.Now(),
					})
				}
			}
		}
	}

	return findings, nil
}

func countLines(s string) int {
	return strings.Count(s, "\n")
}

func getFirstLines(content string, n int) string {
	lines := strings.Split(content, "\n")
	if len(lines) > n {
		lines = lines[:n]
	}
	return strings.Join(lines, "\n")
}

func getContext(content string, pos, size int) string {
	start := pos - size
	if start < 0 {
		start = 0
	}
	end := pos + size
	if end > len(content) {
		end = len(content)
	}
	return content[start:end]
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
