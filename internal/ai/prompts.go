package ai

import (
	"fmt"
	"path/filepath"
	"strings"
)

// LanguageInstruction returns the language instruction for prompts
func LanguageInstruction(lang string) string {
	switch lang {
	case "ru":
		return "\n\nIMPORTANT: Respond in Russian (Русский). All text fields (explanation, remediation, indicators) must be in Russian."
	case "es":
		return "\n\nIMPORTANT: Respond in Spanish (Español). All text fields (explanation, remediation, indicators) must be in Spanish."
	case "de":
		return "\n\nIMPORTANT: Respond in German (Deutsch). All text fields (explanation, remediation, indicators) must be in German."
	case "zh":
		return "\n\nIMPORTANT: Respond in Chinese (中文). All text fields (explanation, remediation, indicators) must be in Chinese."
	default:
		return "" // English is default, no extra instruction needed
	}
}

// GetLanguageName returns the display name for a language code
func GetLanguageName(lang string) string {
	switch lang {
	case "ru":
		return "Русский"
	case "es":
		return "Español"
	case "de":
		return "Deutsch"
	case "zh":
		return "中文"
	default:
		return "English"
	}
}

// getSyntaxLang returns the syntax highlighting language for a file extension
func getSyntaxLang(filePath string) string {
	ext := strings.ToLower(filepath.Ext(filePath))
	switch ext {
	case ".js", ".mjs", ".cjs":
		return "javascript"
	case ".ts", ".tsx":
		return "typescript"
	case ".html", ".htm", ".tpl", ".blade.php":
		return "html"
	case ".css", ".scss", ".sass":
		return "css"
	case ".py":
		return "python"
	case ".rb":
		return "ruby"
	case ".pl", ".pm":
		return "perl"
	case ".sh", ".bash":
		return "bash"
	case ".sql":
		return "sql"
	case ".xml":
		return "xml"
	case ".json":
		return "json"
	case ".yaml", ".yml":
		return "yaml"
	default:
		return "php" // default for web security scanner
	}
}

// QuickFilterSystemPrompt is used for fast triage with Haiku
const QuickFilterSystemPrompt = `You are a security analyst performing initial triage of web application scanner findings.
Determine if a finding requires deep analysis or can be dismissed as a false positive.

OUTPUT: Valid JSON only, no markdown formatting.
{"needs_analysis": true|false, "reason": "brief explanation (max 100 chars)", "confidence": 0-100}

DISMISS (needs_analysis=false) when ALL conditions met:
- File is in standard CMS/framework directory: /wp-includes/, /bitrix/modules/, /vendor/, /node_modules/
- Code matches known libraries: jQuery, React, Vue, Bootstrap, Lodash, Moment.js
- Pattern is standard framework helper: Laravel Blade, Symfony Twig, WordPress hooks
- Minified JS/CSS from reputable sources with matching sourcemaps

ESCALATE (needs_analysis=true) for ANY of these:
- Dynamic code execution: eval(), assert(), create_function(), preg_replace with /e
- Encoding chains: base64_decode(), gzinflate(), gzuncompress(), str_rot13()
- User input to dangerous functions: $_GET/$_POST/$_REQUEST → exec/include/file_put_contents
- Obfuscated identifiers: $O0O0O0, ${"_"."GET"}, $$variable, chr() arithmetic
- Suspicious file locations: /uploads/, /tmp/, /cache/, /images/ containing .php
- Extension mismatches: .php.jpg, .php.txt, .php.gif, .phtml, .phar
- Network functions with variables: curl_exec(), fsockopen(), file_get_contents("http://...")
- File manipulation: fwrite/file_put_contents to .php files

ALWAYS ESCALATE when uncertain. False negatives are worse than false positives.`

// DeepAnalysisSystemPrompt is used for thorough analysis with Sonnet/Opus
const DeepAnalysisSystemPrompt = `You are an expert malware analyst specializing in web shells, PHP backdoors, and web application threats.
Analyze the code finding and provide a definitive security verdict with evidence.

OUTPUT: Valid JSON only, no markdown. Do not escape unicode in strings.
{
  "verdict": "malicious|suspicious|false_positive|benign",
  "confidence": 0-100,
  "explanation": "detailed technical analysis with specific code references",
  "remediation": "actionable steps: delete file, remove code block, update CMS, etc.",
  "indicators": ["specific threat indicators found in this code"],
  "risk_level": "critical|high|medium|low"
}

VERDICT CRITERIA:

malicious (confidence ≥80):
- Confirmed web shell: c99, r57, WSO, FilesMan, Alfa Shell
- Backdoor patterns: hidden admin access, authentication bypass
- Active threats: cryptominers, spam mailers, SEO spam injectors
- Data exfiltration: credential harvesting, database dumps to external
- Ransomware droppers, defacement scripts

suspicious (confidence 50-79):
- Obfuscated code without clear legitimate purpose
- Unusual file permissions or ownership patterns
- Code that COULD be malicious but lacks definitive indicators
- Legitimate tools in wrong locations (phpMyAdmin in /uploads/)

false_positive (confidence ≥70):
- CMS core files: WordPress wp-includes, Bitrix /bitrix/modules/
- Known security plugins: Wordfence, Sucuri, iThemes Security
- Development/debug tools in appropriate locations
- Commented out or dead code
- Test files with sample malicious patterns

benign (confidence ≥80):
- Standard application code with no security concerns
- Common libraries and frameworks
- Safe use of flagged functions (eval in templates, base64 for images)

MALWARE INDICATORS (weight by specificity):
High: preg_replace('/e',...$_), create_function($_), assert($_), $$_POST
High: fsockopen+base64_decode, curl to hardcoded IP, fwrite to .php
High: @$_=, ${'_'.'GET'}, chr(ord()) chains, ${"\x47\x4c"}
Medium: file_get_contents($_GET), include($_POST), system($cmd)
Medium: FilesMan, c99shell, r57shell, WSO, b374k in strings/comments
Low: eval() alone, base64_decode alone (check context)

FALSE POSITIVE SIGNALS:
- Path contains: /vendor/, /node_modules/, /wp-includes/, /bitrix/modules/
- Known file hashes (WordPress, Joomla core)
- Code style matches CMS conventions
- Legitimate admin functionality in admin directories

CONTEXT RULES:
- /wp-admin/, /bitrix/admin/, /administrator/ → higher false positive threshold
- /uploads/, /images/, /tmp/, /cache/ → PHP files always suspicious
- Hidden files (.filename.php, ....php) → likely malicious
- Recently modified core files → check for injection

Provide EVIDENCE: quote specific code snippets that support your verdict.
If genuinely uncertain, use "suspicious" with lower confidence, never "unknown".`

// BuildQuickFilterPrompt builds the user prompt for quick filtering
func BuildQuickFilterPrompt(req *AnalysisRequest, lang string) string {
	var sb strings.Builder

	// Compact format for quick triage - minimize tokens
	sb.WriteString(fmt.Sprintf("SIGNATURE: %s [%s]\n", req.SignatureName, req.SignatureID))
	sb.WriteString(fmt.Sprintf("SEVERITY: %s | TYPE: %s | CONFIDENCE: %d%%\n", req.Severity, req.ThreatType, req.Confidence))
	sb.WriteString(fmt.Sprintf("FILE: %s:%d\n", req.FilePath, req.LineNumber))

	if req.CMSContext != "" {
		sb.WriteString(fmt.Sprintf("CMS: %s\n", req.CMSContext))
	}

	syntaxLang := getSyntaxLang(req.FilePath)
	sb.WriteString(fmt.Sprintf("\nCODE:\n```%s\n", syntaxLang))
	sb.WriteString(truncateCode(req.CodeFragment, 600))
	sb.WriteString("\n```")

	// Quick filter reason is internal, no language needed
	return sb.String()
}

// BuildDeepAnalysisPrompt builds the user prompt for deep analysis
func BuildDeepAnalysisPrompt(req *AnalysisRequest, lang string) string {
	var sb strings.Builder

	// Structured table format for clarity
	sb.WriteString("## Finding\n\n")
	sb.WriteString("| Field | Value |\n")
	sb.WriteString("|-------|-------|\n")
	sb.WriteString(fmt.Sprintf("| Signature | %s (`%s`) |\n", req.SignatureName, req.SignatureID))
	sb.WriteString(fmt.Sprintf("| Severity | %s |\n", req.Severity))
	sb.WriteString(fmt.Sprintf("| Threat Type | %s |\n", req.ThreatType))
	sb.WriteString(fmt.Sprintf("| Scanner Confidence | %d%% |\n", req.Confidence))
	sb.WriteString(fmt.Sprintf("| File | `%s` |\n", req.FilePath))
	sb.WriteString(fmt.Sprintf("| Line | %d |\n", req.LineNumber))

	if req.CMSContext != "" {
		sb.WriteString(fmt.Sprintf("| CMS | %s |\n", req.CMSContext))
	}

	// Add path analysis hints
	sb.WriteString("\n## Path Analysis\n\n")
	pathLower := strings.ToLower(req.FilePath)
	if containsAny(pathLower, []string{"/uploads/", "/upload/", "/images/", "/img/", "/tmp/", "/cache/"}) {
		sb.WriteString("⚠️ File in writable/upload directory - PHP files here are suspicious\n")
	}
	if containsAny(pathLower, []string{"/wp-admin/", "/wp-includes/", "/bitrix/modules/", "/administrator/", "/vendor/"}) {
		sb.WriteString("ℹ️ File in CMS/framework core directory - check if modified from original\n")
	}
	if strings.Contains(filepath.Base(req.FilePath), ".php.") || strings.HasPrefix(filepath.Base(req.FilePath), ".") {
		sb.WriteString("⚠️ Suspicious filename pattern detected\n")
	}

	// Scanner description if available
	if req.Description != "" {
		sb.WriteString(fmt.Sprintf("\n## Scanner Note\n\n%s\n", req.Description))
	}

	// Code with proper syntax highlighting
	syntaxLang := getSyntaxLang(req.FilePath)
	sb.WriteString(fmt.Sprintf("\n## Code\n\n```%s\n", syntaxLang))
	sb.WriteString(truncateCode(req.CodeFragment, 3000))
	sb.WriteString("\n```\n")

	// Analysis instructions are in system prompt, no need to repeat

	// Add language instruction for output
	sb.WriteString(LanguageInstruction(lang))

	return sb.String()
}

// containsAny checks if s contains any of the substrings
func containsAny(s string, substrings []string) bool {
	for _, sub := range substrings {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// truncateCode truncates code to a maximum length while preserving complete lines
// and keeping both the beginning and end of the code for context
func truncateCode(code string, maxLen int) string {
	code = strings.TrimSpace(code)
	if len(code) <= maxLen {
		return code
	}

	// For very long code, keep beginning and end (malware often at start or end)
	if len(code) > maxLen*2 {
		headLen := maxLen * 2 / 3
		tailLen := maxLen / 3

		head := code[:headLen]
		tail := code[len(code)-tailLen:]

		// Find clean break points
		if idx := strings.LastIndex(head, "\n"); idx > headLen/2 {
			head = head[:idx]
		}
		if idx := strings.Index(tail, "\n"); idx > 0 && idx < tailLen/2 {
			tail = tail[idx+1:]
		}

		return head + "\n\n... [" + fmt.Sprintf("%d bytes truncated", len(code)-len(head)-len(tail)) + "] ...\n\n" + tail
	}

	// For moderately long code, just truncate from end
	truncated := code[:maxLen]
	if idx := strings.LastIndex(truncated, "\n"); idx > maxLen/2 {
		truncated = truncated[:idx]
	}

	return truncated + "\n... [truncated]"
}
