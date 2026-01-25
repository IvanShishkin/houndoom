package report

import (
	"fmt"
	"os"
	"strings"

	"github.com/IvanShishkin/houndoom/internal/ai"
	"github.com/IvanShishkin/houndoom/pkg/models"
)

// generateMarkdown generates a Markdown report
func (g *Generator) generateMarkdown(results *models.ScanResults, aiReport *ai.AIReport, outputFile string) error {
	var sb strings.Builder

	// Header
	sb.WriteString(fmt.Sprintf("# Houndoom Security Scanner Report v%s\n\n", results.Version))

	// Summary
	sb.WriteString("## Summary\n\n")
	sb.WriteString("| Parameter | Value |\n")
	sb.WriteString("|-----------|-------|\n")
	sb.WriteString(fmt.Sprintf("| Scan Path | `%s` |\n", results.ScanPath))
	sb.WriteString(fmt.Sprintf("| Scan Mode | %s |\n", results.Mode))
	sb.WriteString(fmt.Sprintf("| Start Time | %s |\n", results.StartTime.Format("2006-01-02 15:04:05")))
	sb.WriteString(fmt.Sprintf("| End Time | %s |\n", results.EndTime.Format("2006-01-02 15:04:05")))
	sb.WriteString(fmt.Sprintf("| Duration | %s |\n", FormatDuration(results.Duration)))
	sb.WriteString(fmt.Sprintf("| Total Files | %d |\n", results.TotalFiles))
	sb.WriteString(fmt.Sprintf("| Scanned Files | %d |\n", results.ScannedFiles))
	sb.WriteString(fmt.Sprintf("| Skipped Files | %d |\n", results.SkippedFiles))
	sb.WriteString(fmt.Sprintf("| **Threats Found** | **%d** |\n", results.ThreatsFound))
	sb.WriteString("\n")

	if results.ThreatsFound == 0 {
		sb.WriteString("> ✅ **No threats detected**\n\n")
		return os.WriteFile(outputFile, []byte(sb.String()), 0644)
	}

	// Statistics by severity
	sb.WriteString("## Threats by Severity\n\n")
	sb.WriteString("| Severity | Count |\n")
	sb.WriteString("|----------|-------|\n")

	for _, severity := range []models.Severity{
		models.SeverityCritical,
		models.SeverityHigh,
		models.SeverityMedium,
		models.SeverityLow,
		models.SeverityInfo,
	} {
		findings := results.FindingsBySeverity[severity]
		if len(findings) > 0 {
			emoji := getSeverityEmoji(severity)
			sb.WriteString(fmt.Sprintf("| %s %s | %d |\n", emoji, strings.ToUpper(string(severity)), len(findings)))
		}
	}
	sb.WriteString("\n")

	// Statistics by type
	if results.Stats != nil {
		sb.WriteString("## Threats by Type\n\n")
		sb.WriteString("| Type | Count |\n")
		sb.WriteString("|------|-------|\n")

		if results.Stats.PHPBackdoors > 0 {
			sb.WriteString(fmt.Sprintf("| PHP Backdoors | %d |\n", results.Stats.PHPBackdoors))
		}
		if results.Stats.JSViruses > 0 {
			sb.WriteString(fmt.Sprintf("| JS Viruses | %d |\n", results.Stats.JSViruses))
		}
		if results.Stats.PhishingPages > 0 {
			sb.WriteString(fmt.Sprintf("| Phishing Pages | %d |\n", results.Stats.PhishingPages))
		}
		if results.Stats.IframeInjections > 0 {
			sb.WriteString(fmt.Sprintf("| IFRAME Injections | %d |\n", results.Stats.IframeInjections))
		}
		if results.Stats.ObfuscatedFiles > 0 {
			sb.WriteString(fmt.Sprintf("| Obfuscated Files | %d |\n", results.Stats.ObfuscatedFiles))
		}
		if results.Stats.SuspiciousFiles > 0 {
			sb.WriteString(fmt.Sprintf("| Suspicious Files | %d |\n", results.Stats.SuspiciousFiles))
		}
		sb.WriteString("\n")
	}

	// Detailed findings
	sb.WriteString("## Detailed Findings\n\n")

	for i, finding := range results.Findings {
		emoji := getSeverityEmoji(finding.Severity)
		sb.WriteString(fmt.Sprintf("### %d. %s %s\n\n", i+1, emoji, finding.SignatureName))

		sb.WriteString("| Field | Value |\n")
		sb.WriteString("|-------|-------|\n")
		sb.WriteString(fmt.Sprintf("| File | `%s` |\n", finding.File.Path))
		sb.WriteString(fmt.Sprintf("| Line | %d |\n", finding.LineNumber))
		sb.WriteString(fmt.Sprintf("| Severity | %s |\n", strings.ToUpper(string(finding.Severity))))
		sb.WriteString(fmt.Sprintf("| Type | %s |\n", finding.Type))
		sb.WriteString(fmt.Sprintf("| Confidence | %d%% |\n", finding.Confidence))
		sb.WriteString(fmt.Sprintf("| Signature ID | `%s` |\n", finding.SignatureID))
		sb.WriteString("\n")

		if finding.Description != "" {
			sb.WriteString(fmt.Sprintf("**Description:** %s\n\n", finding.Description))
		}

		if finding.Fragment != "" {
			sb.WriteString("**Code Fragment:**\n\n")
			sb.WriteString("```php\n")
			sb.WriteString(finding.Fragment)
			sb.WriteString("\n```\n\n")
		}

		sb.WriteString("---\n\n")
	}

	// AI Analysis section
	if aiReport != nil && len(aiReport.Results) > 0 {
		sb.WriteString("## AI Analysis\n\n")

		// Summary table
		sb.WriteString("### Summary\n\n")
		sb.WriteString("| Metric | Value |\n")
		sb.WriteString("|--------|-------|\n")
		if aiReport.IsSmartMode {
			sb.WriteString(fmt.Sprintf("| Mode | Smart (%d signatures) |\n", aiReport.UniqueSignatures))
		}
		sb.WriteString(fmt.Sprintf("| Model | %s |\n", aiReport.Model))
		sb.WriteString(fmt.Sprintf("| Findings Analyzed | %d |\n", aiReport.AnalyzedCount))
		sb.WriteString(fmt.Sprintf("| 🔴 Malicious | %d |\n", aiReport.MaliciousCount))
		sb.WriteString(fmt.Sprintf("| 🟠 Suspicious | %d |\n", aiReport.SuspiciousCount))
		sb.WriteString(fmt.Sprintf("| 🟢 False Positives | %d |\n", aiReport.FalsePositiveCount))
		sb.WriteString(fmt.Sprintf("| 🔵 Benign | %d |\n", aiReport.BenignCount))
		sb.WriteString(fmt.Sprintf("| Tokens Used | %d |\n", aiReport.TotalTokensUsed))
		sb.WriteString(fmt.Sprintf("| Duration | %s |\n", FormatDuration(aiReport.Duration)))
		sb.WriteString("\n")

		// Detailed verdicts
		sb.WriteString("### AI Verdicts\n\n")

		for i, result := range aiReport.Results {
			emoji := ai.GetVerdictEmoji(result.Verdict)
			sb.WriteString(fmt.Sprintf("#### %d. %s %s (Confidence: %d%%)\n\n", i+1, emoji, strings.ToUpper(string(result.Verdict)), result.Confidence))

			sb.WriteString(fmt.Sprintf("**Risk Level:** %s\n\n", result.RiskLevel))
			sb.WriteString(fmt.Sprintf("**Explanation:** %s\n\n", result.Explanation))

			if result.Remediation != "" {
				sb.WriteString(fmt.Sprintf("**Remediation:** %s\n\n", result.Remediation))
			}

			if len(result.Indicators) > 0 {
				sb.WriteString("**Indicators:**\n")
				for _, indicator := range result.Indicators {
					sb.WriteString(fmt.Sprintf("- `%s`\n", indicator))
				}
				sb.WriteString("\n")
			}

			sb.WriteString("---\n\n")
		}
	}

	// Performance stats
	if results.Stats != nil {
		sb.WriteString("## Performance\n\n")
		sb.WriteString("| Metric | Value |\n")
		sb.WriteString("|--------|-------|\n")
		sb.WriteString(fmt.Sprintf("| Files/Second | %.2f |\n", results.Stats.FilesPerSecond))
		sb.WriteString(fmt.Sprintf("| Workers Used | %d |\n", results.Stats.WorkersUsed))
		sb.WriteString(fmt.Sprintf("| Memory Used | %.2f MB |\n", float64(results.Stats.MemoryUsed)/(1024*1024)))
		sb.WriteString("\n")
	}

	// Footer
	sb.WriteString("---\n\n")
	sb.WriteString("*Generated by Houndoom Security Scanner*\n")

	return os.WriteFile(outputFile, []byte(sb.String()), 0644)
}

// getSeverityEmoji returns emoji for severity level
func getSeverityEmoji(severity models.Severity) string {
	switch severity {
	case models.SeverityCritical:
		return "🔴"
	case models.SeverityHigh:
		return "🟠"
	case models.SeverityMedium:
		return "🟡"
	case models.SeverityLow:
		return "🟢"
	case models.SeverityInfo:
		return "🔵"
	default:
		return "⚪"
	}
}
