package report

import (
	"fmt"
	"os"
	"strings"

	"github.com/IvanShishkin/houndoom/internal/ai"
	"github.com/IvanShishkin/houndoom/pkg/models"
)

// generateText generates a text report
func (g *Generator) generateText(results *models.ScanResults, aiReport *ai.AIReport, outputFile string) error {
	var sb strings.Builder

	// Header
	sb.WriteString("=" + strings.Repeat("=", 78) + "\n")
	sb.WriteString(fmt.Sprintf("  HOUNDOOM SECURITY SCANNER REPORT v%s\n", results.Version))
	sb.WriteString("=" + strings.Repeat("=", 78) + "\n\n")

	// Summary
	sb.WriteString("SUMMARY\n")
	sb.WriteString(strings.Repeat("-", 79) + "\n")
	sb.WriteString(fmt.Sprintf("Scan Path:        %s\n", results.ScanPath))
	sb.WriteString(fmt.Sprintf("Scan Mode:        %s\n", results.Mode))
	sb.WriteString(fmt.Sprintf("Start Time:       %s\n", results.StartTime.Format("2006-01-02 15:04:05")))
	sb.WriteString(fmt.Sprintf("End Time:         %s\n", results.EndTime.Format("2006-01-02 15:04:05")))
	sb.WriteString(fmt.Sprintf("Duration:         %s\n", FormatDuration(results.Duration)))
	sb.WriteString(fmt.Sprintf("Total Files:      %d\n", results.TotalFiles))
	sb.WriteString(fmt.Sprintf("Scanned Files:    %d\n", results.ScannedFiles))
	sb.WriteString(fmt.Sprintf("Skipped Files:    %d\n", results.SkippedFiles))
	sb.WriteString(fmt.Sprintf("THREATS FOUND:    %d\n", results.ThreatsFound))
	sb.WriteString("\n")

	// Statistics by severity
	if results.ThreatsFound > 0 {
		sb.WriteString("THREATS BY SEVERITY\n")
		sb.WriteString(strings.Repeat("-", 79) + "\n")

		for _, severity := range []models.Severity{
			models.SeverityCritical,
			models.SeverityHigh,
			models.SeverityMedium,
			models.SeverityLow,
			models.SeverityInfo,
		} {
			findings := results.FindingsBySeverity[severity]
			if len(findings) > 0 {
				sb.WriteString(fmt.Sprintf("  %-10s: %d\n", strings.ToUpper(string(severity)), len(findings)))
			}
		}
		sb.WriteString("\n")

		// Statistics by type
		sb.WriteString("THREATS BY TYPE\n")
		sb.WriteString(strings.Repeat("-", 79) + "\n")

		if results.Stats != nil {
			if results.Stats.PHPBackdoors > 0 {
				sb.WriteString(fmt.Sprintf("  PHP Backdoors:        %d\n", results.Stats.PHPBackdoors))
			}
			if results.Stats.JSViruses > 0 {
				sb.WriteString(fmt.Sprintf("  JS Viruses:           %d\n", results.Stats.JSViruses))
			}
			if results.Stats.PhishingPages > 0 {
				sb.WriteString(fmt.Sprintf("  Phishing Pages:       %d\n", results.Stats.PhishingPages))
			}
			if results.Stats.IframeInjections > 0 {
				sb.WriteString(fmt.Sprintf("  IFRAME Injections:    %d\n", results.Stats.IframeInjections))
			}
			if results.Stats.ObfuscatedFiles > 0 {
				sb.WriteString(fmt.Sprintf("  Obfuscated Files:     %d\n", results.Stats.ObfuscatedFiles))
			}
			if results.Stats.SuspiciousFiles > 0 {
				sb.WriteString(fmt.Sprintf("  Suspicious Files:     %d\n", results.Stats.SuspiciousFiles))
			}
		}
		sb.WriteString("\n")

		// Detailed findings
		sb.WriteString("DETAILED FINDINGS\n")
		sb.WriteString(strings.Repeat("=", 79) + "\n\n")

		for i, finding := range results.Findings {
			sb.WriteString(fmt.Sprintf("[%d] %s\n", i+1, finding.SignatureName))
			sb.WriteString(strings.Repeat("-", 79) + "\n")
			sb.WriteString(fmt.Sprintf("File:        %s\n", finding.File.Path))
			sb.WriteString(fmt.Sprintf("Line:        %d\n", finding.LineNumber))
			sb.WriteString(fmt.Sprintf("Severity:    %s\n", strings.ToUpper(string(finding.Severity))))
			sb.WriteString(fmt.Sprintf("Type:        %s\n", finding.Type))
			sb.WriteString(fmt.Sprintf("Confidence:  %d%%\n", finding.Confidence))
			sb.WriteString(fmt.Sprintf("Description: %s\n", finding.Description))
			sb.WriteString(fmt.Sprintf("Signature:   %s\n", finding.SignatureID))
			sb.WriteString(fmt.Sprintf("\nCode Fragment:\n%s\n", finding.Fragment))
			sb.WriteString("\n")
		}
	} else {
		sb.WriteString("No threats detected.\n\n")
	}

	// AI Analysis section
	if aiReport != nil && len(aiReport.Results) > 0 {
		sb.WriteString("AI ANALYSIS\n")
		sb.WriteString(strings.Repeat("=", 79) + "\n\n")

		// Summary
		sb.WriteString("Summary:\n")
		sb.WriteString(strings.Repeat("-", 79) + "\n")
		if aiReport.IsSmartMode {
			sb.WriteString(fmt.Sprintf("Mode:             Smart (%d unique signatures)\n", aiReport.UniqueSignatures))
		}
		sb.WriteString(fmt.Sprintf("Model:            %s\n", aiReport.Model))
		sb.WriteString(fmt.Sprintf("Findings Analyzed:%d\n", aiReport.AnalyzedCount))
		sb.WriteString(fmt.Sprintf("Malicious:        %d\n", aiReport.MaliciousCount))
		sb.WriteString(fmt.Sprintf("Suspicious:       %d\n", aiReport.SuspiciousCount))
		sb.WriteString(fmt.Sprintf("False Positives:  %d\n", aiReport.FalsePositiveCount))
		sb.WriteString(fmt.Sprintf("Benign:           %d\n", aiReport.BenignCount))
		sb.WriteString(fmt.Sprintf("Tokens Used:      %d\n", aiReport.TotalTokensUsed))
		sb.WriteString(fmt.Sprintf("Duration:         %s\n", FormatDuration(aiReport.Duration)))
		sb.WriteString("\n")

		// Detailed verdicts
		sb.WriteString("AI Verdicts:\n")
		sb.WriteString(strings.Repeat("-", 79) + "\n\n")

		for i, result := range aiReport.Results {
			sb.WriteString(fmt.Sprintf("[%d] %s (Confidence: %d%%)\n", i+1, strings.ToUpper(string(result.Verdict)), result.Confidence))
			sb.WriteString(strings.Repeat("-", 79) + "\n")
			sb.WriteString(fmt.Sprintf("Finding ID:   %s\n", result.FindingID))
			sb.WriteString(fmt.Sprintf("Risk Level:   %s\n", result.RiskLevel))
			sb.WriteString(fmt.Sprintf("Explanation:  %s\n", result.Explanation))
			if result.Remediation != "" {
				sb.WriteString(fmt.Sprintf("Remediation:  %s\n", result.Remediation))
			}
			if len(result.Indicators) > 0 {
				sb.WriteString(fmt.Sprintf("Indicators:   %s\n", strings.Join(result.Indicators, ", ")))
			}
			sb.WriteString("\n")
		}
	}

	// Performance stats
	if results.Stats != nil {
		sb.WriteString("PERFORMANCE\n")
		sb.WriteString(strings.Repeat("-", 79) + "\n")
		sb.WriteString(fmt.Sprintf("Files/Second:     %.2f\n", results.Stats.FilesPerSecond))
		sb.WriteString(fmt.Sprintf("Workers Used:     %d\n", results.Stats.WorkersUsed))
		sb.WriteString(fmt.Sprintf("Memory Used:      %.2f MB\n", float64(results.Stats.MemoryUsed)/(1024*1024)))
		sb.WriteString("\n")
	}

	// Footer
	sb.WriteString(strings.Repeat("=", 79) + "\n")
	sb.WriteString("End of Report\n")
	sb.WriteString(strings.Repeat("=", 79) + "\n")

	// Write to file
	return os.WriteFile(outputFile, []byte(sb.String()), 0644)
}
