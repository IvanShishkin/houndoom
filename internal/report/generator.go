package report

import (
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/IvanShishkin/houndoom/internal/ai"
	"github.com/IvanShishkin/houndoom/internal/config"
	"github.com/IvanShishkin/houndoom/pkg/models"
	"go.uber.org/zap"
)

// ANSI color codes
const (
	colorReset   = "\033[0m"
	colorBold    = "\033[1m"
	colorDim     = "\033[2m"
	colorRed     = "\033[31m"
	colorGreen   = "\033[32m"
	colorYellow  = "\033[33m"
	colorBlue    = "\033[34m"
	colorMagenta = "\033[35m"
	colorCyan    = "\033[36m"
	colorWhite   = "\033[37m"
	colorOrange  = "\033[38;5;208m"
	colorGray    = "\033[38;5;245m"
)

// isColorSupported checks if terminal supports colors
func isColorSupported() bool {
	// Windows cmd doesn't support colors by default, but modern terminals do
	return runtime.GOOS != "windows" || true // Enable for all, modern Windows supports ANSI
}

// FormatDuration formats duration to a human-readable string with max 2 decimal places
func FormatDuration(d time.Duration) string {
	if d < time.Second {
		// Milliseconds
		return fmt.Sprintf("%.2fms", float64(d.Nanoseconds())/1e6)
	} else if d < time.Minute {
		// Seconds
		return fmt.Sprintf("%.2fs", d.Seconds())
	} else if d < time.Hour {
		// Minutes and seconds
		mins := int(d.Minutes())
		secs := d.Seconds() - float64(mins*60)
		return fmt.Sprintf("%dm%.2fs", mins, secs)
	}
	// Hours, minutes and seconds
	hours := int(d.Hours())
	mins := int(d.Minutes()) - hours*60
	secs := d.Seconds() - float64(hours*3600) - float64(mins*60)
	return fmt.Sprintf("%dh%dm%.2fs", hours, mins, secs)
}

// Generator generates scan reports in various formats
type Generator struct {
	config *config.Config
	logger *zap.Logger
}

// NewGenerator creates a new report generator
func NewGenerator(cfg *config.Config, logger *zap.Logger) (*Generator, error) {
	return &Generator{
		config: cfg,
		logger: logger,
	}, nil
}

// Generate generates a report based on scan results
func (g *Generator) Generate(results *models.ScanResults, aiReport *ai.AIReport) (string, error) {
	format := g.config.ReportFormat
	outputFile := g.config.OutputFile

	// If no format specified, print to console
	if format == "" {
		g.printConsole(results, aiReport)
		return "", nil
	}

	// Generate default filename if not specified
	if outputFile == "" {
		timestamp := time.Now().Format("20060102-150405")
		switch format {
		case "json":
			outputFile = fmt.Sprintf("HOUNDOOM-REPORT-%s.json", timestamp)
		case "txt", "text":
			outputFile = fmt.Sprintf("HOUNDOOM-REPORT-%s.txt", timestamp)
		case "xml":
			outputFile = fmt.Sprintf("HOUNDOOM-REPORT-%s.xml", timestamp)
		case "html":
			outputFile = fmt.Sprintf("HOUNDOOM-REPORT-%s.html", timestamp)
		case "md", "markdown":
			outputFile = fmt.Sprintf("HOUNDOOM-REPORT-%s.md", timestamp)
		default:
			return "", fmt.Errorf("unknown report format: %s", format)
		}
	}

	g.logger.Info("Generating report",
		zap.String("format", format),
		zap.String("output", outputFile))

	var err error
	switch format {
	case "json":
		err = g.generateJSON(results, aiReport, outputFile)
	case "txt", "text":
		err = g.generateText(results, aiReport, outputFile)
	case "xml":
		err = g.generateXML(results, aiReport, outputFile)
	case "html":
		err = g.generateHTML(results, aiReport, outputFile)
	case "md", "markdown":
		err = g.generateMarkdown(results, aiReport, outputFile)
	}

	if err != nil {
		return "", fmt.Errorf("failed to generate %s report: %w", format, err)
	}

	// Get absolute path
	absPath, _ := filepath.Abs(outputFile)
	return absPath, nil
}

// printConsole prints results to stdout with colors
func (g *Generator) printConsole(results *models.ScanResults, aiReport *ai.AIReport) {
	fmt.Println()

	// Summary header
	fmt.Printf("%s%sSCAN COMPLETE%s\n", colorBold, colorOrange, colorReset)
	fmt.Println()

	// Stats
	fmt.Printf("  %sPath:%s      %s\n", colorGray, colorReset, results.ScanPath)
	fmt.Printf("  %sMode:%s      %s\n", colorGray, colorReset, results.Mode)
	fmt.Printf("  %sFiles:%s     %d\n", colorGray, colorReset, results.ScannedFiles)
	fmt.Printf("  %sDuration:%s  %s\n", colorGray, colorReset, FormatDuration(results.Duration))
	fmt.Println()

	if results.ThreatsFound == 0 {
		fmt.Printf("  %s%s✓ No threats detected%s\n", colorBold, colorGreen, colorReset)
		fmt.Println()
		return
	}

	// Threats found
	fmt.Printf("  %s%s⚠ THREATS FOUND: %d%s\n", colorBold, colorRed, results.ThreatsFound, colorReset)
	fmt.Println()
	fmt.Printf("%s───────────────────────────────────────────────────────────────%s\n", colorGray, colorReset)

	// Build AI results map for quick lookup
	aiResultsMap := make(map[string]*ai.AnalysisResponse)
	if aiReport != nil {
		for _, result := range aiReport.Results {
			aiResultsMap[result.FindingID] = result
		}
	}

	for i, finding := range results.Findings {
		findingID := fmt.Sprintf("finding-%d", i)
		severityColor := getSeverityColor(finding.Severity)
		severityLabel := strings.ToUpper(string(finding.Severity))

		fmt.Printf("\n  %s%s[%d]%s %s%s%s\n", colorBold, colorWhite, i+1, colorReset, colorBold, finding.SignatureName, colorReset)
		fmt.Printf("      %sSeverity:%s  %s%s%s\n", colorGray, colorReset, severityColor, severityLabel, colorReset)
		fmt.Printf("      %sFile:%s      %s%s%s:%s%d%s\n", colorGray, colorReset, colorOrange, finding.File.Path, colorReset, colorRed, finding.LineNumber, colorReset)
		fmt.Printf("      %sType:%s      %s\n", colorGray, colorReset, finding.Type)

		if finding.Fragment != "" {
			// Clean and truncate fragment
			fragment := cleanFragment(finding.Fragment, 120)
			fmt.Printf("      %sCode:%s      %s%s%s\n", colorGray, colorReset, colorDim, fragment, colorReset)
		}

		// Show AI verdict if available
		if aiResult, ok := aiResultsMap[findingID]; ok {
			verdictColor := getVerdictColor(aiResult.Verdict)
			fmt.Printf("      %sAI:%s        %s%s%s (%d%% confidence)\n",
				colorGray, colorReset, verdictColor, strings.ToUpper(string(aiResult.Verdict)), colorReset, aiResult.Confidence)
			if aiResult.Explanation != "" {
				explanation := cleanFragment(aiResult.Explanation, 100)
				fmt.Printf("      %sReason:%s    %s%s%s\n", colorGray, colorReset, colorDim, explanation, colorReset)
			}
		}
	}

	fmt.Println()
	fmt.Printf("%s───────────────────────────────────────────────────────────────%s\n", colorGray, colorReset)

	// AI Summary
	if aiReport != nil && len(aiReport.Results) > 0 {
		fmt.Println()
		fmt.Printf("%s%sAI ANALYSIS SUMMARY%s\n", colorBold, colorMagenta, colorReset)
		fmt.Println()
		fmt.Printf("  %sModel:%s       %s\n", colorGray, colorReset, aiReport.Model)
		fmt.Printf("  %sAnalyzed:%s    %d findings\n", colorGray, colorReset, aiReport.AnalyzedCount)
		fmt.Printf("  %sMalicious:%s   %s%d%s\n", colorGray, colorReset, colorRed, aiReport.MaliciousCount, colorReset)
		fmt.Printf("  %sSuspicious:%s  %s%d%s\n", colorGray, colorReset, colorOrange, aiReport.SuspiciousCount, colorReset)
		fmt.Printf("  %sFalse Pos:%s   %s%d%s\n", colorGray, colorReset, colorGreen, aiReport.FalsePositiveCount, colorReset)
		fmt.Printf("  %sTokens:%s      %d\n", colorGray, colorReset, aiReport.TotalTokensUsed)
		fmt.Println()
		fmt.Printf("%s───────────────────────────────────────────────────────────────%s\n", colorGray, colorReset)
	}

	fmt.Println()
}

// getVerdictColor returns ANSI color for AI verdict
func getVerdictColor(verdict ai.Verdict) string {
	switch verdict {
	case ai.VerdictMalicious:
		return colorRed + colorBold
	case ai.VerdictSuspicious:
		return colorOrange
	case ai.VerdictFalsePositive:
		return colorGreen
	case ai.VerdictBenign:
		return colorGreen
	default:
		return colorYellow
	}
}

// getSeverityColor returns ANSI color for severity level
func getSeverityColor(severity models.Severity) string {
	switch severity {
	case models.SeverityCritical:
		return colorRed + colorBold
	case models.SeverityHigh:
		return colorOrange
	case models.SeverityMedium:
		return colorYellow
	case models.SeverityLow:
		return colorGreen
	case models.SeverityInfo:
		return colorBlue
	default:
		return colorWhite
	}
}

// cleanFragment cleans and truncates code fragment for console output
func cleanFragment(fragment string, maxLen int) string {
	// Replace newlines and tabs with spaces
	fragment = strings.ReplaceAll(fragment, "\n", " ")
	fragment = strings.ReplaceAll(fragment, "\r", "")
	fragment = strings.ReplaceAll(fragment, "\t", " ")

	// Collapse multiple spaces
	for strings.Contains(fragment, "  ") {
		fragment = strings.ReplaceAll(fragment, "  ", " ")
	}

	fragment = strings.TrimSpace(fragment)

	if len(fragment) > maxLen {
		fragment = fragment[:maxLen] + "..."
	}

	return fragment
}

// generateXML generates an XML report (stub)
func (g *Generator) generateXML(results *models.ScanResults, aiReport *ai.AIReport, outputFile string) error {
	// TODO: Implement XML report generation with AI analysis support
	g.logger.Info("XML report generation not yet implemented")
	return nil
}
