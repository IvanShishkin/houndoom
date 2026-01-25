package report

import (
	"encoding/json"
	"os"

	"github.com/IvanShishkin/houndoom/internal/ai"
	"github.com/IvanShishkin/houndoom/pkg/models"
)

// JSONReport combines scan results with AI analysis for JSON output
type JSONReport struct {
	*models.ScanResults
	AIAnalysis *ai.AIReport `json:"ai_analysis,omitempty"`
}

// generateJSON generates a JSON report
func (g *Generator) generateJSON(results *models.ScanResults, aiReport *ai.AIReport, outputFile string) error {
	// Create combined report
	report := &JSONReport{
		ScanResults: results,
		AIAnalysis:  aiReport,
	}

	// Convert results to JSON
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}

	// Write to file
	return os.WriteFile(outputFile, data, 0644)
}
