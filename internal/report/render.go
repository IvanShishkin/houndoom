package report

import (
	"encoding/json"
	"fmt"
	"os"
)

// RenderHTMLFromJSON reads a JSON scan report (as produced by --report=json)
// and writes a standalone HTML report to htmlPath. It is used to render an
// HTML view locally from a report collected by the agentless remote scan,
// without re-running the scan or touching the target.
func RenderHTMLFromJSON(jsonPath, htmlPath string) error {
	data, err := os.ReadFile(jsonPath)
	if err != nil {
		return fmt.Errorf("read json report: %w", err)
	}

	var rep JSONReport
	if err := json.Unmarshal(data, &rep); err != nil {
		return fmt.Errorf("parse json report: %w", err)
	}
	if rep.ScanResults == nil {
		return fmt.Errorf("json report has no scan results")
	}

	// generateHTML reads neither config nor logger, so a zero Generator is fine.
	g := &Generator{}
	if err := g.generateHTML(rep.ScanResults, rep.AIAnalysis, htmlPath); err != nil {
		return fmt.Errorf("render html: %w", err)
	}
	return nil
}
