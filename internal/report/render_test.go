package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/IvanShishkin/houndoom/pkg/models"
)

// sampleResults builds a minimal but realistic ScanResults for rendering tests.
func sampleResults() *models.ScanResults {
	return &models.ScanResults{
		StartTime:    time.Unix(1700000000, 0),
		EndTime:      time.Unix(1700000060, 0),
		Duration:     60 * time.Second,
		ScanPath:     "/var/www/html",
		ScannedFiles: 1234,
		ThreatsFound: 1,
		Mode:         "normal",
		Version:      "test",
		Stats:        &models.ScanStatistics{},
		Findings: []*models.Finding{
			{
				SignatureID:   "php-eval-backdoor",
				SignatureName: "PHP eval() backdoor",
				Type:          models.ThreatType("php_backdoor"),
				Severity:      models.SeverityCritical,
				Description:   "Suspicious eval of request input",
				Fragment:      "eval($_POST['x']);",
				LineNumber:    42,
				Confidence:    95,
				File:          &models.File{Path: "/var/www/html/shell.php"},
			},
		},
	}
}

// writeJSONReport renders a ScanResults to a JSON report file using the real
// JSON generator, so the test exercises the same on-disk shape remote-scan
// downloads from the target.
func writeJSONReport(t *testing.T, results *models.ScanResults) string {
	t.Helper()
	jsonPath := filepath.Join(t.TempDir(), "report.json")
	g := &Generator{}
	if err := g.generateJSON(results, nil, jsonPath); err != nil {
		t.Fatalf("generateJSON: %v", err)
	}
	return jsonPath
}

func TestRenderHTMLFromJSON(t *testing.T) {
	jsonPath := writeJSONReport(t, sampleResults())
	htmlPath := filepath.Join(t.TempDir(), "report.html")

	if err := RenderHTMLFromJSON(jsonPath, htmlPath); err != nil {
		t.Fatalf("RenderHTMLFromJSON: %v", err)
	}

	data, err := os.ReadFile(htmlPath)
	if err != nil {
		t.Fatalf("read html: %v", err)
	}
	html := string(data)

	if !strings.Contains(html, "<!DOCTYPE html>") {
		t.Error("output is not an HTML document")
	}
	for _, want := range []string{"/var/www/html", "PHP eval() backdoor", "shell.php"} {
		if !strings.Contains(html, want) {
			t.Errorf("HTML report missing %q", want)
		}
	}
}

func TestRenderHTMLFromJSON_BadInput(t *testing.T) {
	t.Run("missing file", func(t *testing.T) {
		err := RenderHTMLFromJSON(filepath.Join(t.TempDir(), "nope.json"), filepath.Join(t.TempDir(), "out.html"))
		if err == nil {
			t.Fatal("expected error for missing input")
		}
	})

	t.Run("invalid json", func(t *testing.T) {
		bad := filepath.Join(t.TempDir(), "bad.json")
		if err := os.WriteFile(bad, []byte("{not json"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := RenderHTMLFromJSON(bad, filepath.Join(t.TempDir(), "out.html")); err == nil {
			t.Fatal("expected error for invalid json")
		}
	})
}
