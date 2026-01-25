# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Houndoom is a high-performance security scanner written in Go for detecting malicious code, vulnerabilities, and threats in web applications.

## Build & Run Commands

```bash
# Build (Linux binary for production)
GOOS=linux GOARCH=amd64 go build -o bin/houndoom ./cmd/scanner

# Test
go test ./...           # Run all tests
go test -v -race ./...  # Verbose with race detection
make test               # Tests with coverage
make test-coverage      # Generate HTML coverage report

# Lint & Format
make lint               # Run golangci-lint
make fmt                # Format code
make vet                # Run go vet


# Run scanner
./bin/houndoom scan /path --mode=fast|normal|paranoid
./bin/houndoom scan /path --report=json --output=report.json
./bin/houndoom detectors list
```

## Architecture

```
cmd/scanner/main.go          # CLI entry point (Cobra)
internal/
├── config/                  # Viper-based configuration
├── core/scanner.go          # Main orchestrator, worker pool
├── filesystem/              # File walker, platform-specific code
├── detectors/               # Threat detectors (plugin architecture)
│   ├── php/                 # PHP backdoors, injection
│   ├── javascript/          # XSS, malicious JS
│   ├── cms/bitrix/          # CMS-specific detection
│   └── detector.go          # Base Detector interface
├── deobfuscator/            # Code deobfuscation (7+ types)
├── heuristic/               # Heuristic analysis
└── report/                  # Report generators (HTML, JSON, text, XML)
pkg/models/
├── finding.go               # Threat finding struct
├── result.go                # Scan results aggregation
└── scoring.go               # Risk scoring system
configs/signatures/          # YAML signature databases
```

## Key Patterns

**Detector Interface** - All detectors implement:
```go
type Detector interface {
    Name() string
    Priority() int
    SupportedExtensions() []string
    Detect(ctx context.Context, file *models.File) ([]*models.Finding, error)
    IsEnabled() bool
    SetEnabled(enabled bool)
}
```

**Configuration Priority:** CLI flags > Environment variables > Defaults

**Scan Modes:**
- `fast` - Critical files only (.php, .js, .html, .htaccess)
- `normal` - Standard extensions, heuristics enabled
- `paranoid` - All files, deep deobfuscation

## Adding a Detector

1. Implement `Detector` interface in `internal/detectors/`
2. Register in `core/scanner.go:initDetectors()`
3. Create signature file in `configs/signatures/`

## Code Style

- All code comments, documentation, and commit messages must be in English
- Variable and function names in English

## Output Directories

- `.reports/` - Scanner reports (HOUNDOOM-REPORT-*.html/json/txt)
- `.claude/artifacts/` - Claude-generated files (documentation, summaries, analysis reports)

**Important:** When creating documentation, summaries, or any descriptive files during work, save them to `.claude/artifacts/` directory. This keeps the project root clean and these files are gitignored.
