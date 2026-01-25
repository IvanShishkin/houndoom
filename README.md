# Houndoom - Advanced Security Scanner

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?logo=go)](https://golang.org/dl/)

Houndoom is a high-performance security scanner written in Go for detecting malicious code, vulnerabilities, web shells, and threats in web applications. It combines signature-based detection with advanced heuristic analysis and optional AI-powered threat assessment.

## Key Features

- **High Performance:** Multi-threaded scanning with goroutine worker pools
- **Extensible Architecture:** Plugin-based detector system
- **Multiple Scan Modes:** Fast, Normal, and Paranoid
- **AI-Powered Analysis:** Claude API integration for deep threat assessment
- **Advanced Deobfuscation:** 8 deobfuscators with recursive processing (up to 100 levels)
- **Heuristic Analysis:** Entropy analysis, data flow tracking, pattern detection
- **CMS-Specific Detection:** Specialized checks for Bitrix, WordPress, and other CMS
- **Multiple Report Formats:** HTML, JSON, Markdown, Text, XML

## HTML Report

Houndoom generates interactive HTML reports with sortable tables, filtering, code highlighting, and statistics dashboard. [View Live Example](http://shishkin.tech/houndoom_example.html)

![HTML Report Screenshot](docs/images/html_report.png)



## Quick Start

### Installation

**Quick Install (Linux/macOS):**

```bash
# Using curl
curl -sSL https://raw.githubusercontent.com/IvanShishkin/houndoom/main/install.sh | bash

# Using wget
wget -qO- https://raw.githubusercontent.com/IvanShishkin/houndoom/main/install.sh | bash
```

**Installation Options:**

```bash
# Install specific version
curl -sSL .../install.sh | bash -s -- --version=v1.0.0

# Install without sudo (to ~/.local/bin)
curl -sSL .../install.sh | bash -s -- --no-sudo

# Install to custom directory
curl -sSL .../install.sh | bash -s -- --dir=/opt/bin
```

**Manual Installation:**

Download the binary for your platform from [GitHub Releases](https://github.com/IvanShishkin/houndoom/releases).

**Build from Source:**

```bash
# Clone the repository
git clone https://github.com/IvanShishkin/houndoom.git
cd houndoom

# Build the scanner
go build -o bin/houndoom ./cmd/scanner

# Or build for Linux production
GOOS=linux GOARCH=amd64 go build -o bin/houndoom ./cmd/scanner
```

### Basic Usage

```bash
# Scan a directory
houndoom scan /path/to/website

# Scan with AI analysis
houndoom scan /path/to/website --ai

# Paranoid mode with smart AI analysis
houndoom scan /path/to/website --mode=paranoid --ai --ai-smart

# Generate JSON report
houndoom scan /path/to/website --report=json --output=report.json

# Deobfuscate a file
houndoom deob suspicious_file.php

# List available detectors
houndoom detectors list
```


## AI-Powered Analysis

Houndoom integrates with Claude API for intelligent threat assessment:

```bash
# Enable AI analysis
houndoom scan /path --ai --ai-token=YOUR_API_KEY

# Smart mode: deduplication + sampling (cost-effective)
houndoom scan /path --ai-smart

# Choose model: haiku (fast), sonnet (balanced), opus (best)
houndoom scan /path --ai --ai-model=sonnet
```

**AI Features:**
- Deep threat classification with confidence levels
- Remediation suggestions
- False positive detection
- Support for English, Russian, Spanish, German, Chinese

## CLI Reference

### Scan Command

```bash
houndoom scan [path] [flags]

# Mode & Performance
  --mode string          fast|normal|paranoid (default "normal")
  --workers int          Worker threads (default: CPU cores × 2)
  --max-size string      Max file size (default "650K")

# Filtering
  --extensions strings   Extensions to scan
  --exclude strings      Directories to exclude
  --detectors strings    Enable specific detectors
  --disable strings      Disable specific detectors
  --experimental         Enable experimental detectors
  --cms string           Force CMS: bitrix|wordpress|laravel|symfony|drupal|joomla

# Reports
  -r, --report string    html|json|txt|xml|md
  -o, --output string    Output file path
  --no-html              Disable HTML report

# AI Analysis
  --ai                   Enable AI analysis
  --ai-smart             Smart mode (dedupe + sampling)
  --ai-model string      haiku|sonnet|opus (default "sonnet")
  --ai-token string      Anthropic API token
  --ai-lang string       en|ru|es|de|zh (default "en")
```

### Other Commands

```bash
# Deobfuscate file
houndoom deob <file>

# List detectors
houndoom detectors list

```

## Detected Threats

### PHP
- Web shells (r57, c99, b374k, WSO, FilesMan)
- Backdoors with eval/base64/gzinflate
- Code injection (eval, assert, create_function)
- Command execution (system, exec, shell_exec, passthru, popen)
- File operations with user input
- preg_replace with /e modifier
- Dangerous CMS methods

### JavaScript
- XSS injections (event handlers, DOM-based)
- IFRAME injections
- Obfuscated code (fromCharCode, eval)
- Malicious redirects
- Cookie stealing

### Other
- Phishing pages
- Adware and SEO spam
- Doorway pages
- Unix executables in web directories

## Architecture

```
houndoom/
├── cmd/scanner/           # CLI entry point (Cobra)
├── internal/
│   ├── config/            # Viper-based configuration
│   ├── core/scanner.go    # Main orchestrator, worker pool
│   ├── filesystem/        # File walker (Windows/Unix)
│   ├── detectors/         # Threat detectors
│   │   ├── php/           # PHP backdoors, injection
│   │   ├── javascript/    # XSS, malicious JS
│   │   └── cms/bitrix/    # CMS-specific detection
│   ├── deobfuscator/      # 8 deobfuscators
│   ├── heuristic/         # Heuristic analysis
│   ├── signatures/        # Pattern matching
│   ├── ai/                # Claude API integration
│   └── report/            # Report generators
├── pkg/models/            # Data models, scoring
└── configs/signatures/    # YAML signature databases
```

## Development

```bash
# Run tests
go test ./...
go test -v -race ./...

# Linting
make lint
make fmt
make vet

# Build all platforms
make build-all
```

### Adding a Detector

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

1. Implement interface in `internal/detectors/`
2. Register in `core/scanner.go:initDetectors()`
3. Add signatures to `configs/signatures/`

## Requirements

- Go 1.21+
- Linux, Windows, macOS

## License

MIT License - see [LICENSE](LICENSE)

## Disclaimer

This scanner is provided for security research and website protection purposes only.
Always perform manual verification of detected threats.
