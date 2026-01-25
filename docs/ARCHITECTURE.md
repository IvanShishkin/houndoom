# Houndoom Architecture

## Overview

Houndoom is designed as a modular, extensible security scanner with a clear separation of concerns. The architecture follows Go best practices and emphasizes performance, maintainability, and extensibility.

## Core Components

### 1. CLI Layer (`cmd/scanner/`)

**Responsibility:** Command-line interface and user interaction

- Uses Cobra for command parsing
- Handles all CLI commands: `scan`, `whitelist`, `update`, `detectors`
- Validates user input and flags
- Initializes logging
- Coordinates high-level workflow

**Key Files:**
- `main.go` - Entry point and command definitions

### 2. Configuration (`internal/config/`)

**Responsibility:** Configuration management and validation

- Loads configuration from multiple sources (file, env vars, CLI flags)
- Priority: CLI > Environment > File > Defaults
- Uses Viper for configuration management
- Provides typed access to configuration values
- Manages scan modes (Fast, Normal, Paranoid)

**Key Files:**
- `config.go` - Configuration struct and loader

### 3. Core Scanner (`internal/core/`)

**Responsibility:** Main scanning orchestration and coordination

**Components:**
- **Scanner:** Main coordinator
  - Manages worker pool (goroutines)
  - Distributes files to workers
  - Collects and aggregates results
  - Calculates statistics
  - Generates final report

**Key Files:**
- `scanner.go` - Main scanner implementation
- `worker.go` - Worker pool implementation
- `queue.go` - File queue management

**Workflow:**
```
Scanner.Scan()
    ↓
Initialize detectors
    ↓
Walk filesystem → Queue files
    ↓
Worker Pool (N goroutines)
    ↓
For each file:
    → Load content
    → Run detectors
    → Collect findings
    ↓
Aggregate results
    ↓
Generate statistics
    ↓
Create report
```

### 4. Filesystem Module (`internal/filesystem/`)

**Responsibility:** File system operations and traversal

**Components:**
- **Walker:** Recursive directory traversal
  - Respects exclude patterns
  - Handles symlinks
  - Detects hidden files
  - Filters by extension

- **Reader:** File reading and hashing
  - Reads file content
  - Calculates CRC32/SHA1 hashes
  - Handles encoding detection

**Key Files:**
- `walker.go` - Directory walker
- `reader.go` - File reader and utilities
- `platform_windows.go` - Windows-specific code
- `platform_unix.go` - Unix-specific code

### 5. Detectors (`internal/detectors/`)

**Responsibility:** Threat detection and analysis

**Interface:**
```go
type Detector interface {
    Name() string
    Priority() int
    SupportedExtensions() []string
    Detect(ctx context.Context, file *File) ([]*Finding, error)
    IsEnabled() bool
    SetEnabled(enabled bool)
}
```

**Detector Types:**

1. **PHP Detector** (`detectors/php/`)
   - Critical PHP threats (backdoors, shells)
   - Code injection detection
   - File operation analysis
   - Command execution detection

2. **JavaScript Detector** (`detectors/javascript/`)
   - XSS injection detection
   - IFRAME injection detection
   - Obfuscated JS analysis
   - Malicious redirects

3. **Phishing Detector** (`detectors/phishing/`)
   - Fake login pages
   - Form analysis
   - Brand impersonation

4. **Adware Detector** (`detectors/adware/`)
   - Hidden links (CSS: display:none)
   - Black-SEO patterns
   - Spam links

5. **Doorway Detector** (`detectors/doorway/`)
   - Auto-generated pages
   - SEO spam patterns

6. **Executable Detector** (`detectors/executable/`)
   - Unix binaries (.so, .o)
   - Shell scripts
   - Python scripts

**Key Files:**
- `detector.go` - Base detector interface
- `php/critical.go` - PHP critical threats
- `php/backdoor.go` - PHP backdoor detection
- `javascript/malicious.go` - Malicious JS
- etc.

### 6. Signature Matching (`internal/signatures/`)

**Responsibility:** Pattern matching and signature database management

**Components:**
- **Signature Database:** Structured threat signatures
  - String-based signatures (fast strpos)
  - Regex-based signatures (flexible matching)
  - Hierarchical levels (basic, expert, paranoid)

- **Matcher:** Signature matching engine
  - Optimized pattern matching
  - Exception handling
  - Confidence scoring

**Database Structure:**
```
Signatures
├── Level 0: Basic string signatures
├── Level 1: Expert string signatures
├── Level 2: Basic regex signatures
├── Level 3: Expert regex signatures
├── Level 4: Paranoid regex signatures
└── Exceptions: False positive filters
```

**Key Files:**
- `loader.go` - Signature database loader
- `matcher.go` - Pattern matching engine
- `database.go` - Signature storage
- `patterns/php.go` - PHP patterns
- `patterns/js.go` - JavaScript patterns

### 7. Deobfuscators (`internal/deobfuscator/`)

**Responsibility:** Code deobfuscation and unpacking

**Supported Types:**

1. **Base64** - Simple base64 decoding
2. **Eval** - Eval unwrapping (recursive)
3. **LocKit** - LocKit packer
4. **ALS** - ALS Fullsite packer
5. **ByteRun** - ByteRun obfuscation
6. **FOPO** - FOPO packer
7. **URLDecode** - URL-encoded payloads
8. **Globals** - $GLOBALS obfuscation

**Interface:**
```go
type Deobfuscator interface {
    Name() string
    CanDeobfuscate(content string) bool
    Deobfuscate(content string) (string, error)
}
```

**Key Files:**
- `deobfuscator.go` - Base interface
- `php/base64.go` - Base64 deobfuscator
- `php/eval.go` - Eval unwrapper
- `php/lockit.go` - LocKit deobfuscator
- `php/als.go` - ALS deobfuscator
- `php/urldecode.go` - URL decoder
- `php/globals.go` - GLOBALS decoder

### 8. Heuristic Analysis (`internal/heuristics/`)

**Responsibility:** Behavioral analysis and scoring

**Components:**
- **Analyzer:** Heuristic analysis engine
  - Suspicious pattern detection
  - Behavioral scoring
  - Anomaly detection

**Heuristic Rules:**

**PHP:**
- Suspicious function calls
- Obfuscated variables
- String fragmentation
- Indirect calls
- Dynamic function creation

**JavaScript:**
- Obfuscated code patterns
- Hidden IFrames
- Suspicious redirects
- Cookie manipulation

**Scoring System:**
```
0-30:   Safe
31-60:  Suspicious
61-90:  Dangerous
91+:    Critical
```

**Key Files:**
- `analyzer.go` - Main analyzer
- `php_heuristics.go` - PHP heuristics
- `js_heuristics.go` - JS heuristics

**Advanced Heuristics (`internal/heuristic/`):**
- `detector.go` - Advanced heuristic detector
- `context.go` - Context-aware analysis
- `dataflow.go` - Data flow analysis
- `variables.go` - Variable tracking
- `combinations.go` - Pattern combinations
- `entropy.go` - Entropy analysis for obfuscation detection

### 9. AI Analysis (`internal/ai/`)

**Responsibility:** AI-powered threat assessment using Claude API

**Components:**

- **Client:** HTTP client for Anthropic API
  - Model selection (Haiku, Sonnet, Opus)
  - Token management
  - Rate limiting and retries
  - Timeout handling

- **Analyzer:** Main analysis orchestrator
  - Standard mode: analyze all findings
  - Smart mode: dedupe + sampling by signature
  - Quick filter: Haiku pre-filtering
  - Progress callbacks

- **Models:** Data structures for AI interaction
  - AnalysisRequest/Response
  - Verdicts (malicious, suspicious, false_positive, benign)
  - Cost estimation

**Interface:**
```go
type Analyzer struct {
    client *Client
    config *config.AIConfig
}

func (a *Analyzer) AnalyzeFindings(ctx context.Context, results *ScanResults) (*AIReport, error)
```

**Verdicts:**
```
malicious      → Confirmed threat
suspicious     → Needs manual review
false_positive → Safe, signature triggered incorrectly
benign         → Safe code
unknown        → Could not determine
```

**Models:**
- `haiku` - Fast, cheap, for quick filtering
- `sonnet` - Balanced (default)
- `opus` - Most accurate, expensive

**Smart Mode:**
1. Deduplicate by signature ID
2. Sample N findings per unique signature
3. Apply Haiku pre-filter (optional)
4. Deep analysis with selected model
5. Apply results to all similar findings

**Key Files:**
- `analyzer.go` - Main analyzer
- `client.go` - API client
- `models.go` - Data structures
- `prompts.go` - Prompt templates

### 10. CMS Checkers (`internal/detectors/cms/`)

**Responsibility:** CMS detection and vulnerability checking

**Supported CMS:**
- WordPress
- Joomla
- Drupal
- Bitrix (with specialized dangerous method detection)
- vBulletin
- phpBB
- MODX

**Key Files:**
- `detector.go` - CMS detection
- `bitrix/detector.go` - Bitrix-specific detectors

### 11. Whitelist System (`internal/whitelist/`)

**Responsibility:** Known-good file database management

**Database Format:**
```
Header: 1024 bytes (256 x uint32 chunk sizes)
Data:   Binary hash chunks (20 bytes each)
Index:  First byte of hash determines chunk (0-255)
```

**Components:**
- **Manager:** Whitelist operations
  - Generate whitelist from clean files
  - Check files against whitelist
  - Update whitelist database

- **Database:** Binary file format
  - Fast binary search (O(log n))
  - Indexed by hash prefix
  - SHA1 hashes (20 bytes)

**Key Files:**
- `manager.go` - Whitelist manager
- `database.go` - Binary database format
- `generator.go` - Database generator

### 12. Report Generation (`internal/report/`)

**Responsibility:** Multi-format report generation

**Supported Formats:**

1. **HTML Report**
   - Interactive tables
   - Sortable columns
   - Filterable results
   - Code highlighting
   - Statistics dashboard
   - AI analysis results

2. **JSON Report**
   - Machine-readable
   - Full detail
   - API-friendly
   - Automation support

3. **Markdown Report**
   - GitHub-friendly
   - Easy to read
   - Good for documentation

4. **Text Report**
   - Console-friendly
   - Human-readable
   - Grep-able

**Key Files:**
- `generator.go` - Report generator
- `html.go` - HTML report
- `json.go` - JSON report
- `markdown.go` - Markdown report
- `text.go` - Text report

## Data Models (`pkg/models/`)

### Core Models:

1. **File**
   - Path, name, extension
   - Size, timestamps
   - Content, hash
   - Metadata (symlink, hidden)

2. **Finding**
   - Threat type and severity
   - Signature information
   - Position and line number
   - Code snippet
   - Confidence level

3. **ScanResults**
   - Summary statistics
   - Findings by type/severity
   - Performance metrics
   - Report path

## Utilities (`pkg/utils/`)

**Common utilities:**
- `hash.go` - Hashing functions
- `encoding.go` - Encoding/decoding
- `regex.go` - Regex utilities

## Data Flow

```
User Input (CLI)
    ↓
Configuration Loading
    ↓
Scanner Initialization
    ↓
Filesystem Walking
    ↓
Worker Pool
    ├→ Worker 1 → Read File → Run Detectors → Collect Results
    ├→ Worker 2 → Read File → Run Detectors → Collect Results
    ├→ Worker 3 → Read File → Run Detectors → Collect Results
    └→ Worker N → Read File → Run Detectors → Collect Results
    ↓
Results Aggregation
    ↓
[Optional] AI Analysis
    ├→ Smart Mode: Dedupe → Sample → Filter → Analyze
    └→ Standard Mode: Analyze all findings
    ↓
Statistics Calculation
    ↓
Report Generation
    ↓
Output (HTML/JSON/Markdown/Text)
```

## Concurrency Model

### Worker Pool Pattern

```go
// Channels
fileChan := make(chan *FileInfo, workers*2)  // File queue
resultsChan := make(chan *ScanResult, workers*2)  // Results queue

// Workers
for i := 0; i < workers; i++ {
    go worker(fileChan, resultsChan)
}

// Results collector
go collectResults(resultsChan)

// Producer
walkFilesystem(fileChan)
```

**Benefits:**
- Bounded concurrency (prevents resource exhaustion)
- Buffered channels (reduces blocking)
- Graceful cancellation (context.Context)
- Resource cleanup (defer, sync.WaitGroup)

## Performance Optimizations

1. **Parallel Processing**
   - Worker pool (N goroutines)
   - Non-blocking I/O
   - Concurrent detectors

2. **Efficient Matching**
   - Fast string search (strpos) before regex
   - Compiled regex (precompiled patterns)
   - Short-circuit evaluation

3. **Memory Management**
   - Streaming file reading
   - Bounded bufferschannel buffers
   - File size limits

4. **Caching**
   - Signature cache
   - Whitelist cache
   - Regex compilation cache

## Extensibility Points

### 1. Custom Detectors

Implement the `Detector` interface:
```go
type MyDetector struct {
    *BaseDetector
}

func (d *MyDetector) Detect(ctx context.Context, file *File) ([]*Finding, error) {
    // Detection logic
}
```

### 2. Custom Deobfuscators

Implement the `Deobfuscator` interface:
```go
type MyDeobfuscator struct{}

func (d *MyDeobfuscator) CanDeobfuscate(content string) bool {
    // Check if can deobfuscate
}

func (d *MyDeobfuscator) Deobfuscate(content string) (string, error) {
    // Deobfuscation logic
}
```

### 3. Custom Report Formats

Implement the `Reporter` interface:
```go
type MyReporter struct{}

func (r *MyReporter) Generate(results *ScanResults) (string, error) {
    // Report generation logic
}
```

## Testing Strategy

1. **Unit Tests**
   - Test individual components
   - Mock dependencies
   - Table-driven tests

2. **Integration Tests**
   - End-to-end scanning
   - Real malware samples
   - Performance benchmarks

3. **Benchmark Tests**
   - Detector performance
   - Matching speed
   - Memory usage

## Security Considerations

1. **Safe Execution**
   - Never execute detected code
   - Sandbox deobfuscation
   - Timeout protection (ReDoS)

2. **Resource Limits**
   - File size limits
   - Memory limits
   - Worker pool size

3. **Input Validation**
   - Path traversal prevention
   - Symlink loop detection
   - Safe file handling

## Future Enhancements

1. **Plugin System**
   - Dynamic detector loading
   - External signature sources
   - Custom reporters

2. **Web Interface**
   - Browser-based UI
   - Real-time progress
   - Interactive reports

3. **REST API**
   - Remote scanning
   - Integration with CI/CD
   - Webhook notifications

4. **Database Backend**
   - Historical scans
   - Trend analysis
   - Team collaboration

---

**Version:** 0.0.1
**Last Updated:** 2026-01-25
