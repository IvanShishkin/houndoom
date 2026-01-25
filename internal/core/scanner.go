package core

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"time"

	"github.com/IvanShishkin/houndoom/internal/ai"
	"github.com/IvanShishkin/houndoom/internal/config"
	"github.com/IvanShishkin/houndoom/internal/deobfuscator"
	deobfPHP "github.com/IvanShishkin/houndoom/internal/deobfuscator/php"
	"github.com/IvanShishkin/houndoom/internal/detectors"
	"github.com/IvanShishkin/houndoom/internal/detectors/adware"
	"github.com/IvanShishkin/houndoom/internal/detectors/cms"
	"github.com/IvanShishkin/houndoom/internal/detectors/cms/bitrix"
	"github.com/IvanShishkin/houndoom/internal/detectors/doorway"
	"github.com/IvanShishkin/houndoom/internal/detectors/executable"
	"github.com/IvanShishkin/houndoom/internal/detectors/javascript"
	"github.com/IvanShishkin/houndoom/internal/detectors/phishing"
	"github.com/IvanShishkin/houndoom/internal/detectors/php"
	"github.com/IvanShishkin/houndoom/internal/heuristic"
	"github.com/IvanShishkin/houndoom/internal/filesystem"
	"github.com/IvanShishkin/houndoom/internal/report"
	"github.com/IvanShishkin/houndoom/internal/signatures"
	"github.com/IvanShishkin/houndoom/pkg/models"
	"go.uber.org/zap"
)

// ProgressCallback is called to report scan progress
type ProgressCallback func(phase string, current, total int, message string)

// AIConfirmCallback is called to confirm AI analysis when cost exceeds threshold
// Returns true to proceed, false to skip AI analysis
type AIConfirmCallback func(estimate *ai.CostEstimate) bool

// Scanner is the main scanner engine
type Scanner struct {
	config            *config.Config
	logger            *zap.Logger
	detectors         []detectors.Detector
	walker            *filesystem.Walker
	reporter          *report.Generator
	results           *models.ScanResults
	deobfuscator      *deobfuscator.Manager
	aiReport          *ai.AIReport
	progressCallback  ProgressCallback
	aiConfirmCallback AIConfirmCallback
	mu                sync.Mutex
}

// NewScanner creates a new scanner instance
func NewScanner(cfg *config.Config, logger *zap.Logger) *Scanner {
	return &Scanner{
		config: cfg,
		logger: logger,
		results: &models.ScanResults{
			FindingsByType:     make(map[models.ThreatType][]*models.Finding),
			FindingsBySeverity: make(map[models.Severity][]*models.Finding),
			Stats:              &models.ScanStatistics{},
		},
	}
}

// RegisterDetector registers a new detector
func (s *Scanner) RegisterDetector(d detectors.Detector) {
	s.detectors = append(s.detectors, d)
	s.logger.Info("Registered detector",
		zap.String("name", d.Name()),
		zap.Int("priority", d.Priority()))
}

// SetProgressCallback sets the progress callback function
func (s *Scanner) SetProgressCallback(cb ProgressCallback) {
	s.progressCallback = cb
}

// SetAIConfirmCallback sets the AI confirmation callback function
func (s *Scanner) SetAIConfirmCallback(cb AIConfirmCallback) {
	s.aiConfirmCallback = cb
}

// reportProgress calls the progress callback if set
func (s *Scanner) reportProgress(phase string, current, total int, message string) {
	if s.progressCallback != nil {
		s.progressCallback(phase, current, total, message)
	}
}

// Scan performs the security scan
func (s *Scanner) Scan(path string) (*models.ScanResults, error) {
	s.logger.Info("Starting scan",
		zap.String("path", path),
		zap.String("mode", s.config.Mode))

	// Initialize
	s.results.StartTime = time.Now()
	s.results.ScanPath = path
	s.results.Mode = s.config.Mode
	s.results.Version = "0.0.1" // TODO: Get from build info

	// Initialize filesystem walker
	s.walker = filesystem.NewWalker(s.config, s.logger)

	// Initialize report generator
	var err error
	s.reporter, err = report.NewGenerator(s.config, s.logger)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize report generator: %w", err)
	}

	// Initialize detectors
	if err = s.initDetectors(); err != nil {
		return nil, fmt.Errorf("failed to initialize detectors: %w", err)
	}

	// Count files first
	s.reportProgress("counting", 0, 0, "Counting files...")
	totalFiles := s.countFiles(path)
	s.reportProgress("counting", totalFiles, totalFiles, fmt.Sprintf("Found %d files to scan", totalFiles))

	// Create context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create worker pool
	workers := s.config.Workers
	if workers <= 0 {
		workers = runtime.NumCPU() * 2
	}
	s.results.Stats.WorkersUsed = workers

	// Scan files with progress
	if err := s.scanFilesWithProgress(ctx, path, workers, totalFiles); err != nil {
		return nil, err
	}

	// AI Analysis (after all findings collected)
	if s.config.AI.Enabled && len(s.results.Findings) > 0 {
		s.logger.Info("Starting AI analysis", zap.Int("findings", len(s.results.Findings)))

		// Count unique signatures for smart mode estimation
		uniqueSignatures := 0
		if s.config.AI.SmartMode {
			sigSet := make(map[string]bool)
			for _, finding := range s.results.Findings {
				sigSet[finding.SignatureID] = true
			}
			uniqueSignatures = len(sigSet)
		}

		// Estimate cost with modes
		estimate := ai.EstimateCostWithModes(
			s.config.AI.Model,
			len(s.results.Findings),
			s.config.AI.QuickFilter,
			s.config.AI.SmartMode,
			uniqueSignatures,
		)

		// Always ask for confirmation when AI is enabled and callback is set
		shouldProceed := true
		if s.aiConfirmCallback != nil {
			shouldProceed = s.aiConfirmCallback(estimate)
		}

		if !shouldProceed {
			s.reportProgress("ai_skipped", 0, 0, "AI analysis skipped by user")
			s.logger.Info("AI analysis skipped by user")
		} else {
			s.reportProgress("ai_init", 0, len(s.results.Findings), "Initializing AI analysis...")

			analyzer, err := ai.NewAnalyzer(&s.config.AI, s.logger)
			if err != nil {
				s.reportProgress("ai_error", 0, 0, fmt.Sprintf("AI skipped: %s", err.Error()))
				s.logger.Debug("Failed to initialize AI analyzer", zap.Error(err))
				// Continue without AI - graceful degradation
			} else {
				// Set progress callback for AI analyzer
				analyzer.SetProgressCallback(func(current, total int, message string) {
					s.reportProgress("ai_analysis", current, total, message)
				})

				aiReport, err := analyzer.AnalyzeFindings(ctx, s.results)
				if err != nil {
					s.reportProgress("ai_error", 0, 0, fmt.Sprintf("AI failed: %s", err.Error()))
					s.logger.Debug("AI analysis failed", zap.Error(err))
				} else {
					s.aiReport = aiReport
					s.enrichFindings(aiReport)
					s.reportProgress("ai_complete", aiReport.TotalTokensUsed, aiReport.AnalyzedCount, "AI analysis complete")
				}
			}
		}
	}

	// Finalize results
	s.results.EndTime = time.Now()
	s.results.Duration = s.results.EndTime.Sub(s.results.StartTime)

	// Calculate statistics
	s.calculateStats()

	// Generate report
	reportPath, err := s.reporter.Generate(s.results, s.aiReport)
	if err != nil {
		s.logger.Error("Failed to generate report", zap.Error(err))
		return s.results, err
	}
	s.results.ReportPath = reportPath

	s.logger.Info("Scan completed",
		zap.Duration("duration", s.results.Duration),
		zap.Int("threats_found", s.results.ThreatsFound),
		zap.Int("files_scanned", s.results.ScannedFiles))

	return s.results, nil
}

// initDetectors initializes all detectors
func (s *Scanner) initDetectors() error {
	// Load signatures
	loader := signatures.NewLoader(s.config.SignaturesPath)
	sigDB, err := loader.Load()
	if err != nil {
		return fmt.Errorf("failed to load signatures: %w", err)
	}

	s.logger.Info("Loaded signatures", zap.Int("count", len(sigDB.Signatures)))

	// Create matcher
	matcher := signatures.NewMatcher(sigDB)

	// Determine signature level based on scan mode
	var sigLevel models.SignatureLevel
	switch s.config.GetScanMode() {
	case config.ModeFast:
		sigLevel = models.LevelBasic
	case config.ModeParanoid:
		sigLevel = models.LevelParanoid
	default:
		sigLevel = models.LevelExpert
	}

	// Detect CMS type (auto-detect or use forced CMS)
	var detectedCMS *cms.DetectionResult
	if s.config.ForceCMS != "" {
		// Use forced CMS
		s.logger.Info("Using forced CMS type", zap.String("cms", s.config.ForceCMS))
		detectedCMS = &cms.DetectionResult{
			Type:       cms.CMSType(s.config.ForceCMS),
			Confidence: 100,
			Indicators: []string{"Forced by --cms flag"},
		}
	} else {
		// Auto-detect CMS
		cmsDetector := cms.NewDetector(s.logger)
		detectedCMS = cmsDetector.Detect(s.results.ScanPath)

		if detectedCMS.Type != cms.CMSUnknown {
			s.logger.Info("Detected CMS",
				zap.String("type", string(detectedCMS.Type)),
				zap.Int("confidence", detectedCMS.Confidence),
				zap.Strings("indicators", detectedCMS.Indicators))
		} else {
			s.logger.Info("CMS not detected, using universal detectors only")
		}
	}

	// Store detected CMS in results
	s.results.DetectedCMS = string(detectedCMS.Type)
	s.results.CMSConfidence = detectedCMS.Confidence

	// Register CRITICAL detectors (always enabled)
	s.logger.Info("Registering critical detectors")

	// PHP Critical detectors
	phpCriticalDetector := php.NewCriticalDetector(matcher, sigLevel)
	s.RegisterDetector(phpCriticalDetector)

	phpBackdoorDetector := php.NewBackdoorDetector(matcher, sigLevel)
	s.RegisterDetector(phpBackdoorDetector)

	phpInjectionDetector := php.NewInjectionDetector(matcher, sigLevel)
	s.RegisterDetector(phpInjectionDetector)

	// PHP Obfuscation detector (detects goto-obfuscation, hex encoding, etc.)
	phpObfuscationDetector := php.NewObfuscationDetector(matcher, sigLevel)
	s.RegisterDetector(phpObfuscationDetector)

	// CMS-specific detectors (conditional based on detection)
	if detectedCMS.IsBitrix() {
		s.logger.Info("Registering Bitrix CMS detector",
			zap.Int("confidence", detectedCMS.Confidence))
		bitrixDetector := bitrix.NewBitrixDetector(matcher, sigLevel)
		s.RegisterDetector(bitrixDetector)
	}

	// JavaScript Critical detector
	jsMaliciousDetector := javascript.NewMaliciousDetector(matcher, sigLevel)
	s.RegisterDetector(jsMaliciousDetector)

	// Executable detector (critical for security)
	executableDetector := executable.NewDetector()
	s.RegisterDetector(executableDetector)

	// Register EXPERIMENTAL detectors (only if enabled)
	if s.config.EnableExperimental {
		s.logger.Info("Registering experimental detectors")

		// JavaScript experimental
		jsIframeDetector := javascript.NewIframeDetector(matcher, sigLevel)
		s.RegisterDetector(jsIframeDetector)

		jsXSSDetector := javascript.NewXSSDetector(matcher, sigLevel)
		s.RegisterDetector(jsXSSDetector)

		// Adware detector
		adwareDetector := adware.NewDetector(matcher, sigLevel)
		s.RegisterDetector(adwareDetector)

		// Phishing detector
		phishingDetector := phishing.NewDetector(matcher, sigLevel)
		s.RegisterDetector(phishingDetector)

		// Doorway detector
		doorwayDetector := doorway.NewDetector(matcher, sigLevel)
		s.RegisterDetector(doorwayDetector)

		// Heuristic detector
		heuristicDetector := heuristic.NewHeuristicDetector()
		s.RegisterDetector(heuristicDetector)
	} else {
		s.logger.Info("Experimental detectors disabled. Use --experimental flag to enable")
	}

	// Initialize deobfuscator if enabled
	if s.config.EnableDeobfuscation {
		s.deobfuscator = deobfuscator.NewManager(s.config.MaxDeobfuscateDepth)
		// Register all PHP deobfuscators
		s.deobfuscator.Register(deobfPHP.NewBase64Deobfuscator())
		s.deobfuscator.Register(deobfPHP.NewEvalDeobfuscator())
		s.deobfuscator.Register(deobfPHP.NewLockItDeobfuscator())
		s.deobfuscator.Register(deobfPHP.NewALSDeobfuscator())
		s.deobfuscator.Register(deobfPHP.NewByteRunDeobfuscator())
		s.deobfuscator.Register(deobfPHP.NewFOPODeobfuscator())
		s.deobfuscator.Register(deobfPHP.NewGlobalsDeobfuscator())
		s.deobfuscator.Register(deobfPHP.NewURLDecodeDeobfuscator())
		s.logger.Info("Deobfuscation enabled",
			zap.Int("max_depth", s.config.MaxDeobfuscateDepth),
			zap.Int("deobfuscators", 8))
	}

	s.logger.Info("Initialized detectors", zap.Int("count", len(s.detectors)))
	return nil
}

// countFiles counts total files to scan
func (s *Scanner) countFiles(path string) int {
	count := 0
	tempWalker := filesystem.NewWalker(s.config, s.logger)
	tempWalker.Walk(path, func(fileInfo *models.FileInfo) error {
		if !fileInfo.IsDir {
			extension := filesystem.GetExtension(fileInfo.Path)
			if s.config.ShouldScanFile(extension) {
				maxSize := filesystem.ParseSize(s.config.MaxSize)
				if fileInfo.Size <= maxSize {
					count++
				}
			}
		}
		return nil
	})
	return count
}

// scanFilesWithProgress scans all files using worker pool with progress reporting
func (s *Scanner) scanFilesWithProgress(ctx context.Context, path string, workers int, totalFiles int) error {
	// Create channels
	fileChan := make(chan *models.FileInfo, workers*2)
	resultsChan := make(chan *ScanResult, workers*2)

	// Start worker pool
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go s.worker(ctx, &wg, fileChan, resultsChan)
	}

	// Start results collector with progress
	var collectWg sync.WaitGroup
	collectWg.Add(1)
	go s.collectResultsWithProgress(&collectWg, resultsChan, totalFiles)

	// Walk filesystem and send files to workers
	walkErr := s.walker.Walk(path, func(fileInfo *models.FileInfo) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case fileChan <- fileInfo:
			s.mu.Lock()
			if fileInfo.IsDir {
				s.results.TotalDirs++
			} else {
				s.results.TotalFiles++
			}
			s.mu.Unlock()
			return nil
		}
	})

	// Close channels and wait
	close(fileChan)
	wg.Wait()
	close(resultsChan)
	collectWg.Wait()

	return walkErr
}

// scanFiles scans all files using worker pool
func (s *Scanner) scanFiles(ctx context.Context, path string, workers int) error {
	// Create channels
	fileChan := make(chan *models.FileInfo, workers*2)
	resultsChan := make(chan *ScanResult, workers*2)

	// Start worker pool
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go s.worker(ctx, &wg, fileChan, resultsChan)
	}

	// Start results collector
	var collectWg sync.WaitGroup
	collectWg.Add(1)
	go s.collectResults(&collectWg, resultsChan)

	// Walk filesystem and send files to workers
	walkErr := s.walker.Walk(path, func(fileInfo *models.FileInfo) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case fileChan <- fileInfo:
			s.mu.Lock()
			if fileInfo.IsDir {
				s.results.TotalDirs++
			} else {
				s.results.TotalFiles++
			}
			s.mu.Unlock()
			return nil
		}
	})

	// Close channels and wait
	close(fileChan)
	wg.Wait()
	close(resultsChan)
	collectWg.Wait()

	return walkErr
}

// worker processes files from the channel
func (s *Scanner) worker(ctx context.Context, wg *sync.WaitGroup, fileChan <-chan *models.FileInfo, resultsChan chan<- *ScanResult) {
	defer wg.Done()

	for fileInfo := range fileChan {
		select {
		case <-ctx.Done():
			return
		default:
			result := s.scanFile(ctx, fileInfo)
			resultsChan <- result
		}
	}
}

// ScanResult represents the result of scanning a single file
type ScanResult struct {
	FileInfo *models.FileInfo
	Findings []*models.Finding
	Error    error
	Skipped  bool
}

// scanFile scans a single file
func (s *Scanner) scanFile(ctx context.Context, fileInfo *models.FileInfo) *ScanResult {
	result := &ScanResult{
		FileInfo: fileInfo,
	}

	// Skip directories
	if fileInfo.IsDir {
		result.Skipped = true
		return result
	}

	// Check if should scan this file
	extension := filesystem.GetExtension(fileInfo.Path)
	if !s.config.ShouldScanFile(extension) {
		result.Skipped = true
		return result
	}

	// Check file size
	maxSize := filesystem.ParseSize(s.config.MaxSize)
	if fileInfo.Size > maxSize {
		s.logger.Debug("File too large, skipping",
			zap.String("path", fileInfo.Path),
			zap.Int64("size", fileInfo.Size))
		result.Skipped = true
		return result
	}

	// Read file
	file, err := filesystem.ReadFile(fileInfo)
	if err != nil {
		result.Error = err
		return result
	}

	// Try to deobfuscate if enabled
	if s.config.EnableDeobfuscation && s.deobfuscator != nil {
		deobfuscated, modified := s.deobfuscator.Deobfuscate(string(file.Content))
		if modified {
			file.Content = []byte(deobfuscated)
			s.logger.Debug("File deobfuscated", zap.String("path", file.Path))
		}
	}

	// Run detectors
	for _, detector := range s.detectors {
		if !detector.IsEnabled() {
			continue
		}

		if !s.shouldRunDetector(detector, extension) {
			continue
		}

		findings, err := detector.Detect(ctx, file)
		if err != nil {
			s.logger.Warn("Detector failed",
				zap.String("detector", detector.Name()),
				zap.String("file", file.Path),
				zap.Error(err))
			continue
		}

		if len(findings) > 0 {
			result.Findings = append(result.Findings, findings...)
		}
	}

	return result
}

// shouldRunDetector checks if a detector should run on a file
func (s *Scanner) shouldRunDetector(d detectors.Detector, extension string) bool {
	exts := d.SupportedExtensions()
	if len(exts) == 0 || exts[0] == "*" {
		return true
	}

	for _, ext := range exts {
		if ext == extension {
			return true
		}
	}
	return false
}

// collectResultsWithProgress collects scan results from workers with progress reporting
func (s *Scanner) collectResultsWithProgress(wg *sync.WaitGroup, resultsChan <-chan *ScanResult, totalFiles int) {
	defer wg.Done()

	processed := 0
	lastReport := time.Now()

	for result := range resultsChan {
		s.mu.Lock()

		if result.Skipped {
			s.results.SkippedFiles++
		} else if result.Error != nil {
			s.results.Stats.ReadErrors++
			s.results.Stats.ErrorFiles = append(s.results.Stats.ErrorFiles, result.FileInfo.Path)
			processed++
		} else {
			s.results.ScannedFiles++
			processed++

			// Add findings
			for _, finding := range result.Findings {
				s.results.AddFinding(finding)
			}
		}

		// Report progress every 100ms or every 100 files
		if time.Since(lastReport) > 100*time.Millisecond || processed%100 == 0 {
			s.reportProgress("scanning", processed, totalFiles, result.FileInfo.Path)
			lastReport = time.Now()
		}

		s.mu.Unlock()
	}

	// Final progress report
	s.reportProgress("scanning", processed, totalFiles, "Scan complete")
}

// collectResults collects scan results from workers
func (s *Scanner) collectResults(wg *sync.WaitGroup, resultsChan <-chan *ScanResult) {
	defer wg.Done()

	for result := range resultsChan {
		s.mu.Lock()

		if result.Skipped {
			s.results.SkippedFiles++
		} else if result.Error != nil {
			s.results.Stats.ReadErrors++
			s.results.Stats.ErrorFiles = append(s.results.Stats.ErrorFiles, result.FileInfo.Path)
		} else {
			s.results.ScannedFiles++

			// Add findings
			for _, finding := range result.Findings {
				s.results.AddFinding(finding)
			}
		}

		s.mu.Unlock()
	}
}

// calculateStats calculates final statistics
func (s *Scanner) calculateStats() {
	if s.results.ScannedFiles > 0 {
		s.results.Stats.AverageFileSize = s.results.Stats.TotalSize / int64(s.results.ScannedFiles)
	}

	duration := s.results.Duration.Seconds()
	if duration > 0 {
		s.results.Stats.FilesPerSecond = float64(s.results.ScannedFiles) / duration
	}

	// Get memory usage
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	s.results.Stats.MemoryUsed = m.Alloc
}

// enrichFindings adds AI analysis data to finding metadata
func (s *Scanner) enrichFindings(aiReport *ai.AIReport) {
	if aiReport == nil {
		return
	}

	for i, finding := range s.results.Findings {
		findingID := fmt.Sprintf("finding-%d", i)
		result := aiReport.GetResultByFindingID(findingID)
		if result == nil {
			continue
		}

		// Initialize metadata if nil
		if finding.Metadata == nil {
			finding.Metadata = make(map[string]any)
		}

		// Add AI analysis data to metadata
		finding.Metadata["ai_verdict"] = string(result.Verdict)
		finding.Metadata["ai_confidence"] = result.Confidence
		finding.Metadata["ai_explanation"] = result.Explanation
		finding.Metadata["ai_remediation"] = result.Remediation
		finding.Metadata["ai_risk"] = result.RiskLevel
		finding.Metadata["ai_indicators"] = result.Indicators
	}
}
