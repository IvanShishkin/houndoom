package ai

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/IvanShishkin/houndoom/internal/config"
	"github.com/IvanShishkin/houndoom/pkg/models"
	"go.uber.org/zap"
)

// AIProgressCallback is called to report AI analysis progress
type AIProgressCallback func(current, total int, message string)

// Analyzer performs AI-powered analysis of security findings
type Analyzer struct {
	client           *Client
	config           *config.AIConfig
	logger           *zap.Logger
	report           *AIReport
	progressCallback AIProgressCallback
}

// SetProgressCallback sets the progress callback function
func (a *Analyzer) SetProgressCallback(cb AIProgressCallback) {
	a.progressCallback = cb
}

// reportProgress calls the progress callback if set
func (a *Analyzer) reportProgress(current, total int, message string) {
	if a.progressCallback != nil {
		a.progressCallback(current, total, message)
	}
}

// NewAnalyzer creates a new AI analyzer
func NewAnalyzer(cfg *config.AIConfig, logger *zap.Logger) (*Analyzer, error) {
	client, err := NewClient(cfg.Model, cfg.APIToken, cfg.Timeout)
	if err != nil {
		return nil, err
	}

	return &Analyzer{
		client: client,
		config: cfg,
		logger: logger,
		report: &AIReport{
			Model:    client.GetModel(),
			Language: cfg.Language,
			Results:  make([]*AnalysisResponse, 0),
		},
	}, nil
}

// AnalyzeFindings performs AI analysis on scan findings
func (a *Analyzer) AnalyzeFindings(ctx context.Context, results *models.ScanResults) (*AIReport, error) {
	a.report.StartTime = time.Now()

	findings := results.Findings

	// Smart mode: dedupe + sample + severity priority
	if a.config.SmartMode {
		a.report.IsSmartMode = true
		return a.analyzeSmartMode(ctx, results)
	}

	// Standard mode
	// Limit findings if configured
	if a.config.MaxFindings > 0 && len(findings) > a.config.MaxFindings {
		a.logger.Info("Limiting findings for AI analysis",
			zap.Int("total", len(findings)),
			zap.Int("limit", a.config.MaxFindings))
		findings = findings[:a.config.MaxFindings]
	}

	// Build analysis requests
	requests := make([]*AnalysisRequest, len(findings))
	for i, finding := range findings {
		requests[i] = buildAnalysisRequest(finding, results.DetectedCMS, i)
	}

	// Quick filter with Haiku if enabled
	var toAnalyze []*AnalysisRequest
	if a.config.QuickFilter && len(requests) > 5 {
		a.logger.Info("Running quick filter with Haiku", zap.Int("findings", len(requests)))
		a.reportProgress(0, len(requests), "Quick filtering with Haiku...")
		toAnalyze = a.quickFilter(ctx, requests)
		a.report.FilteredCount = len(requests) - len(toAnalyze)
		a.reportProgress(len(requests), len(requests), fmt.Sprintf("Filtered: %d passed, %d skipped", len(toAnalyze), a.report.FilteredCount))
		a.logger.Info("Quick filter complete",
			zap.Int("passed", len(toAnalyze)),
			zap.Int("filtered", a.report.FilteredCount))
	} else {
		toAnalyze = requests
	}

	// Deep analysis for remaining findings
	a.logger.Info("Running deep analysis", zap.Int("findings", len(toAnalyze)))
	for i, req := range toAnalyze {
		select {
		case <-ctx.Done():
			a.logger.Warn("Analysis cancelled", zap.Int("analyzed", i))
			break
		default:
			a.reportProgress(i+1, len(toAnalyze), fmt.Sprintf("Analyzing: %s", req.SignatureName))
			a.logger.Debug("Analyzing finding",
				zap.Int("index", i+1),
				zap.Int("total", len(toAnalyze)),
				zap.String("signature", req.SignatureName))

			result, err := a.deepAnalysis(ctx, req)
			if err != nil {
				a.logger.Warn("Analysis failed for finding",
					zap.String("finding_id", req.FindingID),
					zap.Error(err))
				a.report.Errors = append(a.report.Errors, fmt.Sprintf("Finding %s: %v", req.FindingID, err))
				continue
			}

			a.report.Results = append(a.report.Results, result)
			a.report.TotalTokensUsed += result.TokensUsed
			a.updateCounts(result.Verdict)
			a.report.AnalyzedCount++
		}
	}

	a.report.EndTime = time.Now()
	a.report.Duration = a.report.EndTime.Sub(a.report.StartTime)

	a.logger.Info("AI analysis complete",
		zap.Int("analyzed", a.report.AnalyzedCount),
		zap.Int("malicious", a.report.MaliciousCount),
		zap.Int("suspicious", a.report.SuspiciousCount),
		zap.Int("false_positives", a.report.FalsePositiveCount),
		zap.Int("tokens_used", a.report.TotalTokensUsed),
		zap.Duration("duration", a.report.Duration))

	return a.report, nil
}

// analyzeSmartMode performs smart analysis with deduplication and sampling
func (a *Analyzer) analyzeSmartMode(ctx context.Context, results *models.ScanResults) (*AIReport, error) {
	const samplesPerSignature = 3

	findings := results.Findings
	a.logger.Info("Running smart mode analysis", zap.Int("total_findings", len(findings)))

	// Group findings by signature ID
	bySignature := make(map[string][]*models.Finding)
	for _, finding := range findings {
		bySignature[finding.SignatureID] = append(bySignature[finding.SignatureID], finding)
	}

	a.report.UniqueSignatures = len(bySignature)
	a.logger.Info("Grouped by signature", zap.Int("unique_signatures", len(bySignature)))

	// Sort signatures by severity priority (critical first)
	type sigGroup struct {
		signatureID string
		severity    models.Severity
		findings    []*models.Finding
	}

	severityOrder := map[models.Severity]int{
		models.SeverityCritical: 0,
		models.SeverityHigh:     1,
		models.SeverityMedium:   2,
		models.SeverityLow:      3,
		models.SeverityInfo:     4,
	}

	var groups []sigGroup
	for sigID, sigFindings := range bySignature {
		groups = append(groups, sigGroup{
			signatureID: sigID,
			severity:    sigFindings[0].Severity,
			findings:    sigFindings,
		})
	}

	// Sort by severity (critical first)
	sort.Slice(groups, func(i, j int) bool {
		return severityOrder[groups[i].severity] < severityOrder[groups[j].severity]
	})

	// Sample findings from each signature group
	var sampledFindings []*models.Finding
	for _, group := range groups {
		count := samplesPerSignature
		if count > len(group.findings) {
			count = len(group.findings)
		}
		sampledFindings = append(sampledFindings, group.findings[:count]...)
	}

	a.report.SampledFindings = len(sampledFindings)
	a.logger.Info("Sampled findings",
		zap.Int("sampled", len(sampledFindings)),
		zap.Int("original", len(findings)))

	// Build analysis requests
	requests := make([]*AnalysisRequest, len(sampledFindings))
	for i, finding := range sampledFindings {
		requests[i] = buildAnalysisRequest(finding, results.DetectedCMS, i)
	}

	// Quick filter with Haiku if enabled
	var toAnalyze []*AnalysisRequest
	if a.config.QuickFilter && len(requests) > 5 {
		a.logger.Info("Running quick filter with Haiku", zap.Int("findings", len(requests)))
		a.reportProgress(0, len(requests), "Quick filtering with Haiku...")
		toAnalyze = a.quickFilter(ctx, requests)
		a.report.FilteredCount = len(requests) - len(toAnalyze)
		a.reportProgress(len(requests), len(requests), fmt.Sprintf("Filtered: %d passed, %d skipped", len(toAnalyze), a.report.FilteredCount))
		a.logger.Info("Quick filter complete",
			zap.Int("passed", len(toAnalyze)),
			zap.Int("filtered", a.report.FilteredCount))
	} else {
		toAnalyze = requests
	}

	// Deep analysis for sampled findings
	a.logger.Info("Running deep analysis on samples", zap.Int("findings", len(toAnalyze)))
	for i, req := range toAnalyze {
		select {
		case <-ctx.Done():
			a.logger.Warn("Analysis cancelled", zap.Int("analyzed", i))
			break
		default:
			a.reportProgress(i+1, len(toAnalyze), fmt.Sprintf("Analyzing: %s", req.SignatureName))
			a.logger.Debug("Analyzing finding",
				zap.Int("index", i+1),
				zap.Int("total", len(toAnalyze)),
				zap.String("signature", req.SignatureName))

			result, err := a.deepAnalysis(ctx, req)
			if err != nil {
				a.logger.Warn("Analysis failed for finding",
					zap.String("finding_id", req.FindingID),
					zap.Error(err))
				a.report.Errors = append(a.report.Errors, fmt.Sprintf("Finding %s: %v", req.FindingID, err))
				continue
			}

			a.report.Results = append(a.report.Results, result)
			a.report.TotalTokensUsed += result.TokensUsed
			a.updateCounts(result.Verdict)
			a.report.AnalyzedCount++
		}
	}

	a.report.EndTime = time.Now()
	a.report.Duration = a.report.EndTime.Sub(a.report.StartTime)

	a.logger.Info("Smart mode analysis complete",
		zap.Int("analyzed", a.report.AnalyzedCount),
		zap.Int("unique_signatures", a.report.UniqueSignatures),
		zap.Int("sampled", a.report.SampledFindings),
		zap.Int("tokens_used", a.report.TotalTokensUsed),
		zap.Duration("duration", a.report.Duration))

	return a.report, nil
}

// quickFilter runs quick filtering on findings using Haiku
func (a *Analyzer) quickFilter(ctx context.Context, requests []*AnalysisRequest) []*AnalysisRequest {
	var toAnalyze []*AnalysisRequest
	lang := a.config.Language

	for _, req := range requests {
		select {
		case <-ctx.Done():
			// If cancelled, include remaining requests
			toAnalyze = append(toAnalyze, req)
			continue
		default:
		}

		result, err := a.client.QuickFilter(ctx, req, lang)
		if err != nil {
			a.logger.Debug("Quick filter failed, including in analysis",
				zap.String("finding_id", req.FindingID),
				zap.Error(err))
			toAnalyze = append(toAnalyze, req)
			continue
		}

		a.report.FilterResults = append(a.report.FilterResults, result)
		a.report.TotalTokensUsed += result.TokensUsed

		if result.NeedsAnalysis {
			toAnalyze = append(toAnalyze, req)
		} else {
			a.logger.Debug("Finding filtered out",
				zap.String("finding_id", req.FindingID),
				zap.String("reason", result.Reason))
		}
	}

	return toAnalyze
}

// deepAnalysis performs deep analysis on a single finding
func (a *Analyzer) deepAnalysis(ctx context.Context, req *AnalysisRequest) (*AnalysisResponse, error) {
	return a.client.Analyze(ctx, req, a.config.Language)
}

// updateCounts updates verdict statistics
func (a *Analyzer) updateCounts(verdict Verdict) {
	switch verdict {
	case VerdictMalicious:
		a.report.MaliciousCount++
	case VerdictSuspicious:
		a.report.SuspiciousCount++
	case VerdictFalsePositive:
		a.report.FalsePositiveCount++
	case VerdictBenign:
		a.report.BenignCount++
	default:
		a.report.UnknownCount++
	}
}

// buildAnalysisRequest creates an AnalysisRequest from a Finding
func buildAnalysisRequest(finding *models.Finding, cmsContext string, index int) *AnalysisRequest {
	return &AnalysisRequest{
		FindingID:     fmt.Sprintf("finding-%d", index),
		SignatureName: finding.SignatureName,
		SignatureID:   finding.SignatureID,
		Description:   finding.Description,
		FilePath:      finding.File.Path,
		LineNumber:    finding.LineNumber,
		CodeFragment:  finding.Fragment,
		Severity:      string(finding.Severity),
		ThreatType:    string(finding.Type),
		Confidence:    finding.Confidence,
		CMSContext:    cmsContext,
	}
}
