package models

import "time"

// ScanResults contains the complete scan results
type ScanResults struct {
	// Summary
	StartTime    time.Time     `json:"start_time"`
	EndTime      time.Time     `json:"end_time"`
	Duration     time.Duration `json:"duration"`
	ScanPath     string        `json:"scan_path"`
	TotalFiles   int           `json:"total_files"`
	TotalDirs    int           `json:"total_dirs"`
	ScannedFiles int           `json:"scanned_files"`
	SkippedFiles int           `json:"skipped_files"`
	ThreatsFound int           `json:"threats_found"`

	// Findings by category
	Findings         []*Finding        `json:"findings"`
	FindingsByType   map[ThreatType][]*Finding `json:"findings_by_type"`
	FindingsBySeverity map[Severity][]*Finding `json:"findings_by_severity"`

	// Statistics
	Stats *ScanStatistics `json:"statistics"`

	// Configuration
	Mode    string `json:"mode"`
	Version string `json:"version"`

	// CMS Detection
	DetectedCMS   string `json:"detected_cms,omitempty"`   // Detected CMS type (bitrix, wordpress, etc)
	CMSConfidence int    `json:"cms_confidence,omitempty"` // Confidence level (0-100)

	// Report path
	ReportPath string `json:"report_path,omitempty"`
}

// ScanStatistics contains detailed scan statistics
type ScanStatistics struct {
	// File statistics
	TotalSize        int64 `json:"total_size"`
	LargestFile      string `json:"largest_file,omitempty"`
	LargestFileSize  int64  `json:"largest_file_size"`
	AverageFileSize  int64  `json:"average_file_size"`

	// Threat counts by type
	PHPBackdoors     int `json:"php_backdoors"`
	JSViruses        int `json:"js_viruses"`
	PhishingPages    int `json:"phishing_pages"`
	IframeInjections int `json:"iframe_injections"`
	Executables      int `json:"executables"`
	ObfuscatedFiles  int `json:"obfuscated_files"`
	SuspiciousFiles  int `json:"suspicious_files"`
	AdwareFiles      int `json:"adware_files"`
	DoorwayDirs      int `json:"doorway_dirs"`
	Symlinks         int `json:"symlinks"`
	HiddenFiles      int `json:"hidden_files"`
	Vulnerabilities  int `json:"vulnerabilities"`

	// Errors
	ReadErrors    int      `json:"read_errors"`
	ErrorFiles    []string `json:"error_files,omitempty"`

	// Performance
	FilesPerSecond   float64 `json:"files_per_second"`
	MemoryUsed       uint64  `json:"memory_used_bytes"`
	WorkersUsed      int     `json:"workers_used"`
}

// AddFinding adds a finding to the results
func (r *ScanResults) AddFinding(f *Finding) {
	r.Findings = append(r.Findings, f)
	r.ThreatsFound++

	// Add to type map
	if r.FindingsByType == nil {
		r.FindingsByType = make(map[ThreatType][]*Finding)
	}
	r.FindingsByType[f.Type] = append(r.FindingsByType[f.Type], f)

	// Add to severity map
	if r.FindingsBySeverity == nil {
		r.FindingsBySeverity = make(map[Severity][]*Finding)
	}
	r.FindingsBySeverity[f.Severity] = append(r.FindingsBySeverity[f.Severity], f)

	// Update statistics
	if r.Stats == nil {
		r.Stats = &ScanStatistics{}
	}
	r.updateStats(f)
}

func (r *ScanResults) updateStats(f *Finding) {
	switch f.Type {
	case ThreatPHPBackdoor, ThreatPHPShell, ThreatPHPMalware:
		r.Stats.PHPBackdoors++
	case ThreatJSVirus, ThreatJSMalware:
		r.Stats.JSViruses++
	case ThreatPhishing:
		r.Stats.PhishingPages++
	case ThreatIframe:
		r.Stats.IframeInjections++
	case ThreatExecutable:
		r.Stats.Executables++
	case ThreatObfuscated:
		r.Stats.ObfuscatedFiles++
	case ThreatSuspicious:
		r.Stats.SuspiciousFiles++
	case ThreatAdware, ThreatSpam:
		r.Stats.AdwareFiles++
	case ThreatDoorway:
		r.Stats.DoorwayDirs++
	case ThreatSymlink:
		r.Stats.Symlinks++
	case ThreatHiddenFile:
		r.Stats.HiddenFiles++
	case ThreatVulnerability:
		r.Stats.Vulnerabilities++
	}
}
