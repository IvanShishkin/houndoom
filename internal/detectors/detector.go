package detectors

import (
	"context"

	"github.com/IvanShishkin/houndoom/pkg/models"
)

// Detector is the interface that all threat detectors must implement
type Detector interface {
	// Name returns the detector name
	Name() string

	// Priority returns the detector priority (higher = earlier execution)
	Priority() int

	// SupportedExtensions returns list of file extensions this detector can handle
	SupportedExtensions() []string

	// Detect scans a file and returns findings
	Detect(ctx context.Context, file *models.File) ([]*models.Finding, error)

	// IsEnabled returns whether this detector is enabled
	IsEnabled() bool

	// SetEnabled enables or disables this detector
	SetEnabled(enabled bool)
}

// BaseDetector provides common functionality for detectors
type BaseDetector struct {
	name       string
	priority   int
	extensions []string
	enabled    bool
}

// NewBaseDetector creates a new base detector
func NewBaseDetector(name string, priority int, extensions []string) *BaseDetector {
	return &BaseDetector{
		name:       name,
		priority:   priority,
		extensions: extensions,
		enabled:    true,
	}
}

// Name returns the detector name
func (d *BaseDetector) Name() string {
	return d.name
}

// Priority returns the detector priority
func (d *BaseDetector) Priority() int {
	return d.priority
}

// SupportedExtensions returns supported file extensions
func (d *BaseDetector) SupportedExtensions() []string {
	return d.extensions
}

// IsEnabled returns whether this detector is enabled
func (d *BaseDetector) IsEnabled() bool {
	return d.enabled
}

// SetEnabled enables or disables this detector
func (d *BaseDetector) SetEnabled(enabled bool) {
	d.enabled = enabled
}

// SupportsFile checks if this detector supports the given file extension
func (d *BaseDetector) SupportsFile(extension string) bool {
	for _, ext := range d.extensions {
		if ext == extension || ext == "*" {
			return true
		}
	}
	return false
}
