package signatures

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/IvanShishkin/houndoom/pkg/models"
	"gopkg.in/yaml.v3"
)

// Loader loads signatures from YAML files
type Loader struct {
	signaturesPath string
}

// NewLoader creates a new signature loader
func NewLoader(signaturesPath string) *Loader {
	return &Loader{
		signaturesPath: signaturesPath,
	}
}

// SignatureFile represents a YAML signature file
type SignatureFile struct {
	Signatures []*models.Signature `yaml:"signatures"`
}

// Load loads all signatures from the signatures directory
func (l *Loader) Load() (*models.SignatureDatabase, error) {
	db := models.NewSignatureDatabase()

	// Check if signatures path exists
	if _, err := os.Stat(l.signaturesPath); os.IsNotExist(err) {
		return db, nil // Return empty database if path doesn't exist
	}

	// Walk signatures directory
	err := filepath.Walk(l.signaturesPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip directories and non-YAML files
		if info.IsDir() || (filepath.Ext(path) != ".yaml" && filepath.Ext(path) != ".yml") {
			return nil
		}

		// Load signature file
		if err := l.loadFile(path, db); err != nil {
			return fmt.Errorf("failed to load %s: %w", path, err)
		}

		return nil
	})

	return db, err
}

// loadFile loads signatures from a single YAML file
func (l *Loader) loadFile(path string, db *models.SignatureDatabase) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	var sigFile SignatureFile
	if err := yaml.Unmarshal(data, &sigFile); err != nil {
		return err
	}

	// Add signatures to database
	for _, sig := range sigFile.Signatures {
		// Set defaults
		if sig.Enabled == false {
			sig.Enabled = true
		}
		if len(sig.Extensions) == 0 {
			sig.Extensions = []string{"*"}
		}

		if err := db.AddSignature(sig); err != nil {
			return fmt.Errorf("failed to add signature %s: %w", sig.ID, err)
		}
	}

	return nil
}
