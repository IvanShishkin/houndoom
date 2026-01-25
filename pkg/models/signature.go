package models

import "regexp"

// Signature represents a malware signature
type Signature struct {
	ID          string       `yaml:"id" json:"id"`
	Name        string       `yaml:"name" json:"name"`
	Description string       `yaml:"description" json:"description"`
	Severity    Severity     `yaml:"severity" json:"severity"`
	Category    ThreatType   `yaml:"category" json:"category"`
	Pattern     string       `yaml:"pattern" json:"pattern"`
	IsRegex     bool         `yaml:"is_regex" json:"is_regex"`
	Extensions  []string     `yaml:"extensions" json:"extensions"`
	Enabled     bool         `yaml:"enabled" json:"enabled"`
	Level       SignatureLevel `yaml:"level" json:"level"`
	CompiledRe  *regexp.Regexp `yaml:"-" json:"-"`
}

// SignatureLevel represents the signature detection level
type SignatureLevel int

const (
	LevelBasic SignatureLevel = iota
	LevelExpert
	LevelParanoid
)

// SignatureDatabase contains all signatures
type SignatureDatabase struct {
	Signatures []*Signature
	ByID       map[string]*Signature
	ByLevel    map[SignatureLevel][]*Signature
	ByCategory map[ThreatType][]*Signature
}

// NewSignatureDatabase creates a new signature database
func NewSignatureDatabase() *SignatureDatabase {
	return &SignatureDatabase{
		Signatures: make([]*Signature, 0),
		ByID:       make(map[string]*Signature),
		ByLevel:    make(map[SignatureLevel][]*Signature),
		ByCategory: make(map[ThreatType][]*Signature),
	}
}

// AddSignature adds a signature to the database
func (db *SignatureDatabase) AddSignature(sig *Signature) error {
	db.Signatures = append(db.Signatures, sig)
	db.ByID[sig.ID] = sig
	db.ByLevel[sig.Level] = append(db.ByLevel[sig.Level], sig)
	db.ByCategory[sig.Category] = append(db.ByCategory[sig.Category], sig)

	// Compile regex if needed
	if sig.IsRegex {
		re, err := regexp.Compile(sig.Pattern)
		if err != nil {
			return err
		}
		sig.CompiledRe = re
	}

	return nil
}

// GetByLevel returns signatures for a specific level
func (db *SignatureDatabase) GetByLevel(level SignatureLevel) []*Signature {
	return db.ByLevel[level]
}

// GetByCategory returns signatures for a specific category
func (db *SignatureDatabase) GetByCategory(category ThreatType) []*Signature {
	return db.ByCategory[category]
}
