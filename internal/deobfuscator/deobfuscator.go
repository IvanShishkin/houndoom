package deobfuscator

// Deobfuscator is the interface for code deobfuscators
type Deobfuscator interface {
	Name() string
	CanDeobfuscate(content string) bool
	Deobfuscate(content string) (string, error)
}

// Manager manages multiple deobfuscators
type Manager struct {
	deobfuscators []Deobfuscator
	maxDepth      int
}

// NewManager creates a new deobfuscator manager
func NewManager(maxDepth int) *Manager {
	return &Manager{
		deobfuscators: make([]Deobfuscator, 0),
		maxDepth:      maxDepth,
	}
}

// Register registers a deobfuscator
func (m *Manager) Register(d Deobfuscator) {
	m.deobfuscators = append(m.deobfuscators, d)
}

// Deobfuscate attempts to deobfuscate content recursively
func (m *Manager) Deobfuscate(content string) (string, bool) {
	result := content
	modified := false

	for depth := 0; depth < m.maxDepth; depth++ {
		deobfuscated := false

		for _, d := range m.deobfuscators {
			if d.CanDeobfuscate(result) {
				newResult, err := d.Deobfuscate(result)
				if err == nil && newResult != result {
					result = newResult
					deobfuscated = true
					modified = true
					break // Try again from the beginning
				}
			}
		}

		if !deobfuscated {
			break // No more deobfuscation possible
		}
	}

	return result, modified
}
