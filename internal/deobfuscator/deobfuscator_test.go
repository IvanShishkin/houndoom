package deobfuscator

import (
	"testing"
)

// mockDeobfuscator is a test deobfuscator
type mockDeobfuscator struct {
	name       string
	canDeobf   func(string) bool
	deobfFunc  func(string) (string, error)
}

func (m *mockDeobfuscator) Name() string {
	return m.name
}

func (m *mockDeobfuscator) CanDeobfuscate(content string) bool {
	return m.canDeobf(content)
}

func (m *mockDeobfuscator) Deobfuscate(content string) (string, error) {
	return m.deobfFunc(content)
}

func TestNewManager(t *testing.T) {
	manager := NewManager(50)
	if manager == nil {
		t.Fatal("NewManager() returned nil")
	}
	if manager.maxDepth != 50 {
		t.Errorf("maxDepth = %v, want %v", manager.maxDepth, 50)
	}
	if len(manager.deobfuscators) != 0 {
		t.Errorf("deobfuscators count = %v, want %v", len(manager.deobfuscators), 0)
	}
}

func TestManagerRegister(t *testing.T) {
	manager := NewManager(10)

	mock := &mockDeobfuscator{
		name:      "test",
		canDeobf:  func(s string) bool { return false },
		deobfFunc: func(s string) (string, error) { return s, nil },
	}

	manager.Register(mock)

	if len(manager.deobfuscators) != 1 {
		t.Errorf("deobfuscators count = %v, want %v", len(manager.deobfuscators), 1)
	}
}

func TestManagerDeobfuscate_NoChange(t *testing.T) {
	manager := NewManager(10)

	mock := &mockDeobfuscator{
		name:      "test",
		canDeobf:  func(s string) bool { return false },
		deobfFunc: func(s string) (string, error) { return s, nil },
	}
	manager.Register(mock)

	content := "<?php echo 'hello'; ?>"
	result, modified := manager.Deobfuscate(content)

	if modified {
		t.Error("modified = true, want false")
	}
	if result != content {
		t.Errorf("result = %q, want %q", result, content)
	}
}

func TestManagerDeobfuscate_SinglePass(t *testing.T) {
	manager := NewManager(10)

	mock := &mockDeobfuscator{
		name:     "base64_mock",
		canDeobf: func(s string) bool { return s == "ENCODED" },
		deobfFunc: func(s string) (string, error) {
			if s == "ENCODED" {
				return "DECODED", nil
			}
			return s, nil
		},
	}
	manager.Register(mock)

	result, modified := manager.Deobfuscate("ENCODED")

	if !modified {
		t.Error("modified = false, want true")
	}
	if result != "DECODED" {
		t.Errorf("result = %q, want %q", result, "DECODED")
	}
}

func TestManagerDeobfuscate_RecursivePass(t *testing.T) {
	manager := NewManager(10)

	// Simulates nested obfuscation: LAYER2 -> LAYER1 -> CLEAN
	callCount := 0
	mock := &mockDeobfuscator{
		name: "recursive_mock",
		canDeobf: func(s string) bool {
			return s == "LAYER2" || s == "LAYER1"
		},
		deobfFunc: func(s string) (string, error) {
			callCount++
			switch s {
			case "LAYER2":
				return "LAYER1", nil
			case "LAYER1":
				return "CLEAN", nil
			}
			return s, nil
		},
	}
	manager.Register(mock)

	result, modified := manager.Deobfuscate("LAYER2")

	if !modified {
		t.Error("modified = false, want true")
	}
	if result != "CLEAN" {
		t.Errorf("result = %q, want %q", result, "CLEAN")
	}
	if callCount != 2 {
		t.Errorf("callCount = %d, want %d", callCount, 2)
	}
}

func TestManagerDeobfuscate_MaxDepthLimit(t *testing.T) {
	manager := NewManager(5) // Only 5 iterations allowed

	// This deobfuscator always returns modified content (infinite loop scenario)
	callCount := 0
	mock := &mockDeobfuscator{
		name:     "infinite_mock",
		canDeobf: func(s string) bool { return true },
		deobfFunc: func(s string) (string, error) {
			callCount++
			return s + "X", nil // Always modify
		},
	}
	manager.Register(mock)

	result, modified := manager.Deobfuscate("START")

	if !modified {
		t.Error("modified = false, want true")
	}
	// Should stop at maxDepth (5 iterations)
	if callCount != 5 {
		t.Errorf("callCount = %d, want %d (maxDepth limit)", callCount, 5)
	}
	if result != "STARTXXXXX" {
		t.Errorf("result = %q, want %q", result, "STARTXXXXX")
	}
}

func TestManagerDeobfuscate_MultipleDeobfuscators(t *testing.T) {
	manager := NewManager(10)

	// First deobfuscator: handles "BASE64:" prefix
	base64Mock := &mockDeobfuscator{
		name: "base64_mock",
		canDeobf: func(s string) bool {
			return len(s) > 7 && s[:7] == "BASE64:"
		},
		deobfFunc: func(s string) (string, error) {
			return s[7:], nil // Remove prefix
		},
	}

	// Second deobfuscator: handles "GZIP:" prefix
	gzipMock := &mockDeobfuscator{
		name: "gzip_mock",
		canDeobf: func(s string) bool {
			return len(s) > 5 && s[:5] == "GZIP:"
		},
		deobfFunc: func(s string) (string, error) {
			return s[5:], nil // Remove prefix
		},
	}

	manager.Register(base64Mock)
	manager.Register(gzipMock)

	// Nested: BASE64:GZIP:CLEAN
	result, modified := manager.Deobfuscate("BASE64:GZIP:CLEAN")

	if !modified {
		t.Error("modified = false, want true")
	}
	if result != "CLEAN" {
		t.Errorf("result = %q, want %q", result, "CLEAN")
	}
}

func TestManagerDeobfuscate_EmptyContent(t *testing.T) {
	manager := NewManager(10)

	mock := &mockDeobfuscator{
		name:      "test",
		canDeobf:  func(s string) bool { return false },
		deobfFunc: func(s string) (string, error) { return s, nil },
	}
	manager.Register(mock)

	result, modified := manager.Deobfuscate("")

	if modified {
		t.Error("modified = true, want false for empty content")
	}
	if result != "" {
		t.Errorf("result = %q, want empty string", result)
	}
}
