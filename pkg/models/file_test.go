package models

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestFileContentNotSerialized guards against report bloat: File.Content holds
// the full in-memory file body and must never be marshaled into JSON reports.
func TestFileContentNotSerialized(t *testing.T) {
	f := File{
		Path:    "/var/www/html/shell.php",
		Name:    "shell.php",
		Size:    1024,
		Content: []byte("SECRET_FILE_BODY_THAT_MUST_NOT_LEAK"),
		Hash:    "deadbeef",
	}

	data, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	out := string(data)

	if strings.Contains(out, "SECRET_FILE_BODY_THAT_MUST_NOT_LEAK") {
		t.Errorf("File.Content leaked into JSON: %s", out)
	}
	if strings.Contains(out, "\"Content\"") {
		t.Errorf("Content key present in JSON: %s", out)
	}
	// Other fields must still serialize so reports stay useful.
	for _, want := range []string{"/var/www/html/shell.php", "shell.php", "deadbeef"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in JSON, got: %s", want, out)
		}
	}
}
