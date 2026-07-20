package scanner

import (
	"testing"

	"github.com/DarkSar7/DockerHunter/pkg/types"
)

func TestDeduplicate(t *testing.T) {
	candidates := []types.Candidate{
		{
			Image:    "lyft/clutch",
			Tag:      "sha-1",
			File:     "/app/config.py",
			Line:     42,
			Variable: "API_KEY",
			Value:    "secret1",
		},
		{
			Image:    "lyft/clutch",
			Tag:      "sha-1",
			File:     "/app/config.py",
			Line:     42,
			Variable: "API_KEY",
			Value:    "secret1", // Duplicate
		},
		{
			Image:    "lyft/clutch",
			Tag:      "sha-2", // Different tag, but same file, line, var, and value
			File:     "/app/config.py",
			Line:     42,
			Variable: "API_KEY",
			Value:    "secret1", // Duplicate under refactored rules
		},
		{
			Image:    "lyft/clutch",
			Tag:      "sha-1",
			File:     "/app/db.go",
			Line:     12,
			Variable: "DB_PASS",
			Value:    "secret2", // Unique
		},
	}

	unique := Deduplicate(candidates)
	if len(unique) != 2 {
		t.Errorf("Deduplicate() returned %d elements, want 2", len(unique))
	}

	// Verify the remaining candidates are correct
	hasConfigKey := false
	hasDbPass := false
	for _, c := range unique {
		if c.Variable == "API_KEY" && c.Value == "secret1" && c.File == "/app/config.py" && c.Line == 42 {
			hasConfigKey = true
		}
		if c.Variable == "DB_PASS" && c.Value == "secret2" && c.File == "/app/db.go" && c.Line == 12 {
			hasDbPass = true
		}
	}

	if !hasConfigKey {
		t.Error("missing expected unique candidate for API_KEY")
	}
	if !hasDbPass {
		t.Error("missing expected unique candidate for DB_PASS")
	}
}
