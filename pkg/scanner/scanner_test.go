package scanner

import (
	"testing"

	"dockerhunter/pkg/types"
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
			Tag:      "sha-2", // Different tag
			File:     "/app/config.py",
			Line:     42,
			Variable: "API_KEY",
			Value:    "secret1", // Unique because tag differs
		},
		{
			Image:    "lyft/clutch",
			Tag:      "sha-1",
			File:     "/app/db.go", // Different file
			Line:     12,
			Variable: "DB_PASS",
			Value:    "secret2",
		},
	}

	unique := Deduplicate(candidates)
	if len(unique) != 3 {
		t.Errorf("Deduplicate() returned %d elements, want 3", len(unique))
	}

	// Verify that the duplicate was removed and others were kept
	tagCount := make(map[string]int)
	for _, c := range unique {
		tagCount[c.Tag]++
	}
	if tagCount["sha-1"] != 2 {
		t.Errorf("expected 2 candidates under tag sha-1, got %d", tagCount["sha-1"])
	}
	if tagCount["sha-2"] != 1 {
		t.Errorf("expected 1 candidate under tag sha-2, got %d", tagCount["sha-2"])
	}
}
