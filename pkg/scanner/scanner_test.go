package scanner

import (
	"testing"

	"github.com/DarkSar7/DockerHunter/pkg/config"
	"github.com/DarkSar7/DockerHunter/pkg/regex"
	"github.com/DarkSar7/DockerHunter/pkg/types"
	"github.com/DarkSar7/DockerHunter/pkg/validator"
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

func TestPipelineUsesSignatureStageBeforeAI(t *testing.T) {
	rules := regex.CompileRules(&config.RegexRules{Signatures: []config.Signature{
		{Pattern: config.PatternDetail{Name: "Generic Token", Sensitive: false, Value: `(?i)token`}},
		{Pattern: config.PatternDetail{Name: "Google API Key", Sensitive: true, Value: `AIza[0-9A-Za-z_-]{35}`}},
	}})
	pipeline := NewPipeline(validator.NewMockValidator(), rules, 1, 10, 10)
	pipeline.SetCollectPre(true)
	pipeline.Start()
	pipeline.Push(types.Candidate{Variable: "API_TOKEN", Value: "live_token_value", Context: `API_TOKEN="live_token_value"`})
	pipeline.Push(types.Candidate{Variable: "GOOGLE_MAP_KEY", Value: "AIzaSyBHL-BOb3Vy_bQE9xJ4EWD2ga0zv0x_VOk", Context: `GOOGLE_MAP_KEY="AIzaSyBHL-BOb3Vy_bQE9xJ4EWD2ga0zv0x_VOk"`})

	findings, pre, errs, stats := pipeline.Close()
	if len(errs) != 0 {
		t.Fatalf("unexpected pipeline errors: %v", errs)
	}
	if stats.GenericCandidates != 2 || stats.SignatureMatches != 2 || len(pre) != 2 {
		t.Fatalf("two regex stages were not recorded correctly: stats=%+v pre=%d", stats, len(pre))
	}
	if stats.SentToAI != 1 || stats.StrongRegexFindings != 1 {
		t.Fatalf("expected one AI candidate and one high-confidence regex finding: %+v", stats)
	}
	if len(findings) != 2 {
		t.Fatalf("got %d findings, want 2", len(findings))
	}

	for _, finding := range findings {
		if finding.Variable == "GOOGLE_MAP_KEY" && finding.ValidationSource != "signature-regex" {
			t.Fatalf("Google key used %q; want signature-regex", finding.ValidationSource)
		}
	}
}
