package regex

import (
	"testing"

	"github.com/DarkSar7/DockerHunter/pkg/config"
)

func TestExtractCandidates(t *testing.T) {
	tests := []struct {
		name       string
		context    string
		wantVar    string
		wantVal    string
		wantLength int
	}{
		{
			name:       "Standard assignment",
			context:    `api_key = "my_secret_token"`,
			wantVar:    "api_key",
			wantVal:    "my_secret_token",
			wantLength: 1,
		},
		{
			name:       "Colon separator",
			context:    `password: 'supersecret'`,
			wantVar:    "password",
			wantVal:    "supersecret",
			wantLength: 1,
		},
		{
			name:       "Arrow separator",
			context:    `"aws_secret_key"=>"AWS1234567890"`,
			wantVar:    "aws_secret_key",
			wantVal:    "AWS1234567890",
			wantLength: 1,
		},
		{
			name:       "Non-matching string",
			context:    `import os`,
			wantVar:    "",
			wantVal:    "",
			wantLength: 0,
		},
		{
			name:       "Empty value string",
			context:    `api_key = ""`,
			wantVar:    "",
			wantVal:    "",
			wantLength: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			candidates := ExtractCandidates("test-image", "latest", "config.py", 10, tt.context)
			if len(candidates) != tt.wantLength {
				t.Errorf("ExtractCandidates() len = %d, want %d", len(candidates), tt.wantLength)
				return
			}
			if tt.wantLength > 0 {
				got := candidates[0]
				if got.Variable != tt.wantVar {
					t.Errorf("got.Variable = %q, want %q", got.Variable, tt.wantVar)
				}
				if got.Value != tt.wantVal {
					t.Errorf("got.Value = %q, want %q", got.Value, tt.wantVal)
				}
				if got.Context != tt.context {
					t.Errorf("got.Context = %q, want %q", got.Context, tt.context)
				}
			}
		})
	}
}

func TestMatchRulePrefersSensitiveSignature(t *testing.T) {
	rules := &config.RegexRules{Signatures: []config.Signature{
		{Pattern: config.PatternDetail{Name: "Generic Token", Sensitive: false, Value: `(?i)api[_-]?key`}},
		{Pattern: config.PatternDetail{Name: "Google API Key", Sensitive: true, Value: `AIza[0-9A-Za-z_-]{35}`}},
	}}

	sig, matched := MatchRule(
		"GOOGLE_MAP_KEY",
		"AIzaSyBHL-BOb3Vy_bQE9xJ4EWD2ga0zv0x_VOk",
		`"GOOGLE_MAP_KEY": "AIzaSyBHL-BOb3Vy_bQE9xJ4EWD2ga0zv0x_VOk"`,
		CompileRules(rules),
	)
	if !matched {
		t.Fatal("expected second-stage signature match")
	}
	if sig.Name != "Google API Key" || !sig.Sensitive {
		t.Fatalf("got signature %#v; want sensitive Google API Key", sig)
	}
}
