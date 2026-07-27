package validator

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/DarkSar7/DockerHunter/pkg/types"
)

func TestSubprocessValidator(t *testing.T) {
	// Create a temp directory for the mock Python script
	tempDir, err := os.MkdirTemp("", "dockerhunter-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	mockScript := filepath.Join(tempDir, "mock_main.py")
	scriptContent := `import sys
import json

while True:
    line = sys.stdin.readline()
    if not line:
        break
    req = json.loads(line)
    results = []
    for c in req.get('candidates', []):
        results.append({
            'candidate': c,
            'valid': 'secret' in c.get('value', '').lower()
        })
    print(json.dumps({'batch_id': req.get('batch_id', ''), 'results': results}))
    sys.stdout.flush()
`
	if err := os.WriteFile(mockScript, []byte(scriptContent), 0644); err != nil {
		t.Fatalf("failed to write mock script: %v", err)
	}

	val, err := NewSubprocessValidator("python3", mockScript)
	if err != nil {
		t.Fatalf("failed to start subprocess: %v", err)
	}
	defer val.Close()

	candidates := []types.Candidate{
		{Image: "test", Tag: "1.0", File: "a.py", Line: 10, Variable: "key", Value: "my_secret_key"},
		{Image: "test", Tag: "1.0", File: "a.py", Line: 20, Variable: "pass", Value: "placeholder"},
	}

	findings, err := val.Validate(candidates)
	if err != nil {
		t.Fatalf("validation failed: %v", err)
	}

	if len(findings) != 1 {
		t.Errorf("expected 1 finding, got %d", len(findings))
	} else {
		got := findings[0]
		if got.Value != "my_secret_key" {
			t.Errorf("expected finding value 'my_secret_key', got %s", got.Value)
		}
	}
}
