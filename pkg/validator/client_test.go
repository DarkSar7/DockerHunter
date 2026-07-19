package validator

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"dockerhunter/pkg/types"
)

func TestClientValidateBatch(t *testing.T) {
	// Create mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/validate" {
			t.Errorf("expected request path to be /validate, got %s", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Errorf("expected POST request, got %s", r.Method)
		}

		var req ValidateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// Prepare mock response: classify first candidate as valid, second as invalid
		var results []ValidationResult
		for idx, c := range req.Candidates {
			results = append(results, ValidationResult{
				Candidate: c,
				Valid:     idx == 0, // only first one is valid
			})
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(ValidateResponse{Results: results})
	}))
	defer server.Close()

	client := NewClient(server.URL)
	candidates := []types.Candidate{
		{Image: "test", Tag: "1.0", File: "a.go", Line: 1, Variable: "V1", Value: "val1", Context: "context1"},
		{Image: "test", Tag: "1.0", File: "a.go", Line: 2, Variable: "V2", Value: "val2", Context: "context2"},
	}

	findings, err := client.ValidateBatch(candidates)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(findings) != 1 {
		t.Errorf("expected 1 finding, got %d", len(findings))
	} else {
		got := findings[0]
		if got.Value != "val1" {
			t.Errorf("expected finding value to be 'val1', got %s", got.Value)
		}
	}
}
