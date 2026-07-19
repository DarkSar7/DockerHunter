package validator

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"dockerhunter/pkg/types"
)

type Client struct {
	BaseURL    string
	HTTPClient *http.Client
}

// NewClient returns a new validator client. BaseURL defaults to http://localhost:9001.
func NewClient(baseURL string) *Client {
	if baseURL == "" {
		baseURL = "http://localhost:9001"
	}
	return &Client{
		BaseURL: baseURL,
		HTTPClient: &http.Client{
			Timeout: 90 * time.Second, // StarPII model inference can take longer for large batches
		},
	}
}

type ValidateRequest struct {
	Candidates []types.Candidate `json:"candidates"`
}

type ValidationResult struct {
	Candidate types.Candidate `json:"candidate"`
	Valid     bool            `json:"valid"`
}

type ValidateResponse struct {
	Results []ValidationResult `json:"results"`
}

// ValidateBatch sends a batch of candidates to the AI validator and returns the ones classified as valid.
func (c *Client) ValidateBatch(candidates []types.Candidate) ([]types.Candidate, error) {
	if len(candidates) == 0 {
		return nil, nil
	}

	reqBody := ValidateRequest{Candidates: candidates}
	jsonBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	url := c.BaseURL + "/validate"
	resp, err := c.HTTPClient.Post(url, "application/json", bytes.NewBuffer(jsonBytes))
	if err != nil {
		return nil, fmt.Errorf("HTTP post failed to %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("validator returned non-200 status code: %d", resp.StatusCode)
	}

	var valResp ValidateResponse
	if err := json.NewDecoder(resp.Body).Decode(&valResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	var findings []types.Candidate
	for _, res := range valResp.Results {
		if res.Valid {
			findings = append(findings, res.Candidate)
		}
	}
	return findings, nil
}
