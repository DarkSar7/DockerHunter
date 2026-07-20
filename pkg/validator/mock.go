package validator

import (
	"strings"

	"github.com/DarkSar7/DockerHunter/pkg/types"
)

type MockValidator struct {
	Classifier func(c types.Candidate) bool
}

func NewMockValidator() *MockValidator {
	return &MockValidator{
		Classifier: func(c types.Candidate) bool {
			val := strings.ToLower(c.Value)
			return !strings.Contains(val, "placeholder") && !strings.Contains(val, "your_")
		},
	}
}

func (m *MockValidator) Validate(candidates []types.Candidate) ([]types.Finding, error) {
	var findings []types.Finding
	for _, c := range candidates {
		if m.Classifier(c) {
			findings = append(findings, types.Finding{
				Image:    c.Image,
				Tag:      c.Tag,
				File:     c.File,
				Line:     c.Line,
				Variable: c.Variable,
				Value:    c.Value,
				Context:  c.Context,
			})
		}
	}
	return findings, nil
}

func (m *MockValidator) Close() error {
	return nil
}
