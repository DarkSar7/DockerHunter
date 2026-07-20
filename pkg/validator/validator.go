package validator

import (
	"github.com/DarkSar7/DockerHunter/pkg/types"
)

type Validator interface {
	// Validate checks a batch of candidates and returns the validated findings.
	Validate(candidates []types.Candidate) ([]types.Finding, error)
	// Close terminates the validator subprocess or client.
	Close() error
}
