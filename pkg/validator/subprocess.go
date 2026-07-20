package validator

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"sync"
	"time"

	"github.com/DarkSar7/DockerHunter/pkg/types"
)

type SubprocessValidator struct {
	cmd        *exec.Cmd
	stdinPipe  io.WriteCloser
	stdoutScan *bufio.Scanner
	mu         sync.Mutex
}

func NewSubprocessValidator(pythonExe, scriptPath string) (*SubprocessValidator, error) {
	cmd := exec.Command(pythonExe, scriptPath)

	stdinPipe, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to open stdin pipe: %w", err)
	}

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to open stdout pipe: %w", err)
	}

	// We let standard error pass through to parent stderr for debugging visibility
	cmd.Stderr = nil

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start python subprocess: %w", err)
	}

	return &SubprocessValidator{
		cmd:        cmd,
		stdinPipe:  stdinPipe,
		stdoutScan: bufio.NewScanner(stdoutPipe),
	}, nil
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

func (v *SubprocessValidator) Validate(candidates []types.Candidate) ([]types.Finding, error) {
	if len(candidates) == 0 {
		return nil, nil
	}

	v.mu.Lock()
	defer v.mu.Unlock()

	req := ValidateRequest{Candidates: candidates}
	bytes, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// Write request line to python stdin
	if _, err := fmt.Fprintf(v.stdinPipe, "%s\n", string(bytes)); err != nil {
		return nil, fmt.Errorf("failed to write to python stdin: %w", err)
	}

	// Read response line from python stdout
	if !v.stdoutScan.Scan() {
		err := v.stdoutScan.Err()
		if err == nil {
			err = io.EOF
		}
		return nil, fmt.Errorf("failed to read from python stdout: %w", err)
	}

	respLine := v.stdoutScan.Text()
	var resp ValidateResponse
	if err := json.Unmarshal([]byte(respLine), &resp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal python response: %w (raw response: %s)", err, respLine)
	}

	var findings []types.Finding
	for _, res := range resp.Results {
		if res.Valid {
			findings = append(findings, types.Finding{
				Image:    res.Candidate.Image,
				Tag:      res.Candidate.Tag,
				File:     res.Candidate.File,
				Line:     res.Candidate.Line,
				Variable: res.Candidate.Variable,
				Value:    res.Candidate.Value,
				Context:  res.Candidate.Context,
			})
		}
	}

	return findings, nil
}

func (v *SubprocessValidator) Close() error {
	v.mu.Lock()
	defer v.mu.Unlock()

	if v.stdinPipe != nil {
		_ = v.stdinPipe.Close() // Sends EOF to python process
	}

	// Wait with timeout
	done := make(chan error, 1)
	go func() {
		done <- v.cmd.Wait()
	}()

	select {
	case err := <-done:
		return err
	case <-time.After(5 * time.Second):
		// Force kill if it doesn't exit cleanly
		_ = v.cmd.Process.Kill()
		return fmt.Errorf("subprocess did not exit cleanly within 5s and was killed")
	}
}
