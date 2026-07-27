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
	pythonExe  string
	scriptPath string
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

	scanner := bufio.NewScanner(stdoutPipe)
	scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024)

	return &SubprocessValidator{
		cmd:        cmd,
		stdinPipe:  stdinPipe,
		stdoutScan: scanner,
		pythonExe:  pythonExe,
		scriptPath: scriptPath,
	}, nil
}

func (v *SubprocessValidator) restart() error {
	if v.stdinPipe != nil {
		_ = v.stdinPipe.Close()
	}
	if v.cmd != nil && v.cmd.Process != nil {
		_ = v.cmd.Process.Kill()
		_ = v.cmd.Wait() // Reclaim process resources
	}

	cmd := exec.Command(v.pythonExe, v.scriptPath)
	stdinPipe, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("failed to reopen stdin pipe on restart: %w", err)
	}

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("failed to reopen stdout pipe on restart: %w", err)
	}

	cmd.Stderr = nil

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to restart python subprocess: %w", err)
	}

	scanner := bufio.NewScanner(stdoutPipe)
	scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024)

	v.cmd = cmd
	v.stdinPipe = stdinPipe
	v.stdoutScan = scanner
	return nil
}

type ValidateRequest struct {
	BatchID    string            `json:"batch_id"`
	Candidates []types.Candidate `json:"candidates"`
}

type ValidationResult struct {
	Candidate types.Candidate `json:"candidate"`
	Valid     bool            `json:"valid"`
}

type ValidateResponse struct {
	BatchID string             `json:"batch_id"`
	Results []ValidationResult `json:"results"`
}

func (v *SubprocessValidator) Validate(candidates []types.Candidate) ([]types.Finding, error) {
	if len(candidates) == 0 {
		return nil, nil
	}

	v.mu.Lock()
	defer v.mu.Unlock()

	batchID := fmt.Sprintf("%d", time.Now().UnixNano())
	req := ValidateRequest{BatchID: batchID, Candidates: candidates}
	bytes, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// Write request line to python stdin
	if _, err := fmt.Fprintf(v.stdinPipe, "%s\n", string(bytes)); err != nil {
		restartErr := v.restart()
		if restartErr != nil {
			return nil, fmt.Errorf("failed to write to python stdin: %w (restart failed: %v)", err, restartErr)
		}
		if _, errRetry := fmt.Fprintf(v.stdinPipe, "%s\n", string(bytes)); errRetry != nil {
			return nil, fmt.Errorf("failed to write to python stdin after restart: %w", errRetry)
		}
	}

	// Read response line from python stdout
	if !v.stdoutScan.Scan() {
		scanErr := v.stdoutScan.Err()
		if scanErr == nil {
			scanErr = io.EOF
		}
		restartErr := v.restart()
		return nil, fmt.Errorf("failed to read from python stdout: %w (restart status: %v)", scanErr, restartErr)
	}

	respLine := v.stdoutScan.Text()
	var resp ValidateResponse
	if err := json.Unmarshal([]byte(respLine), &resp); err != nil {
		restartErr := v.restart()
		return nil, fmt.Errorf("failed to unmarshal python response: %w (raw response: %s, restart status: %v)", err, respLine, restartErr)
	}

	if resp.BatchID != batchID {
		restartErr := v.restart()
		return nil, fmt.Errorf("batch ID desync: expected %s, got %s (restart status: %v)", batchID, resp.BatchID, restartErr)
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
		_ = v.cmd.Process.Kill()
		return fmt.Errorf("subprocess did not exit cleanly within 5s and was killed")
	}
}
