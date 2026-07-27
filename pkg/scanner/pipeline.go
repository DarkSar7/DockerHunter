package scanner

import (
	"fmt"
	"sync"
	"time"

	"github.com/DarkSar7/DockerHunter/pkg/regex"
	"github.com/DarkSar7/DockerHunter/pkg/types"
	"github.com/DarkSar7/DockerHunter/pkg/validator"
)

type Pipeline struct {
	candidateChan          chan types.Candidate
	validatedCandidateChan chan types.Candidate
	batchChan              chan []types.Candidate
	resultChan             chan []types.Finding
	validator              validator.Validator
	rules                  *regex.CompiledRules
	workerCount            int
	batchSize              int
	batchTimeout           time.Duration
	wgWorkers              sync.WaitGroup
	wgPipeline             sync.WaitGroup
	findings               []types.Finding
	preAICandidates        []types.Candidate
	errors                 []string
	collectPre             bool
	mu                     sync.Mutex
}

func NewPipeline(val validator.Validator, rules *regex.CompiledRules, workerCount, batchSize, timeoutMs int) *Pipeline {
	if workerCount <= 0 {
		workerCount = 8
	}
	if batchSize <= 0 {
		batchSize = 100
	}
	timeout := time.Duration(timeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = 200 * time.Millisecond
	}

	return &Pipeline{
		candidateChan:          make(chan types.Candidate, 5000),
		validatedCandidateChan: make(chan types.Candidate, 5000),
		batchChan:              make(chan []types.Candidate, 500),
		resultChan:             make(chan []types.Finding, 500),
		validator:              val,
		rules:                  rules,
		workerCount:            workerCount,
		batchSize:              batchSize,
		batchTimeout:           timeout,
		preAICandidates:        []types.Candidate{},
		errors:                 []string{},
	}
}

// SetCollectPre enables or disables collecting pre-AI validation candidates.
func (p *Pipeline) SetCollectPre(collect bool) {
	p.collectPre = collect
}

// Start boots background goroutines for the pipeline.
func (p *Pipeline) Start() {
	// 1. Start Regex validation workers
	for i := 0; i < p.workerCount; i++ {
		p.wgWorkers.Add(1)
		go p.workerRegexValidation()
	}

	// Spawn closer for validated candidate stream
	go func() {
		p.wgWorkers.Wait()
		close(p.validatedCandidateChan)
	}()

	// 2. Start Batch Builder
	p.wgPipeline.Add(1)
	go p.workerBatchBuilder()

	// 3. Start Python Validator Caller
	p.wgPipeline.Add(1)
	go p.workerValidatorCaller()

	// 4. Start Results Collector
	p.wgPipeline.Add(1)
	go p.collectFindings()
}

// Push adds a generic candidate to the pipeline.
func (p *Pipeline) Push(c types.Candidate) {
	p.candidateChan <- c
}

// Close tells the pipeline that extraction has completed and blocks until all results are gathered.
func (p *Pipeline) Close() ([]types.Finding, []types.Candidate, []string) {
	close(p.candidateChan)
	p.wgPipeline.Wait()

	p.mu.Lock()
	defer p.mu.Unlock()
	return p.findings, p.preAICandidates, p.errors
}

func (p *Pipeline) workerRegexValidation() {
	defer p.wgWorkers.Done()
	for c := range p.candidateChan {
		if regex.MatchRules(c.Variable, c.Value, c.Context, p.rules) {
			p.validatedCandidateChan <- c
		}
	}
}

func (p *Pipeline) workerBatchBuilder() {
	defer p.wgPipeline.Done()
	defer close(p.batchChan)

	var batch []types.Candidate
	ticker := time.NewTicker(p.batchTimeout)
	defer ticker.Stop()

	for {
		select {
		case c, ok := <-p.validatedCandidateChan:
			if !ok {
				if len(batch) > 0 {
					p.batchChan <- batch
				}
				return
			}
			if p.collectPre {
				p.preAICandidates = append(p.preAICandidates, c)
			}
			batch = append(batch, c)
			if len(batch) >= p.batchSize {
				p.batchChan <- batch
				batch = nil
				ticker.Reset(p.batchTimeout)
			}
		case <-ticker.C:
			if len(batch) > 0 {
				p.batchChan <- batch
				batch = nil
			}
		}
	}
}

func (p *Pipeline) workerValidatorCaller() {
	defer p.wgPipeline.Done()
	defer close(p.resultChan)

	for batch := range p.batchChan {
		findings, err := p.validator.Validate(batch)
		if err != nil {
			p.mu.Lock()
			p.errors = append(p.errors, fmt.Sprintf("AI Validation error on batch: %v", err))
			p.mu.Unlock()
			continue
		}
		p.resultChan <- findings
	}
}

func (p *Pipeline) collectFindings() {
	defer p.wgPipeline.Done()
	for res := range p.resultChan {
		p.mu.Lock()
		p.findings = append(p.findings, res...)
		p.mu.Unlock()
	}
}
