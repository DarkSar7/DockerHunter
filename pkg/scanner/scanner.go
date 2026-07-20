package scanner

import (
	"bufio"
	"context"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/anchore/stereoscope"
	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/filetree/filenode"
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/DarkSar7/DockerHunter/pkg/config"
	"github.com/DarkSar7/DockerHunter/pkg/regex"
	"github.com/DarkSar7/DockerHunter/pkg/types"
	"github.com/DarkSar7/DockerHunter/pkg/validator"
)

var (
	blackListDirs = []string{
		"/node_modules",
		"/vendor",
		"/.git",
		"/.idea",
		"yarn",
		"/package-lock.json",
		"/dist",
		"/locales/",
		"/locale/",
		"/components",
		"/server/data",
		"/.cache",
	}

	blackListExtensions = []string{
		".png",
		".jpg",
		".jpeg",
		".gif",
		".svg",
		".ico",
		".pak",
		".bin",
		".pdf",
		".css",
		".zip",
		".tar",
		".gz",
		".bz2",
		".rar",
		".7z",
		".wim",
		".iso",
		".dmg",
	}
)

type Options struct {
	ImageName string
	AllTags   bool
	Format    string
}

type ScanResults struct {
	Repository      string
	ImagesScanned   int
	ImagesFailed    int
	CandidatesFound int
	Findings        []types.Finding
	Errors          []string
}

func PerformScan(ctx context.Context, opts Options, cfg *config.Config, rRules *config.RegexRules, val validator.Validator) (*ScanResults, error) {
	results := &ScanResults{
		Repository: opts.ImageName,
		Findings:   []types.Finding{},
		Errors:     []string{},
	}

	// 1. Resolve tags to scan
	var tagsToScan []string
	var repoName string

	if opts.AllTags {
		repo, err := name.NewRepository(opts.ImageName)
		if err != nil {
			return nil, fmt.Errorf("failed to parse repository name %q: %w", opts.ImageName, err)
		}
		repoName = repo.Name()

		fmt.Println("Fetching tags from registry...")
		tags, err := remote.List(repo, remote.WithAuthFromKeychain(authn.DefaultKeychain))
		if err != nil {
			return nil, fmt.Errorf("failed to list repository tags: %w", err)
		}
		tagsToScan = tags
		if len(tagsToScan) == 0 {
			return nil, fmt.Errorf("no tags found for repository %q", opts.ImageName)
		}
	} else {
		ref, err := name.ParseReference(opts.ImageName)
		if err != nil {
			return nil, fmt.Errorf("failed to parse image reference %q: %w", opts.ImageName, err)
		}
		repoName = ref.Context().Name()
		tag := "latest"
		if tRef, ok := ref.(name.Tag); ok {
			tag = tRef.TagStr()
		}
		tagsToScan = []string{tag}
	}

	results.Repository = repoName
	totalImages := len(tagsToScan)

	// Pre-compile rules database
	compiledRules := regex.CompileRules(rRules)

	// Initialize pipeline
	pipeline := NewPipeline(
		val,
		compiledRules,
		cfg.Pipeline.WorkerCount,
		cfg.Pipeline.BatchSize,
		cfg.Pipeline.BatchTimeoutMs,
	)
	pipeline.Start()

	// Inline Deduplication Map (unique var+value+file+line)
	seen := make(map[string]bool)

	// 2. Scan each tag sequentially
	for idx, tag := range tagsToScan {
		imageProgressPrefix := fmt.Sprintf("[%d/%d]", idx+1, totalImages)
		fullRef := fmt.Sprintf("%s:%s", repoName, tag)

		fmt.Printf("%s Pulling %s...\n", imageProgressPrefix, fullRef)
		img, err := stereoscope.GetImageFromSource(ctx, fullRef, image.OciRegistrySource)
		if err != nil {
			errStr := fmt.Sprintf("failed to download image %s: %v", fullRef, err)
			fmt.Printf("⚠️  Error: %s\n", errStr)
			results.ImagesFailed++
			results.Errors = append(results.Errors, errStr)
			continue
		}

		// Reconstruct and scan filesystem (safely wrapped to guarantee immediate cleanup)
		func() {
			defer img.Cleanup()

			fmt.Printf("%s Walking filesystem...\n", imageProgressPrefix)
			squashedTree := img.SquashedTree()
			
			_ = squashedTree.Walk(func(path file.Path, node filenode.FileNode) error {
				if node.FileType != file.TypeRegular {
					return nil
				}

				filePath := string(path)
				if skipFile(filePath) {
					return nil
				}

				fileReader, err := img.FileContentsFromSquash(path)
				if err != nil {
					return nil
				}
				defer fileReader.Close()

				scanner := bufio.NewScanner(fileReader)
				lineNum := 0
				isBin := false
				
				for scanner.Scan() {
					lineNum++
					line := scanner.Text()

					if lineNum == 1 {
						if strings.ContainsRune(line, 0) || !utf8.ValidString(line) {
							isBin = true
							break
						}
					}

					if len(line) > 10000 {
						continue
					}

					fileCandidates := regex.ExtractCandidates(repoName, tag, filePath, lineNum, line)
					for _, c := range fileCandidates {
						results.CandidatesFound++

						// Deduplicate immediately after generic extraction
						key := fmt.Sprintf("%s|%s|%s|%d", c.Variable, c.Value, c.File, c.Line)
						if !seen[key] {
							seen[key] = true
							pipeline.Push(c)
						}
					}
				}
				
				if isBin {
					return nil
				}

				return nil
			}, nil)
		}()
		
		results.ImagesScanned++
	}

	// Close the pipeline and collect findings
	findings := pipeline.Close()
	results.Findings = findings

	return results, nil
}

func skipFile(filePath string) bool {
	for _, bl := range blackListDirs {
		if strings.Contains(filePath, bl) {
			return true
		}
	}
	for _, ext := range blackListExtensions {
		if strings.HasSuffix(filePath, ext) {
			return true
		}
	}
	return false
}

// Deduplicate filters out duplicate candidates based on variable, value, file, and line.
func Deduplicate(candidates []types.Candidate) []types.Candidate {
	seen := make(map[string]bool)
	var unique []types.Candidate
	for _, c := range candidates {
		key := fmt.Sprintf("%s|%s|%s|%d", c.Variable, c.Value, c.File, c.Line)
		if !seen[key] {
			seen[key] = true
			unique = append(unique, c)
		}
	}
	return unique
}
