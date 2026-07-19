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

	"dockerhunter/pkg/regex"
	"dockerhunter/pkg/types"
	"dockerhunter/pkg/validator"
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
	ImageName    string
	AllTags      bool
	Format       string // "text" or "json"
	ValidatorURL string
	BatchSize    int
}

type ScanResults struct {
	Repository      string
	ImagesScanned   int
	ImagesFailed    int
	CandidatesFound int
	Findings        []types.Candidate
	Errors          []string
}

func PerformScan(ctx context.Context, opts Options) (*ScanResults, error) {
	results := &ScanResults{
		Repository: opts.ImageName,
		Findings:   []types.Candidate{},
		Errors:     []string{},
	}

	valClient := validator.NewClient(opts.ValidatorURL)
	batchSize := opts.BatchSize
	if batchSize <= 0 {
		batchSize = 100
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
		// Single image scan mode
		ref, err := name.ParseReference(opts.ImageName)
		if err != nil {
			return nil, fmt.Errorf("failed to parse image reference %q: %w", opts.ImageName, err)
		}
		repoName = ref.Context().Name()
		
		// If tag is not specified, default to latest
		tag := "latest"
		if tRef, ok := ref.(name.Tag); ok {
			tag = tRef.TagStr()
		}
		tagsToScan = []string{tag}
	}

	results.Repository = repoName
	totalImages := len(tagsToScan)

	// 2. Scan each tag individually
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

		// Reconstruct and walk filesystem
		fmt.Printf("%s Walking filesystem...\n", imageProgressPrefix)
		squashedTree := img.SquashedTree()
		
		var imageCandidates []types.Candidate
		walkErr := squashedTree.Walk(func(path file.Path, node filenode.FileNode) error {
			if node.FileType != file.TypeRegular {
				return nil
			}

			filePath := string(path)
			if skipFile(filePath) {
				return nil
			}

			// Read and scan file contents
			fileReader, err := img.FileContentsFromSquash(path)
			if err != nil {
				// Log read errors, but do not abort walking
				return nil
			}
			defer fileReader.Close()

			scanner := bufio.NewScanner(fileReader)
			lineNum := 0
			isBin := false
			
			for scanner.Scan() {
				lineNum++
				line := scanner.Text()

				// Binary file checking on first line
				if lineNum == 1 {
					if strings.ContainsRune(line, 0) || !utf8.ValidString(line) {
						isBin = true
						break
					}
				}

				// Skip extremely long lines to avoid scanning minified files or binary blocks
				if len(line) > 10000 {
					continue
				}

				fileCandidates := regex.ExtractCandidates(repoName, tag, filePath, lineNum, line)
				if len(fileCandidates) > 0 {
					imageCandidates = append(imageCandidates, fileCandidates...)
				}
			}
			
			if isBin {
				return nil
			}

			return nil
		}, nil)

		if walkErr != nil {
			errStr := fmt.Sprintf("error walking filesystem for %s: %v", fullRef, walkErr)
			fmt.Printf("⚠️  Error: %s\n", errStr)
			results.ImagesFailed++
			results.Errors = append(results.Errors, errStr)
			img.Cleanup()
			continue
		}

		// Deduplicate candidates for this image
		uniqueCandidates := Deduplicate(imageCandidates)
		results.CandidatesFound += len(imageCandidates)
		fmt.Printf("%s %d candidates found (%d unique)\n", imageProgressPrefix, len(imageCandidates), len(uniqueCandidates))

		// Batch validate candidates
		var imageFindings []types.Candidate
		totalBatches := (len(uniqueCandidates) + batchSize - 1) / batchSize
		
		for b := 0; b < totalBatches; b++ {
			start := b * batchSize
			end := start + batchSize
			if end > len(uniqueCandidates) {
				end = len(uniqueCandidates)
			}
			
			fmt.Printf("%s Sending batch %d/%d to validator...\n", imageProgressPrefix, b+1, totalBatches)
			batch := uniqueCandidates[start:end]
			batchFindings, err := valClient.ValidateBatch(batch)
			if err != nil {
				errStr := fmt.Sprintf("batch validation failed for image %s: %v", fullRef, err)
				fmt.Printf("⚠️  Error: %s\n", errStr)
				results.Errors = append(results.Errors, errStr)
				// Continue to next batch despite failure
				continue
			}
			imageFindings = append(imageFindings, batchFindings...)
		}

		results.Findings = append(results.Findings, imageFindings...)
		results.ImagesScanned++

		// Clean up immediately after tag processing finishes
		img.Cleanup()
	}

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

// Deduplicate filters out duplicate candidates based on the composite key of:
// image, tag, file, line, variable, value.
func Deduplicate(candidates []types.Candidate) []types.Candidate {
	seen := make(map[string]bool)
	var unique []types.Candidate
	for _, c := range candidates {
		key := fmt.Sprintf("%s|%s|%s|%d|%s|%s", c.Image, c.Tag, c.File, c.Line, c.Variable, c.Value)
		if !seen[key] {
			seen[key] = true
			unique = append(unique, c)
		}
	}
	return unique
}
