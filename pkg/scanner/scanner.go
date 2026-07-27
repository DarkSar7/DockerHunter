package scanner

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/Masterminds/semver/v3"
	"github.com/anchore/stereoscope"
	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/filetree/filenode"
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"

	"github.com/DarkSar7/DockerHunter/pkg/auth"
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
	Pre       bool
	MaxTags   int
	Since     string
	Latest    int
	Semver    string
}

type ScanResults struct {
	Repository      string
	ImagesScanned   int
	ImagesFailed    int
	CandidatesFound int
	Findings        []types.Finding
	Errors          []string
}

func PerformScan(ctx context.Context, opts Options, cfg *config.Config, rRules *config.RegexRules, val validator.Validator, authManager *auth.AuthManager) (*ScanResults, error) {
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

		registry := repo.RegistryStr()
		numAccounts := len(authManager.GetAccountsStats(registry))
		maxRetries := numAccounts
		if maxRetries <= 0 {
			maxRetries = 0
		}

		fmt.Println("Fetching tags from registry...")
		
		var tags []string
		for attempt := 0; attempt <= maxRetries; attempt++ {
			a, username, authErr := authManager.GetAuthenticator(registry)
			if authErr != nil {
				return nil, authErr
			}

			optsList := getRemoteOptions(authManager, a)
			tags, err = remote.List(repo, optsList...)
			if err != nil {
				if isRateLimitError(err) && username != "" {
					authManager.ReportRateLimit(registry, username, 0)
					continue
				}
				return nil, fmt.Errorf("failed to list repository tags: %w", err)
			}
			break
		}
		
		tagsToScan = tags
		if len(tagsToScan) == 0 {
			return nil, fmt.Errorf("no tags found for repository %q", opts.ImageName)
		}

		// Apply Semver constraint filter
		if opts.Semver != "" {
			fmt.Printf("Filtering tags by semver constraint %q...\n", opts.Semver)
			tagsToScan = filterSemver(tagsToScan, opts.Semver)
		}

		// Apply Timestamp filters (Since and/or Latest)
		if opts.Since != "" || opts.Latest > 0 {
			var tagMeta []tagWithTime
			var fetched bool

			// Try Docker Hub API directly if repository is on Docker Hub
			parts := strings.Split(repoName, "/")
			if len(parts) >= 2 && (parts[0] == "index.docker.io" || parts[0] == "docker.io") {
				namespace := "library"
				nameStr := parts[len(parts)-1]
				if len(parts) == 3 {
					namespace = parts[1]
				}
				fmt.Printf("Fetching tags from Docker Hub API for %s/%s...\n", namespace, nameStr)
				meta, err := fetchDockerHubTags(namespace, nameStr, authManager)
				if err == nil {
					// Keep only the tags in tagsToScan
					tagSet := make(map[string]bool)
					for _, t := range tagsToScan {
						tagSet[t] = true
					}
					for _, tm := range meta {
						if tagSet[tm.tag] {
							tagMeta = append(tagMeta, tm)
						}
					}
					fetched = true
					fmt.Printf("✓ Successfully fetched %d sorted tags from Docker Hub API.\n", len(tagMeta))
				} else {
					fmt.Printf("⚠️  Docker Hub API call failed: %v. Falling back to OCI configuration queries.\n", err)
				}
			}

			if !fetched {
				tagMeta = fetchTagsCreationTimes(repoName, tagsToScan, authManager)
			}
			
			// Sort tags by creation time descending (newest first)
			sort.Slice(tagMeta, func(i, j int) bool {
				return tagMeta[i].created.After(tagMeta[j].created)
			})

			// Filter by Since Date
			if opts.Since != "" {
				sinceTime, err := parseSince(opts.Since)
				if err != nil {
					return nil, err
				}
				fmt.Printf("Filtering tags created since %s...\n", sinceTime.Format("2006-01-02"))
				var sinceTags []tagWithTime
				for _, tm := range tagMeta {
					if tm.created.After(sinceTime) || tm.created.Equal(sinceTime) {
						sinceTags = append(sinceTags, tm)
					}
				}
				tagMeta = sinceTags
			}

			// Filter by Latest N count
			if opts.Latest > 0 && opts.Latest < len(tagMeta) {
				fmt.Printf("Filtering to top %d latest tags...\n", opts.Latest)
				tagMeta = tagMeta[:opts.Latest]
			}

			// Reconstruct tagsToScan
			tagsToScan = make([]string, len(tagMeta))
			for i, tm := range tagMeta {
				tagsToScan[i] = tm.tag
			}
		}

		// Apply Max Tags cap
		if opts.MaxTags > 0 && opts.MaxTags < len(tagsToScan) {
			fmt.Printf("Capping scan list to %d tags (max-tags limit)...\n", opts.MaxTags)
			tagsToScan = tagsToScan[:opts.MaxTags]
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
	pipeline.SetCollectPre(opts.Pre)
	pipeline.Start()

	// Inline Deduplication Map (unique var+value+file+line)
	seen := make(map[string]bool)

	// 2. Scan each tag sequentially
	for idx, tag := range tagsToScan {
		imageProgressPrefix := fmt.Sprintf("[%d/%d]", idx+1, totalImages)
		fullRef := fmt.Sprintf("%s:%s", repoName, tag)

		fmt.Printf("%s Pulling %s...\n", imageProgressPrefix, fullRef)

		ref, err := name.ParseReference(fullRef)
		if err != nil {
			errStr := fmt.Sprintf("failed to parse reference %s: %v", fullRef, err)
			results.ImagesFailed++
			results.Errors = append(results.Errors, errStr)
			continue
		}
		registry := ref.Context().RegistryStr()

		numAccounts := len(authManager.GetAccountsStats(registry))
		maxRetries := numAccounts
		if maxRetries <= 0 {
			maxRetries = 0
		}

		var img *image.Image
		for attempt := 0; attempt <= maxRetries; attempt++ {
			a, username, authErr := authManager.GetAuthenticator(registry)
			if authErr != nil {
				err = authErr
				break
			}

			img, err = stereoscope.GetImageFromSource(ctx, fullRef, image.OciRegistrySource, stereoscope.WithCredentials(image.RegistryCredentials{
				Authority:     registry,
				Authenticator: a,
			}))
			if err != nil {
				if isRateLimitError(err) && username != "" {
					authManager.ReportRateLimit(registry, username, 0)
					continue
				}
				break
			}
			break
		}

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
	findings, preAICandidates := pipeline.Close()
	results.Findings = findings

	if opts.Pre {
		fmt.Println("Writing pre-AI validation candidates to pre.json...")
		preBytes, err := json.MarshalIndent(preAICandidates, "", "  ")
		if err != nil {
			fmt.Printf("⚠️  Error marshalling pre-AI candidates: %v\n", err)
		} else {
			if err := os.WriteFile("pre.json", preBytes, 0644); err != nil {
				fmt.Printf("⚠️  Error writing pre.json: %v\n", err)
			} else {
				fmt.Println("✓ pre.json written successfully.")
			}
		}
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

type tagWithTime struct {
	tag     string
	created time.Time
}

func parseSince(sinceStr string) (time.Time, error) {
	sinceStr = strings.TrimSpace(sinceStr)
	var t time.Time
	var err error
	if len(sinceStr) == 7 { // YYYY-MM
		t, err = time.Parse("2006-01", sinceStr)
	} else if len(sinceStr) == 10 { // YYYY-MM-DD
		t, err = time.Parse("2006-01-02", sinceStr)
	} else {
		return t, fmt.Errorf("invalid since date format %q (use YYYY-MM or YYYY-MM-DD)", sinceStr)
	}
	return t, err
}

func filterSemver(tags []string, constraintStr string) []string {
	c, err := semver.NewConstraint(constraintStr)
	if err != nil {
		fmt.Printf("⚠️  Invalid semver constraint %q: %v. Skipping semver filter.\n", constraintStr, err)
		return tags
	}

	var filtered []string
	for _, tag := range tags {
		cleanTag := tag
		if len(tag) > 0 && (tag[0] == 'v' || tag[0] == 'V') {
			cleanTag = tag[1:]
		}
		v, err := semver.NewVersion(cleanTag)
		if err == nil {
			if c.Check(v) {
				filtered = append(filtered, tag)
			}
		}
	}
	return filtered
}

func fetchTagsCreationTimes(repoName string, tags []string, authManager *auth.AuthManager) []tagWithTime {
	fmt.Printf("Fetching creation timestamps for %d tags...\n", len(tags))
	
	tagChan := make(chan string, len(tags))
	for _, tag := range tags {
		tagChan <- tag
	}
	close(tagChan)

	var wg sync.WaitGroup
	var mu sync.Mutex
	var results []tagWithTime

	refRepo, err := name.NewRepository(repoName)
	registry := "index.docker.io"
	if err == nil {
		registry = refRepo.RegistryStr()
	}

	numAccounts := len(authManager.GetAccountsStats(registry))
	maxRetries := numAccounts
	if maxRetries <= 0 {
		maxRetries = 0
	}

	workerCount := 8
	if len(tags) < workerCount {
		workerCount = len(tags)
	}

	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for t := range tagChan {
				ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)

				ref, err := name.ParseReference(fmt.Sprintf("%s:%s", repoName, t))
				if err != nil {
					cancel()
					continue
				}
				
				var desc *remote.Descriptor
				for attempt := 0; attempt <= maxRetries; attempt++ {
					a, username, authErr := authManager.GetAuthenticator(registry)
					if authErr != nil {
						err = authErr
						break
					}

					optsList := getRemoteOptions(authManager, a)
					optsList = append(optsList, remote.WithContext(ctx))

					desc, err = remote.Get(ref, optsList...)
					if err != nil {
						if isRateLimitError(err) && username != "" {
							authManager.ReportRateLimit(registry, username, 0)
							continue
						}
						break
					}
					break
				}

				if err != nil {
					cancel()
					continue
				}

				img, err := desc.Image()
				if err != nil {
					index, indexErr := desc.ImageIndex()
					if indexErr != nil {
						cancel()
						continue
					}
					manifest, manifestErr := index.IndexManifest()
					if manifestErr != nil {
						cancel()
						continue
					}
					if len(manifest.Manifests) == 0 {
						cancel()
						continue
					}
					img, err = index.Image(manifest.Manifests[0].Digest)
					if err != nil {
						cancel()
						continue
					}
				}

				cfg, err := img.ConfigFile()
				if err != nil {
					cancel()
					continue
				}
				cancel()

				mu.Lock()
				results = append(results, tagWithTime{
					tag:     t,
					created: cfg.Created.Time,
				})
				mu.Unlock()
			}
		}()
	}

	wg.Wait()
	return results
}

type hubResponse struct {
	Results []struct {
		Name        string    `json:"name"`
		LastUpdated time.Time `json:"last_updated"`
	} `json:"results"`
	Next string `json:"next"`
}

func fetchDockerHubTags(namespace, name string, authManager *auth.AuthManager) ([]tagWithTime, error) {
	url := fmt.Sprintf("https://hub.docker.com/v2/repositories/%s/%s/tags?page_size=100", namespace, name)
	
	var results []tagWithTime
	client := &http.Client{Timeout: 10 * time.Second}

	for url != "" {
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return nil, err
		}
		
		a, username, authErr := authManager.GetAuthenticator("index.docker.io")
		if authErr == nil && username != "" {
			if basic, ok := a.(*authn.Basic); ok {
				req.SetBasicAuth(basic.Username, basic.Password)
			}
		}

		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusTooManyRequests && username != "" {
			authManager.ReportRateLimit("index.docker.io", username, 0)
			continue
		}

		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("unexpected status: %s", resp.Status)
		}

		var hr hubResponse
		if err := json.NewDecoder(resp.Body).Decode(&hr); err != nil {
			return nil, err
		}

		for _, r := range hr.Results {
			results = append(results, tagWithTime{
				tag:     r.Name,
				created: r.LastUpdated,
			})
		}
		url = hr.Next
	}
	return results, nil
}

type rateLimitTransport struct {
	inner http.RoundTripper
	mgr   *auth.AuthManager
}

func (t *rateLimitTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.inner.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	t.mgr.InterceptResponse(req, resp)
	return resp, nil
}

func getRemoteOptions(mgr *auth.AuthManager, a authn.Authenticator) []remote.Option {
	var opts []remote.Option
	if a != nil {
		opts = append(opts, remote.WithAuth(a))
	}
	opts = append(opts, remote.WithTransport(&rateLimitTransport{
		inner: remote.DefaultTransport,
		mgr:   mgr,
	}))
	return opts
}

func isRateLimitError(err error) bool {
	if err == nil {
		return false
	}
	if tErr, ok := err.(*transport.Error); ok {
		return tErr.StatusCode == http.StatusTooManyRequests
	}
	errStr := strings.ToUpper(err.Error())
	return strings.Contains(errStr, "TOOMANYREQUESTS") || strings.Contains(errStr, "429")
}
