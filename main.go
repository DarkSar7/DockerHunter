package main

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"

	"github.com/spf13/cobra"
	"github.com/google/go-containerregistry/pkg/name"

	"github.com/DarkSar7/DockerHunter/pkg/auth"
	"github.com/DarkSar7/DockerHunter/pkg/config"
	"github.com/DarkSar7/DockerHunter/pkg/scanner"
	"github.com/DarkSar7/DockerHunter/pkg/setup"
	"github.com/DarkSar7/DockerHunter/pkg/types"
	"github.com/DarkSar7/DockerHunter/pkg/validator"
)

func buildVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok || info.Main.Version == "" || info.Main.Version == "(devel)" {
		return "dev"
	}
	return info.Main.Version
}

//go:embed validator/* config/*
var embeddedFS embed.FS

var (
	allTags         bool
	format          string
	outputPath      string
	preAICandidates bool
	maxTags         int
	sinceDate       string
	latestCount     int
	semverRange     string
	contextOpt      string
)

func main() {
	rootCmd := &cobra.Command{
		Use:     "dockerhunter",
		Short:   "DockerHunter is an OCI registry secret scanner with AI validation",
		Long:    `DockerHunter retrieves squashed container image filesystems directly from registries, scans them, and uses StarPII to validate credentials.`,
		Version: buildVersion(),
	}

	setupCmd := &cobra.Command{
		Use:   "setup",
		Short: "Initialize working directory, virtual environment, and cache the model",
		RunE: func(cmd *cobra.Command, args []string) error {
			return setup.RunSetup(embeddedFS)
		},
	}

	scanCmd := &cobra.Command{
		Use:   "scan [image]",
		Short: "Scan a container image or repository for secrets",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			imageName := args[0]

			// Load configurations from ~/.dockerhunter
			home, err := os.UserHomeDir()
			if err != nil {
				return fmt.Errorf("failed to get user home directory: %w", err)
			}
			baseDir := filepath.Join(home, ".dockerhunter")
			configPath := filepath.Join(baseDir, "config.yaml")

			// Check if setup has been executed
			if _, err := os.Stat(configPath); os.IsNotExist(err) {
				fmt.Println("Error: Configuration files not found. Please run 'dockerhunter setup' first.")
				os.Exit(1)
			}

			cfg, err := config.LoadConfig(configPath)
			if err != nil {
				return fmt.Errorf("failed to load configuration: %w", err)
			}

			rules, err := config.LoadRegexRules(cfg.Scanner.RegexRulesPath)
			if err != nil {
				return fmt.Errorf("failed to load regex validation rules: %w", err)
			}

			// Resolve Python and Script paths
			pyExe := cfg.Validator.ExecutablePath
			scriptPath := filepath.Join(baseDir, "validator", "main.py")

			// Open error log file
			errLogFile, err := os.OpenFile("scanner_errors.log", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
			if err != nil {
				return fmt.Errorf("failed to create or open scanner_errors.log: %w", err)
			}
			defer errLogFile.Close()

			// Start Python validator subprocess (Start ONCE, live during scan, close at exit)
			fmt.Println("AI Server Status: Checking...")
			val, err := validator.NewSubprocessValidator(pyExe, scriptPath, errLogFile)
			if err != nil {
				fmt.Println("AI Server Status: Not Running")
				return fmt.Errorf("failed to start validator subprocess: %w", err)
			}
			fmt.Println("AI Server Status: Running")
			defer val.Close()

			// Resolve repoName for path structuring
			repoPath := imageName
			if rRepo, err := name.NewRepository(imageName); err == nil {
				repoPath = rRepo.Name()
			}
			repoPath = strings.ReplaceAll(repoPath, ":", "_") // clean tags

			var finalResultsPath string
			var baseOutputDir string

			if outputPath != "" {
				if filepath.Ext(outputPath) == ".json" {
					baseDir := filepath.Dir(outputPath)
					fileName := filepath.Base(outputPath)
					baseOutputDir = filepath.Join(baseDir, repoPath)
					finalResultsPath = filepath.Join(baseOutputDir, fileName)
				} else {
					baseOutputDir = filepath.Join(outputPath, repoPath)
					finalResultsPath = filepath.Join(baseOutputDir, "results.json")
				}
			} else if contextOpt != "none" {
				baseOutputDir = filepath.Join("output", repoPath)
				finalResultsPath = filepath.Join(baseOutputDir, "results.json")
			}

			opts := scanner.Options{
				ImageName:  imageName,
				AllTags:    allTags,
				Format:     format,
				Pre:        preAICandidates,
				MaxTags:    maxTags,
				Since:      sinceDate,
				Latest:     latestCount,
				Semver:     semverRange,
				Context:    contextOpt,
				OutputPath: outputPath,
			}
			if opts.Format == "" {
				opts.Format = cfg.Scanner.OutputFormat
			}

			authMgr := auth.NewAuthManager(cfg)
			results, err := scanner.PerformScan(context.Background(), opts, cfg, rules, val, authMgr, errLogFile)
			if err != nil {
				return err
			}

			if finalResultsPath != "" {
				if err := os.MkdirAll(filepath.Dir(finalResultsPath), 0755); err != nil {
					return fmt.Errorf("failed to create output directory %s: %w", filepath.Dir(finalResultsPath), err)
				}
				file, err := os.OpenFile(finalResultsPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
				if err != nil {
					return fmt.Errorf("failed to create output file %s: %w", finalResultsPath, err)
				}
				defer file.Close()
				displayResults(file, results, opts.Format)
				fmt.Printf("✓ Scan results saved to %s\n", finalResultsPath)
			} else {
				displayResults(os.Stdout, results, opts.Format)
			}

			if stat, err := os.Stat("scanner_errors.log"); err == nil && stat.Size() > 0 {
				fmt.Println("\n⚠️  Warnings or errors were encountered during the scan. Please check scanner_errors.log for details.")
			}

			return nil
		},
	}

	scanCmd.Flags().BoolVar(&allTags, "all-tags", false, "Scan all tags in the repository")
	scanCmd.Flags().StringVar(&format, "format", "", "Output format (text, json)")
	scanCmd.Flags().StringVarP(&outputPath, "output", "o", "", "Path to save final results")
	scanCmd.Flags().BoolVar(&preAICandidates, "pre", false, "Save pre-AI validation candidates to pre.json")
	scanCmd.Flags().IntVar(&maxTags, "max-tags", 0, "Maximum number of tags to scan")
	scanCmd.Flags().StringVar(&sinceDate, "since", "", "Scan tags created since date (YYYY-MM or YYYY-MM-DD)")
	scanCmd.Flags().IntVar(&latestCount, "latest", 0, "Scan only the N most recently updated tags")
	scanCmd.Flags().StringVar(&semverRange, "semver", "", "Scan only tags matching semantic versioning constraint")
	scanCmd.Flags().StringVar(&contextOpt, "context", "none", "Context export mode (none, files, full)")

	rootCmd.AddCommand(setupCmd)
	rootCmd.AddCommand(scanCmd)

	if err := rootCmd.Execute(); err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
}

func displayResults(w io.Writer, res *scanner.ScanResults, fmtOpt string) {
	if res == nil {
		return
	}
	if res.Findings == nil {
		res.Findings = []types.Finding{}
	}
	if res.Errors == nil {
		res.Errors = []string{}
	}

	if fmtOpt == "json" {
		jsonBytes, err := json.MarshalIndent(res, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error formatting JSON: %v\n", err)
			return
		}
		fmt.Fprintln(w, string(jsonBytes))
		return
	}

	fmt.Fprintln(w, "\n=======================================================")
	fmt.Fprintln(w, "             DOCKERHUNTER SCAN SUMMARY")
	fmt.Fprintln(w, "=======================================================")
	fmt.Fprintf(w, "Repository:         %s\n", res.Repository)
	fmt.Fprintf(w, "Images Scanned:     %d\n", res.ImagesScanned)
	fmt.Fprintf(w, "Images Failed:      %d\n", res.ImagesFailed)
	fmt.Fprintf(w, "Generic Candidates: %d\n", res.CandidatesFound)
	fmt.Fprintf(w, "Signature Matches:  %d\n", res.Pipeline.SignatureMatches)
	fmt.Fprintf(w, "Sent to StarPII:    %d\n", res.Pipeline.SentToAI)
	fmt.Fprintf(w, "AI Rejected:        %d\n", res.Pipeline.AIRejected)
	fmt.Fprintf(w, "Validated Findings: %d\n", len(res.Findings))
	fmt.Fprintln(w, "=======================================================")

	if len(res.Findings) > 0 {
		fmt.Fprintln(w, "\nValidated Findings Details:")
		fmt.Fprintln(w, "-------------------------------------------------------")
		for idx, f := range res.Findings {
			fmt.Fprintf(w, "[%d] Tag: %s | File: %s:%d\n", idx+1, f.Tag, f.File, f.Line)
			fmt.Fprintf(w, "    Variable: %s\n", f.Variable)
			fmt.Fprintf(w, "    Value:    %s\n", f.Value)
			fmt.Fprintf(w, "    Context:  %s\n", f.Context)
			fmt.Fprintln(w, "-------------------------------------------------------")
		}
	} else {
		fmt.Fprintln(w, "\nNo validated secrets found in the scanned target(s).")
	}

	if len(res.Errors) > 0 {
		fmt.Fprintln(w, "\nErrors encountered during scan:")
		for _, errStr := range res.Errors {
			fmt.Fprintf(w, " - %s\n", errStr)
		}
	}
}
