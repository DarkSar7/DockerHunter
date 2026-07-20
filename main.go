package main

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/DarkSar7/DockerHunter/pkg/config"
	"github.com/DarkSar7/DockerHunter/pkg/scanner"
	"github.com/DarkSar7/DockerHunter/pkg/setup"
	"github.com/DarkSar7/DockerHunter/pkg/validator"
)

//go:embed validator/* config/*
var embeddedFS embed.FS

var (
	allTags bool
	format  string
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "dockerhunter",
		Short: "DockerHunter is an OCI registry secret scanner with AI validation",
		Long:  `DockerHunter retrieves squashed container image filesystems directly from registries, scans them, and uses StarPII to validate credentials.`,
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

			// Start Python validator subprocess (Start ONCE, live during scan, close at exit)
			fmt.Println("Starting AI Validator subprocess...")
			val, err := validator.NewSubprocessValidator(pyExe, scriptPath)
			if err != nil {
				return fmt.Errorf("failed to start validator subprocess: %w", err)
			}
			defer val.Close()

			opts := scanner.Options{
				ImageName: imageName,
				AllTags:   allTags,
				Format:    format,
			}
			if opts.Format == "" {
				opts.Format = cfg.Scanner.OutputFormat
			}

			results, err := scanner.PerformScan(context.Background(), opts, cfg, rules, val)
			if err != nil {
				return err
			}

			displayResults(results, opts.Format)
			return nil
		},
	}

	scanCmd.Flags().BoolVar(&allTags, "all-tags", false, "Scan all tags in the repository")
	scanCmd.Flags().StringVar(&format, "format", "", "Output format (text, json)")

	rootCmd.AddCommand(setupCmd)
	rootCmd.AddCommand(scanCmd)

	if err := rootCmd.Execute(); err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
}

func displayResults(res *scanner.ScanResults, fmtOpt string) {
	if fmtOpt == "json" {
		jsonBytes, err := json.MarshalIndent(res.Findings, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error formatting JSON: %v\n", err)
			return
		}
		fmt.Println(string(jsonBytes))
		return
	}

	fmt.Println("\n=======================================================")
	fmt.Println("             DOCKERHUNTER SCAN SUMMARY")
	fmt.Println("=======================================================")
	fmt.Printf("Repository:         %s\n", res.Repository)
	fmt.Printf("Images Scanned:     %d\n", res.ImagesScanned)
	fmt.Printf("Images Failed:      %d\n", res.ImagesFailed)
	fmt.Printf("Candidates Found:   %d\n", res.CandidatesFound)
	fmt.Printf("Validated Findings: %d\n", len(res.Findings))
	fmt.Println("=======================================================")

	if len(res.Findings) > 0 {
		fmt.Println("\nValidated Findings Details:")
		fmt.Println("-------------------------------------------------------")
		for idx, f := range res.Findings {
			fmt.Printf("[%d] Tag: %s | File: %s:%d\n", idx+1, f.Tag, f.File, f.Line)
			fmt.Printf("    Variable: %s\n", f.Variable)
			fmt.Printf("    Value:    %s\n", f.Value)
			fmt.Printf("    Context:  %s\n", f.Context)
			fmt.Println("-------------------------------------------------------")
		}
	} else {
		fmt.Println("\nNo validated secrets found in the scanned target(s).")
	}

	if len(res.Errors) > 0 {
		fmt.Println("\nErrors encountered during scan:")
		for _, errStr := range res.Errors {
			fmt.Printf(" - %s\n", errStr)
		}
	}
}
