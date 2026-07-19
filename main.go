package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"dockerhunter/pkg/scanner"
)

var (
	allTags      bool
	jsonOutput   bool
	format       string
	validatorURL string
	batchSize    int
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "dockerhunter",
		Short: "DockerHunter is an OCI registry secret scanner with AI validation",
		Long:  `DockerHunter retrieves squashed container image filesystems directly from registries, scans them, and uses StarPII to validate credentials.`,
	}

	scanCmd := &cobra.Command{
		Use:   "scan [image]",
		Short: "Scan a container image or repository for secrets",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			imageName := args[0]

			// Harmonize --json and --format json
			outputFormat := format
			if jsonOutput {
				outputFormat = "json"
			}

			opts := scanner.Options{
				ImageName:    imageName,
				AllTags:      allTags,
				Format:       outputFormat,
				ValidatorURL: validatorURL,
				BatchSize:    batchSize,
			}

			results, err := scanner.PerformScan(context.Background(), opts)
			if err != nil {
				return err
			}

			displayResults(results, opts.Format)
			return nil
		},
	}

	// Add flags
	scanCmd.Flags().BoolVar(&allTags, "all-tags", false, "Scan all tags in the repository")
	scanCmd.Flags().BoolVar(&jsonOutput, "json", false, "Output results in JSON format")
	scanCmd.Flags().StringVar(&format, "format", "text", "Output format (text, json)")
	scanCmd.Flags().StringVarP(&validatorURL, "validator-url", "u", "http://localhost:9001", "AI Validator Service endpoint URL")
	scanCmd.Flags().IntVarP(&batchSize, "batch-size", "b", 100, "Inference batch size")

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

	// Print beautiful Text report
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
