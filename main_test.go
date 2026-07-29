package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/DarkSar7/DockerHunter/pkg/scanner"
	"github.com/DarkSar7/DockerHunter/pkg/types"
)

func TestJSONOutputUsesEmptyArraysInsteadOfNull(t *testing.T) {
	var out bytes.Buffer
	displayResults(&out, &scanner.ScanResults{
		Repository: "example/image",
		Findings:   []types.Finding{},
		Errors:     []string{},
	}, "json")

	got := out.String()
	if strings.Contains(got, `"findings": null`) || strings.Contains(got, `"errors": null`) {
		t.Fatalf("JSON output contains null collection: %s", got)
	}
	if !strings.Contains(got, `"findings": []`) {
		t.Fatalf("JSON output does not include an empty findings array: %s", got)
	}
}
