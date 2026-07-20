package config

import (
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Validator struct {
		ModelName        string `yaml:"model_name"`
		CacheDir         string `yaml:"cache_dir"`
		ExecutablePath   string `yaml:"executable_path"`
		HuggingFaceToken string `yaml:"huggingface_token"`
	} `yaml:"validator"`
	Pipeline struct {
		BatchSize      int `yaml:"batch_size"`
		BatchTimeoutMs int `yaml:"batch_timeout_ms"`
		WorkerCount    int `yaml:"worker_count"`
	} `yaml:"pipeline"`
	Scanner struct {
		RegexRulesPath string `yaml:"regex_rules_path"`
		OutputFormat   string `yaml:"output_format"`
	} `yaml:"scanner"`
}

type RegexRules struct {
	Signatures []Signature `yaml:"signatures"`
}

type Signature struct {
	Pattern PatternDetail `yaml:"pattern"`
}

type PatternDetail struct {
	Sensitive bool   `yaml:"sensitive"`
	Name      string `yaml:"name"`
	Value     string `yaml:"value"`
}

// ExpandHome resolves '~' at the beginning of paths to the user's home directory.
func ExpandHome(path string) string {
	if strings.HasPrefix(path, "~") {
		home, err := os.UserHomeDir()
		if err == nil {
			if len(path) > 1 && (path[1] == '/' || path[1] == '\\') {
				return filepath.Join(home, path[2:])
			}
			return filepath.Join(home, path[1:])
		}
	}
	return path
}

func LoadConfig(path string) (*Config, error) {
	expandedPath := ExpandHome(path)
	data, err := os.ReadFile(expandedPath)
	if err != nil {
		return nil, err
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	// Resolve paths
	cfg.Validator.CacheDir = ExpandHome(cfg.Validator.CacheDir)
	cfg.Validator.ExecutablePath = ExpandHome(cfg.Validator.ExecutablePath)
	cfg.Scanner.RegexRulesPath = ExpandHome(cfg.Scanner.RegexRulesPath)

	return &cfg, nil
}

func LoadRegexRules(path string) (*RegexRules, error) {
	expandedPath := ExpandHome(path)
	data, err := os.ReadFile(expandedPath)
	if err != nil {
		return nil, err
	}

	var rules RegexRules
	if err := yaml.Unmarshal(data, &rules); err != nil {
		return nil, err
	}

	return &rules, nil
}
