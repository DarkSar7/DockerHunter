package auth

import (
	"errors"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"

	"github.com/DarkSar7/DockerHunter/pkg/config"
)

func TestNewAuthManager(t *testing.T) {
	cfg := &config.Config{
		Authentication: struct {
			DefaultCooldown   string `yaml:"default_cooldown"`
			AnonymousFallback bool   `yaml:"anonymous_fallback"`
		}{
			DefaultCooldown:   "2h",
			AnonymousFallback: true,
		},
		Registries: map[string]config.RegistryConfig{
			"docker.io": {
				Accounts: []config.AccountConfig{
					{Username: "user1", Token: "tok1"},
					{Username: "user2", Token: "tok2"},
				},
			},
		},
	}

	mgr := NewAuthManager(cfg)
	if mgr.defaultCooldown != 2*time.Hour {
		t.Errorf("expected default cooldown 2h, got %v", mgr.defaultCooldown)
	}
	if !mgr.anonymousFallback {
		t.Error("expected anonymous fallback to be true")
	}

	accounts := mgr.registries["docker.io"]
	if len(accounts) != 2 {
		t.Fatalf("expected 2 accounts, got %d", len(accounts))
	}
	if accounts[0].Username != "user1" || accounts[0].Token != "tok1" {
		t.Errorf("incorrect account[0]: %+v", accounts[0])
	}
}

func TestRoundRobinScheduling(t *testing.T) {
	cfg := &config.Config{
		Registries: map[string]config.RegistryConfig{
			"docker.io": {
				Accounts: []config.AccountConfig{
					{Username: "user1", Token: "tok1"},
					{Username: "user2", Token: "tok2"},
				},
			},
		},
	}

	mgr := NewAuthManager(cfg)

	// Call 1
	a1, u1, err := mgr.GetAuthenticator("docker.io")
	if err != nil {
		t.Fatalf("GetAuthenticator failed: %v", err)
	}
	if u1 != "user1" {
		t.Errorf("expected user1, got %s", u1)
	}
	b1, ok := a1.(*authn.Basic)
	if !ok || b1.Username != "user1" || b1.Password != "tok1" {
		t.Error("incorrect authn interface for user1")
	}

	// Call 2
	_, u2, err := mgr.GetAuthenticator("docker.io")
	if err != nil {
		t.Fatalf("GetAuthenticator failed: %v", err)
	}
	if u2 != "user2" {
		t.Errorf("expected user2, got %s", u2)
	}

	// Call 3 (Round-Robin wraps back to user1)
	_, u3, err := mgr.GetAuthenticator("docker.io")
	if err != nil {
		t.Fatalf("GetAuthenticator failed: %v", err)
	}
	if u3 != "user1" {
		t.Errorf("expected wrap back to user1, got %s", u3)
	}
}

func TestReactiveRateLimitRotationAndCooldown(t *testing.T) {
	cfg := &config.Config{
		Registries: map[string]config.RegistryConfig{
			"docker.io": {
				Accounts: []config.AccountConfig{
					{Username: "user1", Token: "tok1"},
					{Username: "user2", Token: "tok2"},
				},
			},
		},
	}

	mgr := NewAuthManager(cfg)
	mgr.defaultCooldown = 1 * time.Second

	// Report rate limit for user1
	mgr.ReportRateLimit("docker.io", "user1", 0)

	// User1 should be disabled. GetAuthenticator should return user2
	_, u, err := mgr.GetAuthenticator("docker.io")
	if err != nil {
		t.Fatalf("GetAuthenticator failed: %v", err)
	}
	if u != "user2" {
		t.Errorf("expected user2 because user1 is disabled, got %s", u)
	}

	// Fetching again should return user2 again because user1 is still disabled
	_, u, err = mgr.GetAuthenticator("docker.io")
	if err != nil {
		t.Fatalf("GetAuthenticator failed: %v", err)
	}
	if u != "user2" {
		t.Errorf("expected user2 again, got %s", u)
	}

	// Wait for cooldown to expire
	time.Sleep(1100 * time.Millisecond)

	// User1 cooldown expired, should wrap back to user1 now
	_, u, err = mgr.GetAuthenticator("docker.io")
	if err != nil {
		t.Fatalf("GetAuthenticator failed: %v", err)
	}
	if u != "user1" {
		t.Errorf("expected user1 after cooldown reset, got %s", u)
	}
}

func TestProactiveRateLimitHeaderInterception(t *testing.T) {
	cfg := &config.Config{
		Registries: map[string]config.RegistryConfig{
			"docker.io": {
				Accounts: []config.AccountConfig{
					{Username: "user1", Token: "tok1"},
				},
			},
		},
	}

	mgr := NewAuthManager(cfg)

	// Intercept response indicating remaining is 0
	req, _ := http.NewRequest("GET", "https://index.docker.io/v2/alpine/manifests/latest", nil)
	// Base64 encoding for "user1:tok1" is "dXNlcjE6dG9rMQ=="
	req.Header.Set("Authorization", "Basic dXNlcjE6dG9rMQ==")

	resp := &http.Response{
		Header: make(http.Header),
	}
	resp.Header.Set("RateLimit-Remaining", "0;w=21600")
	resp.Header.Set("RateLimit-Reset", "30") // 30 seconds

	mgr.InterceptResponse(req, resp)

	// Account should have been proactively disabled
	stats := mgr.GetAccountsStats("docker.io")
	if len(stats) != 1 {
		t.Fatal("expected 1 account stats")
	}
	if !stats[0].Disabled {
		t.Error("expected account to be disabled proactively")
	}
	if stats[0].RateLimitCount != 1 {
		t.Errorf("expected RateLimitCount=1, got %d", stats[0].RateLimitCount)
	}
}

func TestAnonymousFallbackToggles(t *testing.T) {
	cfg := &config.Config{
		Authentication: struct {
			DefaultCooldown   string `yaml:"default_cooldown"`
			AnonymousFallback bool   `yaml:"anonymous_fallback"`
		}{
			AnonymousFallback: false,
		},
		Registries: map[string]config.RegistryConfig{
			"docker.io": {
				Accounts: []config.AccountConfig{
					{Username: "user1", Token: "tok1"},
				},
			},
		},
	}

	mgr := NewAuthManager(cfg)

	// Disable the only account
	mgr.ReportRateLimit("docker.io", "user1", 10*time.Minute)

	// Try fetching authenticator when fallback is false
	_, _, err := mgr.GetAuthenticator("docker.io")
	if err == nil || !errors.Is(err, ErrAllAccountsRateLimited) {
		t.Errorf("expected ErrAllAccountsRateLimited, got: %v", err)
	}

	// Set fallback to true
	mgr.anonymousFallback = true

	// Try fetching authenticator when fallback is true
	auth, u, err := mgr.GetAuthenticator("docker.io")
	if err != nil {
		t.Fatalf("expected anonymous fallback, got error: %v", err)
	}
	if auth != authn.Anonymous || u != "" {
		t.Errorf("expected authn.Anonymous, got auth=%v, user=%s", auth, u)
	}
}

func TestNormalizeRegistry(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"index.docker.io", "docker.io"},
		{"docker.io", "docker.io"},
		{"Docker.io", "docker.io"},
		{"ghcr.io", "ghcr.io"},
	}

	for _, tc := range tests {
		got := normalizeRegistry(tc.input)
		if got != tc.expected {
			t.Errorf("normalizeRegistry(%q) = %q; want %q", tc.input, got, tc.expected)
		}
	}
}

func TestParseHeaderInt(t *testing.T) {
	tests := []struct {
		input    string
		expected int
	}{
		{"100;w=21600", 100},
		{"0;w=21600", 0},
		{" 150 ", 150},
		{"invalid", 0},
	}

	for _, tc := range tests {
		got := parseHeaderInt(tc.input)
		if got != tc.expected {
			t.Errorf("parseHeaderInt(%q) = %d; want %d", tc.input, got, tc.expected)
		}
	}
}

func TestFormatDuration(t *testing.T) {
	tests := []struct {
		input    time.Duration
		expected string
	}{
		{3*time.Hour + 42*time.Minute, "3h 42m"},
		{5*time.Minute + 12*time.Second, "5m 12s"},
		{15 * time.Second, "15s"},
	}

	for _, tc := range tests {
		got := formatDuration(tc.input)
		if got != tc.expected {
			t.Errorf("formatDuration(%v) = %q; want %q", tc.input, got, tc.expected)
		}
	}
}

func TestRegistryNormalizationInHTTPRequests(t *testing.T) {
	cfg := &config.Config{
		Registries: map[string]config.RegistryConfig{
			"docker.io": {
				Accounts: []config.AccountConfig{
					{Username: "user1", Token: "tok1"},
				},
			},
		},
	}

	mgr := NewAuthManager(cfg)

	// Verify we can find auth using both docker.io and index.docker.io registry strings
	_, u1, err := mgr.GetAuthenticator("docker.io")
	if err != nil || u1 != "user1" {
		t.Errorf("failed to fetch auth with docker.io: %v", err)
	}

	_, u2, err := mgr.GetAuthenticator("index.docker.io")
	if err != nil || u2 != "user1" {
		t.Errorf("failed to fetch auth with index.docker.io: %v", err)
	}

	// Test intercepting request to index.docker.io maps back to docker.io configs
	req := &http.Request{
		URL: &url.URL{
			Host: "index.docker.io",
		},
		Header: make(http.Header),
	}
	req.Header.Set("Authorization", "Basic dXNlcjE6dG9rMQ==")
	resp := &http.Response{
		Header: make(http.Header),
	}
	resp.Header.Set("RateLimit-Remaining", "0")
	mgr.InterceptResponse(req, resp)

	stats := mgr.GetAccountsStats("docker.io")
	if !stats[0].Disabled {
		t.Error("proactive disablement failed to resolve index.docker.io response to docker.io account")
	}
}
