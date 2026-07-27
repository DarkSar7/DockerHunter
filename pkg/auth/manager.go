package auth

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"

	"github.com/DarkSar7/DockerHunter/pkg/config"
)

var ErrAllAccountsRateLimited = errors.New("all accounts for the registry are rate-limited")

type Account struct {
	Username       string
	Token          string
	PullCount      int
	RateLimitCount int
	LastUsed       time.Time
	DisabledUntil  time.Time
	Disabled       bool
}

type AccountStats struct {
	Username       string
	PullCount      int
	RateLimitCount int
	LastUsed       time.Time
	DisabledUntil  time.Time
	Disabled       bool
}

type AuthManager struct {
	mu                sync.RWMutex
	registries        map[string][]*Account
	nextAccountIndex  map[string]int
	defaultCooldown   time.Duration
	anonymousFallback bool
}

func NewAuthManager(cfg *config.Config) *AuthManager {
	mgr := &AuthManager{
		registries:        make(map[string][]*Account),
		nextAccountIndex:  make(map[string]int),
		defaultCooldown:   6 * time.Hour,
		anonymousFallback: false,
	}

	if cfg == nil {
		return mgr
	}

	// Parse default cooldown
	if cfg.Authentication.DefaultCooldown != "" {
		d, err := time.ParseDuration(cfg.Authentication.DefaultCooldown)
		if err == nil && d > 0 {
			mgr.defaultCooldown = d
		}
	}
	mgr.anonymousFallback = cfg.Authentication.AnonymousFallback

	// Load registries
	for reg, regConf := range cfg.Registries {
		normalizedReg := normalizeRegistry(reg)
		var accounts []*Account
		for _, acc := range regConf.Accounts {
			accounts = append(accounts, &Account{
				Username: acc.Username,
				Token:    acc.Token,
			})
		}
		mgr.registries[normalizedReg] = accounts
	}

	return mgr
}

// GetAuthenticator returns the next available authn.Authenticator for a registry using round-robin.
func (m *AuthManager) GetAuthenticator(registry string) (authn.Authenticator, string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	normalized := normalizeRegistry(registry)
	accounts, exists := m.registries[normalized]
	if !exists || len(accounts) == 0 {
		return authn.Anonymous, "", nil
	}

	now := time.Now()
	numAccounts := len(accounts)
	startIndex := m.nextAccountIndex[normalized]

	var earliestAvailable time.Time
	hasEarliest := false

	for i := 0; i < numAccounts; i++ {
		idx := (startIndex + i) % numAccounts
		acc := accounts[idx]

		// Check if cooldown expired
		if acc.Disabled {
			if now.After(acc.DisabledUntil) {
				acc.Disabled = false
				acc.DisabledUntil = time.Time{}
			} else {
				if !hasEarliest || acc.DisabledUntil.Before(earliestAvailable) {
					earliestAvailable = acc.DisabledUntil
					hasEarliest = true
				}
				continue
			}
		}

		// Found active account. Update round-robin pointer.
		m.nextAccountIndex[normalized] = (idx + 1) % numAccounts
		acc.PullCount++
		acc.LastUsed = now

		auth := &authn.Basic{
			Username: acc.Username,
			Password: acc.Token,
		}
		return auth, acc.Username, nil
	}

	// If all rate-limited, fall back to anonymous if configured
	if m.anonymousFallback {
		return authn.Anonymous, "", nil
	}

	waitDuration := earliestAvailable.Sub(now)
	if waitDuration < 0 {
		waitDuration = 0
	}
	return nil, "", fmt.Errorf("%w: %s. Next available in %s", ErrAllAccountsRateLimited, registry, formatDuration(waitDuration))
}

// ReportRateLimit reactively disables an account on HTTP 429.
func (m *AuthManager) ReportRateLimit(registry, username string, customCooldown time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()

	normalized := normalizeRegistry(registry)
	accounts, exists := m.registries[normalized]
	if !exists {
		return
	}

	cooldown := customCooldown
	if cooldown <= 0 {
		cooldown = m.defaultCooldown
	}

	for _, acc := range accounts {
		if acc.Username == username {
			acc.Disabled = true
			acc.DisabledUntil = time.Now().Add(cooldown)
			acc.RateLimitCount++
			fmt.Printf("⚠️  Rate limit (HTTP 429) reached for account %q on registry %q. Disabled for %s.\n", username, registry, formatDuration(cooldown))
			return
		}
	}
}

// DisableAccount proactively disables an account before a query is issued.
func (m *AuthManager) DisableAccount(registry, username string, cooldown time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()

	normalized := normalizeRegistry(registry)
	accounts, exists := m.registries[normalized]
	if !exists {
		return
	}

	for _, acc := range accounts {
		if acc.Username == username {
			if !acc.Disabled {
				acc.Disabled = true
				acc.DisabledUntil = time.Now().Add(cooldown)
				acc.RateLimitCount++
				fmt.Printf("⚠️  Proactive rate limit: remaining=0 for account %q on registry %q. Disabled for %s.\n", username, registry, formatDuration(cooldown))
			}
			return
		}
	}
}

// UpdateStats updates the state of an account with remaining rate limit quota.
func (m *AuthManager) UpdateStats(registry, username string, remaining, resetSeconds int) {
	m.mu.Lock()
	defer m.mu.Unlock()

	normalized := normalizeRegistry(registry)
	accounts, exists := m.registries[normalized]
	if !exists {
		return
	}

	for _, acc := range accounts {
		if acc.Username == username {
			acc.LastUsed = time.Now()
			// If reset time and remaining indicates it is active
			if remaining > 0 && acc.Disabled {
				acc.Disabled = false
				acc.DisabledUntil = time.Time{}
			}
			return
		}
	}
}

// GetAccountsStats returns a snapshot of runtime statistics for registry accounts.
func (m *AuthManager) GetAccountsStats(registry string) []AccountStats {
	m.mu.RLock()
	defer m.mu.RUnlock()

	normalized := normalizeRegistry(registry)
	accounts, exists := m.registries[normalized]
	if !exists {
		return nil
	}

	now := time.Now()
	stats := make([]AccountStats, len(accounts))
	for i, acc := range accounts {
		disabled := acc.Disabled
		if disabled && now.After(acc.DisabledUntil) {
			disabled = false
		}
		stats[i] = AccountStats{
			Username:       acc.Username,
			PullCount:      acc.PullCount,
			RateLimitCount: acc.RateLimitCount,
			LastUsed:       acc.LastUsed,
			DisabledUntil:  acc.DisabledUntil,
			Disabled:       disabled,
		}
	}
	return stats
}

// InterceptResponse parses HTTP response headers to detect registry rate limit quotas proactively.
func (m *AuthManager) InterceptResponse(req *http.Request, resp *http.Response) {
	if req == nil || resp == nil {
		return
	}

	registry := req.URL.Host
	username := ""

	// Parse Basic Auth header to map headers back to the username
	authHeader := req.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Basic ") {
		payload := strings.TrimPrefix(authHeader, "Basic ")
		decoded, err := base64.StdEncoding.DecodeString(payload)
		if err == nil {
			parts := strings.SplitN(string(decoded), ":", 2)
			if len(parts) > 0 {
				username = parts[0]
			}
		}
	}

	if username == "" {
		return
	}

	// Intercept Docker Hub / OCI rate-limit headers
	remainingHeader := resp.Header.Get("RateLimit-Remaining")
	resetHeader := resp.Header.Get("RateLimit-Reset")

	// Standard fallback/alternative headers (e.g. X-RateLimit)
	if remainingHeader == "" {
		remainingHeader = resp.Header.Get("X-RateLimit-Remaining")
		resetHeader = resp.Header.Get("X-RateLimit-Reset")
	}

	if remainingHeader != "" {
		remaining := parseHeaderInt(remainingHeader)
		reset := parseHeaderInt(resetHeader) // seconds

		if remaining == 0 {
			cooldown := time.Duration(reset) * time.Second
			if cooldown <= 0 {
				m.mu.RLock()
				cooldown = m.defaultCooldown
				m.mu.RUnlock()
			}
			m.DisableAccount(registry, username, cooldown)
		} else {
			m.UpdateStats(registry, username, remaining, reset)
		}
	}
}

func parseHeaderInt(h string) int {
	parts := strings.Split(h, ";")
	if len(parts) == 0 {
		return 0
	}
	var val int
	fmt.Sscanf(strings.TrimSpace(parts[0]), "%d", &val)
	return val
}

func normalizeRegistry(registry string) string {
	registry = strings.ToLower(strings.TrimSpace(registry))
	if registry == "index.docker.io" {
		return "docker.io"
	}
	return registry
}

func formatDuration(d time.Duration) string {
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	s := int(d.Seconds()) % 60
	if h > 0 {
		return fmt.Sprintf("%dh %dm", h, m)
	}
	if m > 0 {
		return fmt.Sprintf("%dm %ds", m, s)
	}
	return fmt.Sprintf("%ds", s)
}
