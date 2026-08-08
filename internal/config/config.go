// Package config loads and validates MCP Gateway runtime configuration.
package config

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const maxTimeout = 5 * time.Minute

// maxRateLimitCapacity bounds a single token bucket's capacity so a
// misconfigured or malicious value cannot request unbounded memory or
// overflow duration arithmetic during refill.
const maxRateLimitCapacity = 100_000_000

var validToolName = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

// maxBodyBytes bounds request and response byte caps to a value safe for a
// memory-constrained host, matching the maxTimeout sanity bound above.
const maxBodyBytes = 64 * 1024 * 1024

// Values is the complete typed runtime configuration.
type Values struct {
	UpstreamURL         string
	ListenAddress       string
	UpstreamTimeout     time.Duration
	ReadTimeout         time.Duration
	WriteTimeout        time.Duration
	IdleTimeout         time.Duration
	MaxRequestBytes     int64
	MaxResponseBytes    int64
	APIKeys             []APIKey
	ToolPolicies        []ToolPolicy
	RateLimits          []RateLimit
	RedactAuditMetadata []string
}

// APIKey is a safe client identifier and a SHA-256 digest of its raw key.
type APIKey struct {
	ID     string
	SHA256 [sha256.Size]byte
}

// ToolPolicy grants or denies one authenticated client permission to invoke
// one MCP tool by name via tools/call. Any (client, tool) pair without a
// matching policy is denied by default.
type ToolPolicy struct {
	ClientID string
	Tool     string
	Allow    bool
}

// RateLimit bounds one authenticated client's tools/call rate for one MCP
// tool with a token-bucket that starts full, holds at most Capacity tokens,
// and refills one token every RefillInterval. Every allow ToolPolicy must
// have exactly one matching RateLimit; deny policies must have none.
type RateLimit struct {
	ClientID       string
	Tool           string
	Capacity       uint32
	RefillInterval time.Duration
}

// Load reads required settings using getenv and validates them before startup.
func Load(getenv func(string) string) (Values, error) {
	if getenv == nil {
		return Values{}, errors.New("configuration source is required")
	}
	values := Values{
		UpstreamURL:   strings.TrimSpace(getenv("MCP_GATEWAY_UPSTREAM_URL")),
		ListenAddress: strings.TrimSpace(getenv("MCP_GATEWAY_LISTEN_ADDRESS")),
	}
	upstream, err := url.ParseRequestURI(values.UpstreamURL)
	if err != nil || upstream.Hostname() == "" || (upstream.Scheme != "http" && upstream.Scheme != "https") || upstream.User != nil {
		return Values{}, errors.New("MCP_GATEWAY_UPSTREAM_URL must be an absolute HTTP(S) URL without user information")
	}
	_, portText, err := net.SplitHostPort(values.ListenAddress)
	if err != nil {
		return Values{}, errors.New("MCP_GATEWAY_LISTEN_ADDRESS must be a host:port address")
	}
	if portText == "" || strings.IndexFunc(portText, func(character rune) bool {
		return character < '0' || character > '9'
	}) != -1 {
		return Values{}, errors.New("MCP_GATEWAY_LISTEN_ADDRESS port must contain only digits")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return Values{}, errors.New("MCP_GATEWAY_LISTEN_ADDRESS port must be a number from 1 to 65535")
	}

	for _, item := range []struct {
		name   string
		target *time.Duration
	}{
		{"MCP_GATEWAY_UPSTREAM_TIMEOUT", &values.UpstreamTimeout},
		{"MCP_GATEWAY_READ_TIMEOUT", &values.ReadTimeout},
		{"MCP_GATEWAY_WRITE_TIMEOUT", &values.WriteTimeout},
		{"MCP_GATEWAY_IDLE_TIMEOUT", &values.IdleTimeout},
	} {
		duration, err := time.ParseDuration(strings.TrimSpace(getenv(item.name)))
		if err != nil || duration <= 0 || duration > maxTimeout {
			return Values{}, fmt.Errorf("%s must be a positive duration no greater than %s", item.name, maxTimeout)
		}
		*item.target = duration
	}

	for _, item := range []struct {
		name   string
		target *int64
	}{
		{"MCP_GATEWAY_MAX_REQUEST_BYTES", &values.MaxRequestBytes},
		{"MCP_GATEWAY_MAX_RESPONSE_BYTES", &values.MaxResponseBytes},
	} {
		value, err := strconv.ParseInt(strings.TrimSpace(getenv(item.name)), 10, 64)
		if err != nil || value <= 0 || value > maxBodyBytes {
			return Values{}, fmt.Errorf("%s must be a positive byte count no greater than %d", item.name, maxBodyBytes)
		}
		*item.target = value
	}
	apiKeys, err := parseAPIKeys(strings.TrimSpace(getenv("MCP_GATEWAY_API_KEYS")))
	if err != nil {
		return Values{}, err
	}
	values.APIKeys = apiKeys

	toolPolicies, err := parseToolPolicies(strings.TrimSpace(getenv("MCP_GATEWAY_TOOL_POLICIES")), apiKeys)
	if err != nil {
		return Values{}, err
	}
	values.ToolPolicies = toolPolicies

	rateLimits, err := parseRateLimits(strings.TrimSpace(getenv("MCP_GATEWAY_TOOL_RATE_LIMITS")), apiKeys, toolPolicies)
	if err != nil {
		return Values{}, err
	}
	values.RateLimits = rateLimits
	redactions, err := parseAuditRedactions(strings.TrimSpace(getenv("MCP_GATEWAY_AUDIT_REDACT")))
	if err != nil {
		return Values{}, err
	}
	values.RedactAuditMetadata = redactions
	return values, nil
}

func parseAuditRedactions(value string) ([]string, error) {
	if value == "" {
		return nil, nil
	}
	entries := strings.Split(value, ",")
	if len(entries) > 3 {
		return nil, errors.New("MCP_GATEWAY_AUDIT_REDACT supports request_id, client_id, and tool")
	}
	seen := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		if entry != "request_id" && entry != "client_id" && entry != "tool" {
			return nil, errors.New("MCP_GATEWAY_AUDIT_REDACT supports request_id, client_id, and tool")
		}
		if _, exists := seen[entry]; exists {
			return nil, errors.New("MCP_GATEWAY_AUDIT_REDACT entries must be unique")
		}
		seen[entry] = struct{}{}
	}
	return entries, nil
}

func parseAPIKeys(value string) ([]APIKey, error) {
	if value == "" {
		return nil, errors.New("MCP_GATEWAY_API_KEYS must contain at least one hashed API key")
	}
	entries := strings.Split(value, ",")
	if len(entries) > 1000 {
		return nil, errors.New("MCP_GATEWAY_API_KEYS supports at most 1000 entries")
	}
	keys := make([]APIKey, 0, len(entries))
	seenIDs := make(map[string]struct{}, len(entries))
	seenHashes := make(map[[sha256.Size]byte]struct{}, len(entries))
	var zeroHash [sha256.Size]byte
	for _, entry := range entries {
		identifier, digestText, found := strings.Cut(entry, "=")
		if !found || !validAPIKeyIdentifier(identifier) || len(digestText) != sha256.Size*2 {
			return nil, errors.New("MCP_GATEWAY_API_KEYS entries must use safe-id=64-character-sha256-hex")
		}
		digestBytes, err := hex.DecodeString(digestText)
		if err != nil {
			return nil, errors.New("MCP_GATEWAY_API_KEYS entries must use safe-id=64-character-sha256-hex")
		}
		var digest [sha256.Size]byte
		copy(digest[:], digestBytes)
		if digest == zeroHash {
			return nil, errors.New("MCP_GATEWAY_API_KEYS hashes must not be all zeroes")
		}
		if _, exists := seenIDs[identifier]; exists {
			return nil, errors.New("MCP_GATEWAY_API_KEYS identifiers must be unique")
		}
		if _, exists := seenHashes[digest]; exists {
			return nil, errors.New("MCP_GATEWAY_API_KEYS hashes must be unique")
		}
		seenIDs[identifier] = struct{}{}
		seenHashes[digest] = struct{}{}
		keys = append(keys, APIKey{ID: identifier, SHA256: digest})
	}
	return keys, nil
}

// parseToolPolicies parses MCP_GATEWAY_TOOL_POLICIES entries of the form
// client-id:tool=allow|deny. An empty value yields no policies, which denies
// every tools/call by default without affecting other MCP methods.
func parseToolPolicies(value string, apiKeys []APIKey) ([]ToolPolicy, error) {
	if value == "" {
		return nil, nil
	}
	knownClientIDs := make(map[string]struct{}, len(apiKeys))
	for _, key := range apiKeys {
		knownClientIDs[key.ID] = struct{}{}
	}
	entries := strings.Split(value, ",")
	if len(entries) > 1000 {
		return nil, errors.New("MCP_GATEWAY_TOOL_POLICIES supports at most 1000 entries")
	}
	policies := make([]ToolPolicy, 0, len(entries))
	seen := make(map[[2]string]struct{}, len(entries))
	for _, entry := range entries {
		scope, effectText, found := strings.Cut(entry, "=")
		if !found {
			return nil, errors.New("MCP_GATEWAY_TOOL_POLICIES entries must use client-id:tool=allow|deny")
		}
		clientID, tool, found := strings.Cut(scope, ":")
		if !found || !validAPIKeyIdentifier(clientID) || !validToolName.MatchString(tool) {
			return nil, errors.New("MCP_GATEWAY_TOOL_POLICIES entries must use client-id:tool=allow|deny")
		}
		var allow bool
		switch effectText {
		case "allow":
			allow = true
		case "deny":
			allow = false
		default:
			return nil, errors.New("MCP_GATEWAY_TOOL_POLICIES effect must be allow or deny")
		}
		if _, exists := knownClientIDs[clientID]; !exists {
			return nil, errors.New("MCP_GATEWAY_TOOL_POLICIES client id must match a configured API key identifier")
		}
		key := [2]string{clientID, tool}
		if _, exists := seen[key]; exists {
			return nil, errors.New("MCP_GATEWAY_TOOL_POLICIES entries must be unique per client and tool")
		}
		seen[key] = struct{}{}
		policies = append(policies, ToolPolicy{ClientID: clientID, Tool: tool, Allow: allow})
	}
	return policies, nil
}

// parseRateLimits parses MCP_GATEWAY_TOOL_RATE_LIMITS entries of the form
// client-id:tool=capacity/refill-interval (for example client-a:search=10/1s).
// Every allow ToolPolicy must have exactly one matching entry here, and deny
// policies (or pairs with no policy at all) must have none, so the set of
// configured rate limits exactly mirrors the set of allowed tool calls.
func parseRateLimits(value string, apiKeys []APIKey, toolPolicies []ToolPolicy) ([]RateLimit, error) {
	knownClientIDs := make(map[string]struct{}, len(apiKeys))
	for _, key := range apiKeys {
		knownClientIDs[key.ID] = struct{}{}
	}
	allowedPairs := make(map[[2]string]struct{}, len(toolPolicies))
	deniedPairs := make(map[[2]string]struct{}, len(toolPolicies))
	for _, policy := range toolPolicies {
		pair := [2]string{policy.ClientID, policy.Tool}
		if policy.Allow {
			allowedPairs[pair] = struct{}{}
		} else {
			deniedPairs[pair] = struct{}{}
		}
	}

	if value == "" {
		if len(allowedPairs) > 0 {
			return nil, errors.New("MCP_GATEWAY_TOOL_RATE_LIMITS must configure exactly one rate limit per allowed tool policy")
		}
		return nil, nil
	}

	entries := strings.Split(value, ",")
	if len(entries) > 1000 {
		return nil, errors.New("MCP_GATEWAY_TOOL_RATE_LIMITS supports at most 1000 entries")
	}
	limits := make([]RateLimit, 0, len(entries))
	seen := make(map[[2]string]struct{}, len(entries))
	for _, entry := range entries {
		scope, rateText, found := strings.Cut(entry, "=")
		if !found {
			return nil, errors.New("MCP_GATEWAY_TOOL_RATE_LIMITS entries must use client-id:tool=capacity/refill-interval")
		}
		clientID, tool, found := strings.Cut(scope, ":")
		if !found || !validAPIKeyIdentifier(clientID) || !validToolName.MatchString(tool) {
			return nil, errors.New("MCP_GATEWAY_TOOL_RATE_LIMITS entries must use client-id:tool=capacity/refill-interval")
		}
		capacityText, intervalText, found := strings.Cut(rateText, "/")
		if !found {
			return nil, errors.New("MCP_GATEWAY_TOOL_RATE_LIMITS rate must use capacity/refill-interval")
		}
		capacity, err := strconv.ParseUint(capacityText, 10, 32)
		if err != nil || capacity < 1 || capacity > maxRateLimitCapacity {
			return nil, fmt.Errorf("MCP_GATEWAY_TOOL_RATE_LIMITS capacity must be a positive integer no greater than %d", maxRateLimitCapacity)
		}
		interval, err := time.ParseDuration(intervalText)
		if err != nil || interval <= 0 || interval > maxTimeout {
			return nil, fmt.Errorf("MCP_GATEWAY_TOOL_RATE_LIMITS refill interval must be a positive duration no greater than %s", maxTimeout)
		}
		if _, exists := knownClientIDs[clientID]; !exists {
			return nil, errors.New("MCP_GATEWAY_TOOL_RATE_LIMITS client id must match a configured API key identifier")
		}
		pair := [2]string{clientID, tool}
		if _, exists := seen[pair]; exists {
			return nil, errors.New("MCP_GATEWAY_TOOL_RATE_LIMITS entries must be unique per client and tool")
		}
		if _, allowed := allowedPairs[pair]; !allowed {
			if _, denied := deniedPairs[pair]; denied {
				return nil, errors.New("MCP_GATEWAY_TOOL_RATE_LIMITS must not configure a rate limit for a denied tool policy")
			}
			return nil, errors.New("MCP_GATEWAY_TOOL_RATE_LIMITS must not configure a rate limit without a matching allow tool policy")
		}
		seen[pair] = struct{}{}
		limits = append(limits, RateLimit{ClientID: clientID, Tool: tool, Capacity: uint32(capacity), RefillInterval: interval})
	}
	for pair := range allowedPairs {
		if _, exists := seen[pair]; !exists {
			return nil, errors.New("MCP_GATEWAY_TOOL_RATE_LIMITS must configure exactly one rate limit per allowed tool policy")
		}
	}
	return limits, nil
}

func validAPIKeyIdentifier(value string) bool {
	if len(value) < 1 || len(value) > 64 {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') && (character < '0' || character > '9') && character != '.' && character != '_' && character != '-' {
			return false
		}
	}
	return true
}
