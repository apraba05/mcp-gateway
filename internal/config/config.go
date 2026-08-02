// Package config loads and validates MCP Gateway runtime configuration.
package config

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const maxTimeout = 5 * time.Minute

// maxBodyBytes bounds request and response byte caps to a value safe for a
// memory-constrained host, matching the maxTimeout sanity bound above.
const maxBodyBytes = 64 * 1024 * 1024

// Values is the complete typed runtime configuration.
type Values struct {
	UpstreamURL      string
	ListenAddress    string
	UpstreamTimeout  time.Duration
	ReadTimeout      time.Duration
	WriteTimeout     time.Duration
	IdleTimeout      time.Duration
	MaxRequestBytes  int64
	MaxResponseBytes int64
	APIKeys          []APIKey
}

// APIKey is a safe client identifier and a SHA-256 digest of its raw key.
type APIKey struct {
	ID     string
	SHA256 [sha256.Size]byte
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
	return values, nil
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
