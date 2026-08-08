package gateway_test

import (
	"crypto/sha256"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/apraba05/mcp-gateway/gateway"
)

func rateLimitConfigFixture() gateway.Config {
	hash := sha256.Sum256([]byte("client-a-secret"))
	return gateway.Config{
		UpstreamURL:      "http://127.0.0.1:9000/mcp",
		UpstreamTimeout:  time.Second,
		MaxRequestBytes:  1024,
		MaxResponseBytes: 1024,
		MaxInFlight:      64,
		APIKeys:          []gateway.APIKey{{ID: "client-a", SHA256: hash}},
		ToolPolicies:     []gateway.ToolPolicy{{ClientID: "client-a", Tool: "search", Allow: true}, {ClientID: "client-a", Tool: "delete", Allow: false}},
		Logger:           slog.New(slog.NewJSONHandler(io.Discard, nil)),
	}
}

func TestNewAcceptsRateLimitMatchingEveryAllowPolicy(t *testing.T) {
	t.Parallel()

	cfg := rateLimitConfigFixture()
	cfg.RateLimits = []gateway.RateLimit{{ClientID: "client-a", Tool: "search", Capacity: 5, RefillInterval: time.Second}}
	if _, err := gateway.New(cfg); err != nil {
		t.Fatalf("New rejected a valid matching rate limit: %v", err)
	}
}

func TestNewRejectsAllowPolicyWithoutMatchingRateLimit(t *testing.T) {
	t.Parallel()

	cfg := rateLimitConfigFixture()
	// No RateLimits entry at all, even though client-a:search is allowed.
	if _, err := gateway.New(cfg); err == nil {
		t.Fatal("New accepted an allow tool policy without a matching rate limit")
	}
}

func TestNewRejectsRateLimitOnDeniedToolPolicy(t *testing.T) {
	t.Parallel()

	cfg := rateLimitConfigFixture()
	cfg.RateLimits = []gateway.RateLimit{
		{ClientID: "client-a", Tool: "search", Capacity: 5, RefillInterval: time.Second},
		{ClientID: "client-a", Tool: "delete", Capacity: 5, RefillInterval: time.Second},
	}
	if _, err := gateway.New(cfg); err == nil {
		t.Fatal("New accepted a rate limit for an explicitly denied tool policy")
	}
}

func TestNewRejectsRateLimitWithoutMatchingToolPolicy(t *testing.T) {
	t.Parallel()

	cfg := rateLimitConfigFixture()
	cfg.RateLimits = []gateway.RateLimit{
		{ClientID: "client-a", Tool: "search", Capacity: 5, RefillInterval: time.Second},
		{ClientID: "client-a", Tool: "unknown-tool", Capacity: 5, RefillInterval: time.Second},
	}
	if _, err := gateway.New(cfg); err == nil {
		t.Fatal("New accepted a rate limit with no corresponding tool policy")
	}
}

func TestNewRejectsDuplicateRateLimitForSameClientAndTool(t *testing.T) {
	t.Parallel()

	cfg := rateLimitConfigFixture()
	cfg.RateLimits = []gateway.RateLimit{
		{ClientID: "client-a", Tool: "search", Capacity: 5, RefillInterval: time.Second},
		{ClientID: "client-a", Tool: "search", Capacity: 1, RefillInterval: time.Second},
	}
	if _, err := gateway.New(cfg); err == nil {
		t.Fatal("New accepted duplicate rate limits for the same client and tool")
	}
}

func TestNewRejectsRateLimitWithZeroCapacity(t *testing.T) {
	t.Parallel()

	cfg := rateLimitConfigFixture()
	cfg.RateLimits = []gateway.RateLimit{{ClientID: "client-a", Tool: "search", Capacity: 0, RefillInterval: time.Second}}
	if _, err := gateway.New(cfg); err == nil {
		t.Fatal("New accepted a rate limit with zero capacity")
	}
}

func TestNewRejectsRateLimitWithExcessiveCapacity(t *testing.T) {
	t.Parallel()

	cfg := rateLimitConfigFixture()
	cfg.RateLimits = []gateway.RateLimit{{ClientID: "client-a", Tool: "search", Capacity: 100_000_001, RefillInterval: time.Second}}
	if _, err := gateway.New(cfg); err == nil {
		t.Fatal("New accepted a rate limit with excessive capacity")
	}
}

func TestNewRejectsRateLimitWithNonPositiveRefillInterval(t *testing.T) {
	t.Parallel()

	cfg := rateLimitConfigFixture()
	cfg.RateLimits = []gateway.RateLimit{{ClientID: "client-a", Tool: "search", Capacity: 5, RefillInterval: 0}}
	if _, err := gateway.New(cfg); err == nil {
		t.Fatal("New accepted a rate limit with a non-positive refill interval")
	}
}

func TestNewRejectsRateLimitWithExcessiveRefillInterval(t *testing.T) {
	t.Parallel()

	cfg := rateLimitConfigFixture()
	cfg.RateLimits = []gateway.RateLimit{{ClientID: "client-a", Tool: "search", Capacity: 5, RefillInterval: 6 * time.Minute}}
	if _, err := gateway.New(cfg); err == nil {
		t.Fatal("New accepted a rate limit with an excessive refill interval")
	}
}

func TestNewRejectsMoreThanOneThousandRateLimits(t *testing.T) {
	t.Parallel()

	hash := sha256.Sum256([]byte("client-a-secret"))
	toolPolicies := make([]gateway.ToolPolicy, 0, 1001)
	rateLimits := make([]gateway.RateLimit, 0, 1001)
	for i := 0; i < 1001; i++ {
		tool := "tool" + string(rune('a'+i%26)) + string(rune('A'+(i/26)%26))
		toolPolicies = append(toolPolicies, gateway.ToolPolicy{ClientID: "client-a", Tool: tool, Allow: true})
		rateLimits = append(rateLimits, gateway.RateLimit{ClientID: "client-a", Tool: tool, Capacity: 1, RefillInterval: time.Second})
	}
	cfg := gateway.Config{
		UpstreamURL:      "http://127.0.0.1:9000/mcp",
		UpstreamTimeout:  time.Second,
		MaxRequestBytes:  1024,
		MaxResponseBytes: 1024,
		MaxInFlight:      64,
		APIKeys:          []gateway.APIKey{{ID: "client-a", SHA256: hash}},
		ToolPolicies:     toolPolicies,
		RateLimits:       rateLimits,
		Logger:           slog.New(slog.NewJSONHandler(io.Discard, nil)),
	}
	if _, err := gateway.New(cfg); err == nil {
		t.Fatal("New accepted more than 1000 rate limits")
	}
}
