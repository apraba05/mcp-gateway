package config_test

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/apraba05/mcp-gateway/internal/config"
)

func rateLimitBaseEnvironment() map[string]string {
	first := sha256.Sum256([]byte("first-secret"))
	second := sha256.Sum256([]byte("second-secret"))
	return map[string]string{
		"MCP_GATEWAY_UPSTREAM_URL":       "http://127.0.0.1:9000/mcp",
		"MCP_GATEWAY_LISTEN_ADDRESS":     "127.0.0.1:8080",
		"MCP_GATEWAY_UPSTREAM_TIMEOUT":   "3s",
		"MCP_GATEWAY_READ_TIMEOUT":       "5s",
		"MCP_GATEWAY_WRITE_TIMEOUT":      "7s",
		"MCP_GATEWAY_IDLE_TIMEOUT":       "30s",
		"MCP_GATEWAY_MAX_REQUEST_BYTES":  "65536",
		"MCP_GATEWAY_MAX_RESPONSE_BYTES": "131072",
		"MCP_GATEWAY_API_KEYS":           "client-a=" + hex.EncodeToString(first[:]) + ",client-b=" + hex.EncodeToString(second[:]),
		"MCP_GATEWAY_TOOL_POLICIES":      "client-a:search=allow,client-a:delete=deny,client-b:search=allow",
	}
}

func TestLoadParsesToolRateLimitsForEveryAllowPolicy(t *testing.T) {
	t.Parallel()

	environment := rateLimitBaseEnvironment()
	environment["MCP_GATEWAY_TOOL_RATE_LIMITS"] = "client-a:search=10/1s,client-b:search=5/500ms"

	values, err := config.Load(func(key string) string { return environment[key] })
	if err != nil {
		t.Fatalf("load valid tool rate limits: %v", err)
	}
	want := []config.RateLimit{
		{ClientID: "client-a", Tool: "search", Capacity: 10, RefillInterval: time.Second},
		{ClientID: "client-b", Tool: "search", Capacity: 5, RefillInterval: 500 * time.Millisecond},
	}
	if len(values.RateLimits) != len(want) {
		t.Fatalf("rate limits = %#v", values.RateLimits)
	}
	for index, limit := range want {
		if values.RateLimits[index] != limit {
			t.Errorf("rate limit[%d] = %#v, want %#v", index, values.RateLimits[index], limit)
		}
	}
}

func TestLoadRejectsAllowPolicyWithoutMatchingRateLimit(t *testing.T) {
	t.Parallel()

	environment := rateLimitBaseEnvironment()
	// client-b:search is allow but has no rate limit entry.
	environment["MCP_GATEWAY_TOOL_RATE_LIMITS"] = "client-a:search=10/1s"

	if _, err := config.Load(func(key string) string { return environment[key] }); err == nil {
		t.Fatal("Load accepted an allow tool policy without a matching rate limit")
	}
}

func TestLoadRejectsRateLimitOnDenyPolicy(t *testing.T) {
	t.Parallel()

	environment := rateLimitBaseEnvironment()
	environment["MCP_GATEWAY_TOOL_RATE_LIMITS"] = "client-a:search=10/1s,client-b:search=5/1s,client-a:delete=1/1s"

	if _, err := config.Load(func(key string) string { return environment[key] }); err == nil {
		t.Fatal("Load accepted a rate limit for an explicitly denied tool policy")
	}
}

func TestLoadRejectsRateLimitWithoutAnyToolPolicy(t *testing.T) {
	t.Parallel()

	environment := rateLimitBaseEnvironment()
	environment["MCP_GATEWAY_TOOL_RATE_LIMITS"] = "client-a:search=10/1s,client-b:search=5/1s,client-a:unknown-tool=1/1s"

	if _, err := config.Load(func(key string) string { return environment[key] }); err == nil {
		t.Fatal("Load accepted a rate limit with no corresponding tool policy at all")
	}
}

func TestLoadDefaultsToNoRateLimitsWhenUnsetAndNoAllowPolicies(t *testing.T) {
	t.Parallel()

	first := sha256.Sum256([]byte("first-secret"))
	environment := map[string]string{
		"MCP_GATEWAY_UPSTREAM_URL":       "http://127.0.0.1:9000/mcp",
		"MCP_GATEWAY_LISTEN_ADDRESS":     "127.0.0.1:8080",
		"MCP_GATEWAY_UPSTREAM_TIMEOUT":   "3s",
		"MCP_GATEWAY_READ_TIMEOUT":       "5s",
		"MCP_GATEWAY_WRITE_TIMEOUT":      "7s",
		"MCP_GATEWAY_IDLE_TIMEOUT":       "30s",
		"MCP_GATEWAY_MAX_REQUEST_BYTES":  "65536",
		"MCP_GATEWAY_MAX_RESPONSE_BYTES": "131072",
		"MCP_GATEWAY_API_KEYS":           "client-a=" + hex.EncodeToString(first[:]),
	}

	values, err := config.Load(func(key string) string { return environment[key] })
	if err != nil {
		t.Fatalf("load config without rate limits: %v", err)
	}
	if len(values.RateLimits) != 0 {
		t.Fatalf("rate limits = %#v, want none", values.RateLimits)
	}
}

func TestLoadRejectsInvalidToolRateLimitEntries(t *testing.T) {
	t.Parallel()

	base := rateLimitBaseEnvironment()
	valid := "client-a:search=10/1s,client-b:search=5/1s"

	for _, testCase := range []struct {
		name  string
		value string
	}{
		{"missing slash", "client-a:search=10,client-b:search=5/1s"},
		{"missing capacity", "client-a:search=/1s,client-b:search=5/1s"},
		{"zero capacity", "client-a:search=0/1s,client-b:search=5/1s"},
		{"negative capacity", "client-a:search=-1/1s,client-b:search=5/1s"},
		{"non-numeric capacity", "client-a:search=abc/1s,client-b:search=5/1s"},
		{"excessive capacity", "client-a:search=100000001/1s,client-b:search=5/1s"},
		{"missing interval", "client-a:search=10/,client-b:search=5/1s"},
		{"zero interval", "client-a:search=10/0s,client-b:search=5/1s"},
		{"negative interval", "client-a:search=10/-1s,client-b:search=5/1s"},
		{"invalid interval syntax", "client-a:search=10/notaduration,client-b:search=5/1s"},
		{"excessive interval", "client-a:search=10/6m,client-b:search=5/1s"},
		{"unsafe client id", "unsafe id:search=10/1s,client-b:search=5/1s"},
		{"unsafe tool name", "client-a:un safe=10/1s,client-b:search=5/1s"},
		{"unknown client id", valid + ",client-unknown:search=10/1s"},
		{"duplicate client and tool", "client-a:search=10/1s,client-a:search=1/1s,client-b:search=5/1s"},
	} {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			environment := make(map[string]string, len(base))
			for key, value := range base {
				environment[key] = value
			}
			environment["MCP_GATEWAY_TOOL_RATE_LIMITS"] = testCase.value
			if _, err := config.Load(func(key string) string { return environment[key] }); err == nil {
				t.Fatalf("Load accepted MCP_GATEWAY_TOOL_RATE_LIMITS=%q", testCase.value)
			}
		})
	}
}

func TestLoadCapsToolRateLimitCardinalityAtOneThousand(t *testing.T) {
	t.Parallel()

	first := sha256.Sum256([]byte("first-secret"))
	environment := map[string]string{
		"MCP_GATEWAY_UPSTREAM_URL":       "http://127.0.0.1:9000/mcp",
		"MCP_GATEWAY_LISTEN_ADDRESS":     "127.0.0.1:8080",
		"MCP_GATEWAY_UPSTREAM_TIMEOUT":   "3s",
		"MCP_GATEWAY_READ_TIMEOUT":       "5s",
		"MCP_GATEWAY_WRITE_TIMEOUT":      "7s",
		"MCP_GATEWAY_IDLE_TIMEOUT":       "30s",
		"MCP_GATEWAY_MAX_REQUEST_BYTES":  "65536",
		"MCP_GATEWAY_MAX_RESPONSE_BYTES": "131072",
		"MCP_GATEWAY_API_KEYS":           "client-a=" + hex.EncodeToString(first[:]),
	}

	toolPolicies := make([]string, 0, 1001)
	rateLimits := make([]string, 0, 1001)
	for i := 0; i < 1001; i++ {
		tool := "tool" + itoa(i)
		toolPolicies = append(toolPolicies, "client-a:"+tool+"=allow")
		rateLimits = append(rateLimits, "client-a:"+tool+"=1/1s")
	}
	environment["MCP_GATEWAY_TOOL_POLICIES"] = strings.Join(toolPolicies, ",")
	environment["MCP_GATEWAY_TOOL_RATE_LIMITS"] = strings.Join(rateLimits, ",")

	if _, err := config.Load(func(key string) string { return environment[key] }); err == nil {
		t.Fatal("Load accepted more than 1000 tool rate limit entries")
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	digits := []byte{}
	for i > 0 {
		digits = append([]byte{byte('0' + i%10)}, digits...)
		i /= 10
	}
	return string(digits)
}
