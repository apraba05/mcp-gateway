package config_test

import (
	"testing"

	"github.com/apraba05/mcp-gateway/internal/config"
)

func reliabilityEnvironment() map[string]string {
	return map[string]string{
		"MCP_GATEWAY_UPSTREAM_URL":       "http://127.0.0.1:9000/mcp",
		"MCP_GATEWAY_LISTEN_ADDRESS":     "127.0.0.1:8080",
		"MCP_GATEWAY_UPSTREAM_TIMEOUT":   "3s",
		"MCP_GATEWAY_READ_TIMEOUT":       "5s",
		"MCP_GATEWAY_WRITE_TIMEOUT":      "7s",
		"MCP_GATEWAY_IDLE_TIMEOUT":       "30s",
		"MCP_GATEWAY_MAX_REQUEST_BYTES":  "65536",
		"MCP_GATEWAY_MAX_RESPONSE_BYTES": "131072",
		"MCP_GATEWAY_MAX_IN_FLIGHT":      "17",
		"MCP_GATEWAY_MAX_SAFE_RETRIES":   "2",
		"MCP_GATEWAY_API_KEYS":           "client-a=e0a5091e7f566a51018100473bf5078fe614e6dde73a7592c1161ecd6ec3826a",
	}
}

func TestLoadParsesReliabilityBounds(t *testing.T) {
	t.Parallel()
	environment := reliabilityEnvironment()
	values, err := config.Load(func(key string) string { return environment[key] })
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if values.MaxInFlight != 17 || values.MaxSafeRetries != 2 {
		t.Fatalf("reliability bounds = (%d, %d), want (17, 2)", values.MaxInFlight, values.MaxSafeRetries)
	}
}

func TestLoadRejectsInvalidReliabilityBounds(t *testing.T) {
	t.Parallel()
	for _, testCase := range []struct {
		name, key, value string
	}{
		{"missing max in flight", "MCP_GATEWAY_MAX_IN_FLIGHT", ""},
		{"zero max in flight", "MCP_GATEWAY_MAX_IN_FLIGHT", "0"},
		{"excessive max in flight", "MCP_GATEWAY_MAX_IN_FLIGHT", "100001"},
		{"negative retries", "MCP_GATEWAY_MAX_SAFE_RETRIES", "-1"},
		{"excessive retries", "MCP_GATEWAY_MAX_SAFE_RETRIES", "4"},
	} {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			environment := reliabilityEnvironment()
			environment[testCase.key] = testCase.value
			if _, err := config.Load(func(key string) string { return environment[key] }); err == nil {
				t.Fatalf("Load accepted %s=%q", testCase.key, testCase.value)
			}
		})
	}
}
