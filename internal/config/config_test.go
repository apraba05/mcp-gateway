package config_test

import (
	"testing"
	"time"

	"github.com/apraba05/mcp-gateway/internal/config"
)

func TestLoadRejectsUpstreamURLWithoutHostname(t *testing.T) {
	t.Parallel()

	environment := map[string]string{
		"MCP_GATEWAY_UPSTREAM_URL":     "http://:9000/mcp",
		"MCP_GATEWAY_LISTEN_ADDRESS":   "127.0.0.1:8080",
		"MCP_GATEWAY_UPSTREAM_TIMEOUT": "3s",
		"MCP_GATEWAY_READ_TIMEOUT":     "5s",
		"MCP_GATEWAY_WRITE_TIMEOUT":    "7s",
		"MCP_GATEWAY_IDLE_TIMEOUT":     "30s",
	}

	if _, err := config.Load(func(key string) string { return environment[key] }); err == nil {
		t.Fatal("Load accepted upstream URL without hostname")
	}
}

func TestLoadRejectsInvalidListenerPorts(t *testing.T) {
	t.Parallel()

	for _, address := range []string{"localhost:", "localhost:http", "localhost:+8080", "localhost:0", "localhost:70000"} {
		address := address
		t.Run(address, func(t *testing.T) {
			t.Parallel()
			environment := map[string]string{
				"MCP_GATEWAY_UPSTREAM_URL":     "http://127.0.0.1:9000/mcp",
				"MCP_GATEWAY_LISTEN_ADDRESS":   address,
				"MCP_GATEWAY_UPSTREAM_TIMEOUT": "3s",
				"MCP_GATEWAY_READ_TIMEOUT":     "5s",
				"MCP_GATEWAY_WRITE_TIMEOUT":    "7s",
				"MCP_GATEWAY_IDLE_TIMEOUT":     "30s",
			}

			if _, err := config.Load(func(key string) string { return environment[key] }); err == nil {
				t.Fatalf("Load accepted listener address %q", address)
			}
		})
	}
}

func TestLoadParsesTypedConfiguration(t *testing.T) {
	t.Parallel()

	environment := map[string]string{
		"MCP_GATEWAY_UPSTREAM_URL":       "http://127.0.0.1:9000/mcp",
		"MCP_GATEWAY_LISTEN_ADDRESS":     "127.0.0.1:8080",
		"MCP_GATEWAY_UPSTREAM_TIMEOUT":   "3s",
		"MCP_GATEWAY_READ_TIMEOUT":       "5s",
		"MCP_GATEWAY_WRITE_TIMEOUT":      "7s",
		"MCP_GATEWAY_IDLE_TIMEOUT":       "30s",
		"MCP_GATEWAY_MAX_REQUEST_BYTES":  "65536",
		"MCP_GATEWAY_MAX_RESPONSE_BYTES": "131072",
	}

	got, err := config.Load(func(key string) string { return environment[key] })
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if got.UpstreamURL != environment["MCP_GATEWAY_UPSTREAM_URL"] || got.ListenAddress != environment["MCP_GATEWAY_LISTEN_ADDRESS"] {
		t.Errorf("string config = %#v", got)
	}
	if got.UpstreamTimeout != 3*time.Second || got.ReadTimeout != 5*time.Second || got.WriteTimeout != 7*time.Second || got.IdleTimeout != 30*time.Second {
		t.Errorf("duration config = %#v", got)
	}
	if got.MaxRequestBytes != 65536 || got.MaxResponseBytes != 131072 {
		t.Errorf("byte cap config = %#v", got)
	}
}

func TestLoadRejectsNonPositiveByteCaps(t *testing.T) {
	t.Parallel()

	baseEnvironment := map[string]string{
		"MCP_GATEWAY_UPSTREAM_URL":       "http://127.0.0.1:9000/mcp",
		"MCP_GATEWAY_LISTEN_ADDRESS":     "127.0.0.1:8080",
		"MCP_GATEWAY_UPSTREAM_TIMEOUT":   "3s",
		"MCP_GATEWAY_READ_TIMEOUT":       "5s",
		"MCP_GATEWAY_WRITE_TIMEOUT":      "7s",
		"MCP_GATEWAY_IDLE_TIMEOUT":       "30s",
		"MCP_GATEWAY_MAX_REQUEST_BYTES":  "65536",
		"MCP_GATEWAY_MAX_RESPONSE_BYTES": "131072",
	}

	for _, testCase := range []struct {
		name  string
		key   string
		value string
	}{
		{"request zero", "MCP_GATEWAY_MAX_REQUEST_BYTES", "0"},
		{"request negative", "MCP_GATEWAY_MAX_REQUEST_BYTES", "-1"},
		{"request not a number", "MCP_GATEWAY_MAX_REQUEST_BYTES", "big"},
		{"request too large", "MCP_GATEWAY_MAX_REQUEST_BYTES", "99999999999"},
		{"response zero", "MCP_GATEWAY_MAX_RESPONSE_BYTES", "0"},
		{"response negative", "MCP_GATEWAY_MAX_RESPONSE_BYTES", "-1"},
		{"response not a number", "MCP_GATEWAY_MAX_RESPONSE_BYTES", "big"},
		{"response too large", "MCP_GATEWAY_MAX_RESPONSE_BYTES", "99999999999"},
	} {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			environment := map[string]string{}
			for key, value := range baseEnvironment {
				environment[key] = value
			}
			environment[testCase.key] = testCase.value

			if _, err := config.Load(func(key string) string { return environment[key] }); err == nil {
				t.Fatalf("Load accepted %s=%q", testCase.key, testCase.value)
			}
		})
	}
}
