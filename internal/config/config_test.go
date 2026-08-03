package config_test

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/apraba05/mcp-gateway/internal/config"
)

func TestLoadParsesHashedAPIKeysAndRejectsPlaintextOrUnsafeIdentifiers(t *testing.T) {
	t.Parallel()

	first := sha256.Sum256([]byte("first-secret"))
	second := sha256.Sum256([]byte("second-secret"))
	base := map[string]string{
		"MCP_GATEWAY_UPSTREAM_URL":       "http://127.0.0.1:9000/mcp",
		"MCP_GATEWAY_LISTEN_ADDRESS":     "127.0.0.1:8080",
		"MCP_GATEWAY_UPSTREAM_TIMEOUT":   "3s",
		"MCP_GATEWAY_READ_TIMEOUT":       "5s",
		"MCP_GATEWAY_WRITE_TIMEOUT":      "7s",
		"MCP_GATEWAY_IDLE_TIMEOUT":       "30s",
		"MCP_GATEWAY_MAX_REQUEST_BYTES":  "65536",
		"MCP_GATEWAY_MAX_RESPONSE_BYTES": "131072",
		"MCP_GATEWAY_API_KEYS":           "client-a=e0a5091e7f566a51018100473bf5078fe614e6dde73a7592c1161ecd6ec3826a",
	}
	base["MCP_GATEWAY_API_KEYS"] = "client-a=" + hex.EncodeToString(first[:]) + ",client_b=" + hex.EncodeToString(second[:])

	values, err := config.Load(func(key string) string { return base[key] })
	if err != nil {
		t.Fatalf("load valid API keys: %v", err)
	}
	if len(values.APIKeys) != 2 || values.APIKeys[0].ID != "client-a" || values.APIKeys[0].SHA256 != first || values.APIKeys[1].ID != "client_b" || values.APIKeys[1].SHA256 != second {
		t.Fatalf("parsed API keys = %#v", values.APIKeys)
	}

	for _, invalid := range []string{"", "client-a=plaintext-secret", "unsafe id=" + hex.EncodeToString(first[:]), "client-a=" + hex.EncodeToString(first[:]) + ",client-a=" + hex.EncodeToString(second[:]), "client-zero=" + strings.Repeat("0", sha256.Size*2)} {
		invalid := invalid
		t.Run(invalid, func(t *testing.T) {
			environment := make(map[string]string, len(base))
			for key, value := range base {
				environment[key] = value
			}
			environment["MCP_GATEWAY_API_KEYS"] = invalid
			if _, err := config.Load(func(key string) string { return environment[key] }); err == nil {
				t.Fatalf("Load accepted MCP_GATEWAY_API_KEYS=%q", invalid)
			}
		})
	}
}

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
		"MCP_GATEWAY_API_KEYS":           "client-a=e0a5091e7f566a51018100473bf5078fe614e6dde73a7592c1161ecd6ec3826a",
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

func TestLoadParsesToolPoliciesAndRejectsInvalidEntries(t *testing.T) {
	t.Parallel()

	first := sha256.Sum256([]byte("first-secret"))
	second := sha256.Sum256([]byte("second-secret"))
	base := map[string]string{
		"MCP_GATEWAY_UPSTREAM_URL":       "http://127.0.0.1:9000/mcp",
		"MCP_GATEWAY_LISTEN_ADDRESS":     "127.0.0.1:8080",
		"MCP_GATEWAY_UPSTREAM_TIMEOUT":   "3s",
		"MCP_GATEWAY_READ_TIMEOUT":       "5s",
		"MCP_GATEWAY_WRITE_TIMEOUT":      "7s",
		"MCP_GATEWAY_IDLE_TIMEOUT":       "30s",
		"MCP_GATEWAY_MAX_REQUEST_BYTES":  "65536",
		"MCP_GATEWAY_MAX_RESPONSE_BYTES": "131072",
		"MCP_GATEWAY_API_KEYS":           "client-a=" + hex.EncodeToString(first[:]) + ",client-b=" + hex.EncodeToString(second[:]),
	}

	base["MCP_GATEWAY_TOOL_POLICIES"] = "client-a:search=allow,client-a:delete=deny,client-b:search=allow"
	values, err := config.Load(func(key string) string { return base[key] })
	if err != nil {
		t.Fatalf("load valid tool policies: %v", err)
	}
	want := []config.ToolPolicy{
		{ClientID: "client-a", Tool: "search", Allow: true},
		{ClientID: "client-a", Tool: "delete", Allow: false},
		{ClientID: "client-b", Tool: "search", Allow: true},
	}
	if len(values.ToolPolicies) != len(want) {
		t.Fatalf("tool policies = %#v", values.ToolPolicies)
	}
	for index, policy := range want {
		if values.ToolPolicies[index] != policy {
			t.Errorf("tool policy[%d] = %#v, want %#v", index, values.ToolPolicies[index], policy)
		}
	}

	for _, invalid := range []string{
		"client-a:search",                            // missing effect
		"client-a:search=maybe",                      // unknown effect
		"client-a=allow",                             // missing tool
		"unsafe id:search=allow",                     // unsafe client id
		"client-a:un safe=allow",                     // unsafe tool name
		"client-a:search=allow,client-a:search=deny", // duplicate client+tool
		"client-unknown:search=allow",                // client id not in API keys
	} {
		invalid := invalid
		t.Run(invalid, func(t *testing.T) {
			environment := make(map[string]string, len(base))
			for key, value := range base {
				environment[key] = value
			}
			environment["MCP_GATEWAY_TOOL_POLICIES"] = invalid
			if _, err := config.Load(func(key string) string { return environment[key] }); err == nil {
				t.Fatalf("Load accepted MCP_GATEWAY_TOOL_POLICIES=%q", invalid)
			}
		})
	}
}

func TestLoadDefaultsToNoToolPoliciesWhenUnset(t *testing.T) {
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
		t.Fatalf("load config without tool policies: %v", err)
	}
	if len(values.ToolPolicies) != 0 {
		t.Fatalf("tool policies = %#v, want none", values.ToolPolicies)
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
		"MCP_GATEWAY_API_KEYS":           "client-a=e0a5091e7f566a51018100473bf5078fe614e6dde73a7592c1161ecd6ec3826a",
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
