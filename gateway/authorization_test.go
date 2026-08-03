package gateway_test

import (
	"bytes"
	"crypto/sha256"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/apraba05/mcp-gateway/gateway"
)

func TestProxyDeniesExplicitlyDeniedToolCallWithoutCallingUpstream(t *testing.T) {
	t.Parallel()

	const rawKey = "client-a-secret"
	hash := sha256.Sum256([]byte(rawKey))
	var upstreamCalls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamCalls.Add(1)
		_, _ = io.WriteString(w, `{}`)
	}))
	defer upstream.Close()
	handler, err := gateway.New(gateway.Config{
		UpstreamURL:      upstream.URL,
		UpstreamTimeout:  time.Second,
		MaxRequestBytes:  1024,
		MaxResponseBytes: 1024,
		APIKeys:          []gateway.APIKey{{ID: "client-a", SHA256: hash}},
		ToolPolicies:     []gateway.ToolPolicy{{ClientID: "client-a", Tool: "delete", Allow: false}},
		Logger:           slog.New(slog.NewJSONHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("new gateway: %v", err)
	}
	request := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBufferString(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete","arguments":{}}}`))
	request.Header.Set("X-MCP-Gateway-Key", rawKey)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%q", response.Code, response.Body.String())
	}
	if upstreamCalls.Load() != 0 {
		t.Fatalf("upstream calls = %d, want 0", upstreamCalls.Load())
	}
}

func TestProxyRejectsToolCallWithoutAValidNameBeforeUpstream(t *testing.T) {
	t.Parallel()

	const rawKey = "client-a-secret"
	hash := sha256.Sum256([]byte(rawKey))
	var upstreamCalls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamCalls.Add(1)
		_, _ = io.WriteString(w, `{}`)
	}))
	defer upstream.Close()
	handler, err := gateway.New(gateway.Config{
		UpstreamURL:      upstream.URL,
		UpstreamTimeout:  time.Second,
		MaxRequestBytes:  1024,
		MaxResponseBytes: 1024,
		APIKeys:          []gateway.APIKey{{ID: "client-a", SHA256: hash}},
		ToolPolicies:     []gateway.ToolPolicy{{ClientID: "client-a", Tool: "search", Allow: true}},
		RateLimits:       []gateway.RateLimit{{ClientID: "client-a", Tool: "search", Capacity: 100, RefillInterval: time.Second}},
		Logger:           slog.New(slog.NewJSONHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("new gateway: %v", err)
	}
	request := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBufferString(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"arguments":{}}}`))
	request.Header.Set("X-MCP-Gateway-Key", rawKey)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%q", response.Code, response.Body.String())
	}
	if upstreamCalls.Load() != 0 {
		t.Fatalf("upstream calls = %d, want 0", upstreamCalls.Load())
	}
}

func TestProxyRejectsMalformedJSONBeforeUpstream(t *testing.T) {
	t.Parallel()

	const rawKey = "client-a-secret"
	hash := sha256.Sum256([]byte(rawKey))
	var upstreamCalls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamCalls.Add(1)
		_, _ = io.WriteString(w, `{}`)
	}))
	defer upstream.Close()
	handler, err := gateway.New(gateway.Config{
		UpstreamURL:      upstream.URL,
		UpstreamTimeout:  time.Second,
		MaxRequestBytes:  1024,
		MaxResponseBytes: 1024,
		APIKeys:          []gateway.APIKey{{ID: "client-a", SHA256: hash}},
		ToolPolicies:     []gateway.ToolPolicy{{ClientID: "client-a", Tool: "search", Allow: true}},
		RateLimits:       []gateway.RateLimit{{ClientID: "client-a", Tool: "search", Capacity: 100, RefillInterval: time.Second}},
		Logger:           slog.New(slog.NewJSONHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("new gateway: %v", err)
	}
	request := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBufferString(`{"jsonrpc":"2.0","id":1,"method":"tools/call"`))
	request.Header.Set("X-MCP-Gateway-Key", rawKey)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%q", response.Code, response.Body.String())
	}
	if upstreamCalls.Load() != 0 {
		t.Fatalf("upstream calls = %d, want 0", upstreamCalls.Load())
	}
}

func TestProxyRejectsDuplicateJSONRPCMethodBeforeUpstream(t *testing.T) {
	t.Parallel()

	const rawKey = "client-a-secret"
	hash := sha256.Sum256([]byte(rawKey))
	var upstreamCalls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamCalls.Add(1)
		_, _ = io.WriteString(w, `{}`)
	}))
	defer upstream.Close()
	handler, err := gateway.New(gateway.Config{
		UpstreamURL:      upstream.URL,
		UpstreamTimeout:  time.Second,
		MaxRequestBytes:  1024,
		MaxResponseBytes: 1024,
		APIKeys:          []gateway.APIKey{{ID: "client-a", SHA256: hash}},
		ToolPolicies:     []gateway.ToolPolicy{{ClientID: "client-a", Tool: "search", Allow: true}},
		RateLimits:       []gateway.RateLimit{{ClientID: "client-a", Tool: "search", Capacity: 100, RefillInterval: time.Second}},
		Logger:           slog.New(slog.NewJSONHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("new gateway: %v", err)
	}
	request := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBufferString(`{"jsonrpc":"2.0","id":1,"method":"tools/call","method":"tools/list","params":{"name":"search"}}`))
	request.Header.Set("X-MCP-Gateway-Key", rawKey)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%q", response.Code, response.Body.String())
	}
	if upstreamCalls.Load() != 0 {
		t.Fatalf("upstream calls = %d, want 0", upstreamCalls.Load())
	}
}

func TestProxyPermitsAllowedToolCallAndPreservesBody(t *testing.T) {
	t.Parallel()

	const rawKey = "client-a-secret"
	const body = `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search","arguments":{"query":"mcp"}}}`
	hash := sha256.Sum256([]byte(rawKey))
	var upstreamBody atomic.Value
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		payload, _ := io.ReadAll(r.Body)
		upstreamBody.Store(string(payload))
		w.WriteHeader(http.StatusAccepted)
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{}}`)
	}))
	defer upstream.Close()
	handler, err := gateway.New(gateway.Config{
		UpstreamURL:      upstream.URL,
		UpstreamTimeout:  time.Second,
		MaxRequestBytes:  1024,
		MaxResponseBytes: 1024,
		APIKeys:          []gateway.APIKey{{ID: "client-a", SHA256: hash}},
		ToolPolicies:     []gateway.ToolPolicy{{ClientID: "client-a", Tool: "search", Allow: true}},
		RateLimits:       []gateway.RateLimit{{ClientID: "client-a", Tool: "search", Capacity: 100, RefillInterval: time.Second}},
		Logger:           slog.New(slog.NewJSONHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("new gateway: %v", err)
	}
	request := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBufferString(body))
	request.Header.Set("X-MCP-Gateway-Key", rawKey)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202; body=%q", response.Code, response.Body.String())
	}
	if got, _ := upstreamBody.Load().(string); got != body {
		t.Fatalf("upstream body = %q, want exact %q", got, body)
	}
}

func TestProxyDeniesUnknownToolByDefaultWithoutCallingUpstream(t *testing.T) {
	t.Parallel()

	const rawKey = "client-a-secret"
	hash := sha256.Sum256([]byte(rawKey))
	var upstreamCalls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamCalls.Add(1)
		_, _ = io.WriteString(w, `{}`)
	}))
	defer upstream.Close()
	handler, err := gateway.New(gateway.Config{
		UpstreamURL:      upstream.URL,
		UpstreamTimeout:  time.Second,
		MaxRequestBytes:  1024,
		MaxResponseBytes: 1024,
		APIKeys:          []gateway.APIKey{{ID: "client-a", SHA256: hash}},
		ToolPolicies:     []gateway.ToolPolicy{{ClientID: "client-a", Tool: "search", Allow: true}},
		RateLimits:       []gateway.RateLimit{{ClientID: "client-a", Tool: "search", Capacity: 100, RefillInterval: time.Second}},
		Logger:           slog.New(slog.NewJSONHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("new gateway: %v", err)
	}
	request := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBufferString(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"unknown"}}`))
	request.Header.Set("X-MCP-Gateway-Key", rawKey)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%q", response.Code, response.Body.String())
	}
	if upstreamCalls.Load() != 0 {
		t.Fatalf("upstream calls = %d, want 0", upstreamCalls.Load())
	}
}

func TestNewRejectsToolPolicyReferencingUnknownClientID(t *testing.T) {
	t.Parallel()

	hash := sha256.Sum256([]byte("client-a-secret"))
	_, err := gateway.New(gateway.Config{
		UpstreamURL:      "http://127.0.0.1:9000/mcp",
		UpstreamTimeout:  time.Second,
		MaxRequestBytes:  1024,
		MaxResponseBytes: 1024,
		APIKeys:          []gateway.APIKey{{ID: "client-a", SHA256: hash}},
		ToolPolicies:     []gateway.ToolPolicy{{ClientID: "client-unknown", Tool: "search", Allow: true}},
		Logger:           slog.New(slog.NewJSONHandler(io.Discard, nil)),
	})
	if err == nil {
		t.Fatal("New accepted a tool policy referencing an unknown client id")
	}
}

func TestNewRejectsDuplicateToolPolicyForSameClientAndTool(t *testing.T) {
	t.Parallel()

	hash := sha256.Sum256([]byte("client-a-secret"))
	_, err := gateway.New(gateway.Config{
		UpstreamURL:      "http://127.0.0.1:9000/mcp",
		UpstreamTimeout:  time.Second,
		MaxRequestBytes:  1024,
		MaxResponseBytes: 1024,
		APIKeys:          []gateway.APIKey{{ID: "client-a", SHA256: hash}},
		ToolPolicies: []gateway.ToolPolicy{
			{ClientID: "client-a", Tool: "search", Allow: true},
			{ClientID: "client-a", Tool: "search", Allow: false},
		},
		Logger: slog.New(slog.NewJSONHandler(io.Discard, nil)),
	})
	if err == nil {
		t.Fatal("New accepted duplicate tool policies for the same client and tool")
	}
}

func TestNewRejectsInvalidToolPolicyToolName(t *testing.T) {
	t.Parallel()

	hash := sha256.Sum256([]byte("client-a-secret"))
	_, err := gateway.New(gateway.Config{
		UpstreamURL:      "http://127.0.0.1:9000/mcp",
		UpstreamTimeout:  time.Second,
		MaxRequestBytes:  1024,
		MaxResponseBytes: 1024,
		APIKeys:          []gateway.APIKey{{ID: "client-a", SHA256: hash}},
		ToolPolicies:     []gateway.ToolPolicy{{ClientID: "client-a", Tool: "un safe tool", Allow: true}},
		Logger:           slog.New(slog.NewJSONHandler(io.Discard, nil)),
	})
	if err == nil {
		t.Fatal("New accepted a tool policy with an unsafe tool name")
	}
}

func TestNewAcceptsNoToolPolicies(t *testing.T) {
	t.Parallel()

	hash := sha256.Sum256([]byte("client-a-secret"))
	_, err := gateway.New(gateway.Config{
		UpstreamURL:      "http://127.0.0.1:9000/mcp",
		UpstreamTimeout:  time.Second,
		MaxRequestBytes:  1024,
		MaxResponseBytes: 1024,
		APIKeys:          []gateway.APIKey{{ID: "client-a", SHA256: hash}},
		Logger:           slog.New(slog.NewJSONHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("New rejected a config with no tool policies: %v", err)
	}
}
