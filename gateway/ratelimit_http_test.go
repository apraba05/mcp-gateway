package gateway_test

import (
	"bytes"
	"crypto/sha256"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/apraba05/mcp-gateway/gateway"
)

func TestProxyRateLimitsAllowedToolBeforeUpstreamAndRefillsDeterministically(t *testing.T) {
	t.Parallel()

	const rawKey = "client-a-secret"
	const payload = `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search","arguments":{"secret":"do-not-log"}}}`
	hash := sha256.Sum256([]byte(rawKey))
	var upstreamCalls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamCalls.Add(1)
		w.WriteHeader(http.StatusAccepted)
		_, _ = io.WriteString(w, `{}`)
	}))
	defer upstream.Close()

	now := time.Date(2026, 8, 3, 0, 0, 0, 0, time.UTC)
	var clockMu sync.Mutex
	clock := func() time.Time {
		clockMu.Lock()
		defer clockMu.Unlock()
		return now
	}
	var logs bytes.Buffer
	handler, err := gateway.New(gateway.Config{
		UpstreamURL:      upstream.URL,
		UpstreamTimeout:  time.Second,
		MaxRequestBytes:  1024,
		MaxResponseBytes: 1024,
		APIKeys:          []gateway.APIKey{{ID: "client-a", SHA256: hash}},
		ToolPolicies:     []gateway.ToolPolicy{{ClientID: "client-a", Tool: "search", Allow: true}},
		RateLimits:       []gateway.RateLimit{{ClientID: "client-a", Tool: "search", Capacity: 1, RefillInterval: 1500 * time.Millisecond}},
		Logger:           slog.New(slog.NewJSONHandler(&logs, nil)),
		Clock:            clock,
	})
	if err != nil {
		t.Fatalf("new gateway: %v", err)
	}

	doRequest := func() *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(payload))
		request.Header.Set("X-MCP-Gateway-Key", rawKey)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response
	}

	if response := doRequest(); response.Code != http.StatusAccepted {
		t.Fatalf("first status = %d, want 202", response.Code)
	}
	limited := doRequest()
	if limited.Code != http.StatusTooManyRequests {
		t.Fatalf("limited status = %d, want 429; body=%q", limited.Code, limited.Body.String())
	}
	if got := limited.Header().Get("Retry-After"); got != "2" {
		t.Fatalf("Retry-After = %q, want %q", got, "2")
	}
	if got := limited.Header().Get("X-RateLimit-Retry-After-Ms"); got != "1500" {
		t.Fatalf("X-RateLimit-Retry-After-Ms = %q, want %q", got, "1500")
	}
	if upstreamCalls.Load() != 1 {
		t.Fatalf("upstream calls while limited = %d, want 1", upstreamCalls.Load())
	}
	combined := limited.Body.String() + logs.String()
	for _, forbidden := range []string{rawKey, "search", "do-not-log"} {
		if strings.Contains(combined, forbidden) {
			t.Fatalf("limited response/logs leaked %q: %q", forbidden, combined)
		}
	}

	clockMu.Lock()
	now = now.Add(1500 * time.Millisecond)
	clockMu.Unlock()
	if response := doRequest(); response.Code != http.StatusAccepted {
		t.Fatalf("post-refill status = %d, want 202", response.Code)
	}
	if upstreamCalls.Load() != 2 {
		t.Fatalf("upstream calls after refill = %d, want 2", upstreamCalls.Load())
	}
}

func TestProxyRateLimitBucketsAreIsolatedByClientAndTool(t *testing.T) {
	t.Parallel()

	const keyA = "client-a-secret"
	const keyB = "client-b-secret"
	hashA := sha256.Sum256([]byte(keyA))
	hashB := sha256.Sum256([]byte(keyB))
	var upstreamCalls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamCalls.Add(1)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer upstream.Close()

	handler, err := gateway.New(gateway.Config{
		UpstreamURL:      upstream.URL,
		UpstreamTimeout:  time.Second,
		MaxRequestBytes:  1024,
		MaxResponseBytes: 1024,
		APIKeys: []gateway.APIKey{
			{ID: "client-a", SHA256: hashA},
			{ID: "client-b", SHA256: hashB},
		},
		ToolPolicies: []gateway.ToolPolicy{
			{ClientID: "client-a", Tool: "search", Allow: true},
			{ClientID: "client-a", Tool: "lookup", Allow: true},
			{ClientID: "client-b", Tool: "search", Allow: true},
		},
		RateLimits: []gateway.RateLimit{
			{ClientID: "client-a", Tool: "search", Capacity: 1, RefillInterval: 5 * time.Minute},
			{ClientID: "client-a", Tool: "lookup", Capacity: 1, RefillInterval: 5 * time.Minute},
			{ClientID: "client-b", Tool: "search", Capacity: 1, RefillInterval: 5 * time.Minute},
		},
		Logger: slog.New(slog.NewJSONHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("new gateway: %v", err)
	}

	call := func(key, tool string) int {
		body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"` + tool + `"}}`
		request := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
		request.Header.Set("X-MCP-Gateway-Key", key)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response.Code
	}

	if got := call(keyA, "search"); got != http.StatusAccepted {
		t.Fatalf("client-a/search first status = %d, want 202", got)
	}
	if got := call(keyA, "search"); got != http.StatusTooManyRequests {
		t.Fatalf("client-a/search second status = %d, want 429", got)
	}
	if got := call(keyA, "lookup"); got != http.StatusAccepted {
		t.Fatalf("client-a/lookup status = %d, want 202", got)
	}
	if got := call(keyB, "search"); got != http.StatusAccepted {
		t.Fatalf("client-b/search status = %d, want 202", got)
	}
	if upstreamCalls.Load() != 3 {
		t.Fatalf("upstream calls = %d, want 3", upstreamCalls.Load())
	}
}
