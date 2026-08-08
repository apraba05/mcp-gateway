package gateway_test

import (
	"bytes"
	"crypto/sha256"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/apraba05/mcp-gateway/gateway"
)

// FuzzServeHTTPBoundaries fuzzes raw /mcp request bodies against a handler
// configured with one allowed and one denied tool, looking for panics and
// contract violations in JSON-RPC parsing and tool-policy authorization. It
// checks the one invariant documented in the README that is cheap to verify
// on arbitrary bytes: every pre-upstream rejection (malformed/invalid body,
// denied/unlisted tool, exhausted rate limit, oversized body) must never
// reach the upstream fixture. Inputs are capped so a single corpus entry
// cannot exhaust memory on a 1 vCPU/4 GB host.
func FuzzServeHTTPBoundaries(f *testing.F) {
	for _, seed := range [][]byte{
		[]byte(`{}`),
		[]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search","arguments":{}}}`),
		[]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"blocked"}}`),
		[]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"unlisted-tool"}}`),
		[]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","method":"tools/list"}`),
		[]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search","name":"blocked"}}`),
		[]byte(`[{"jsonrpc":"2.0","id":1,"method":"ping"}]`),
		[]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call"`),
		[]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":123}}`),
		[]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":"not-an-object"}`),
		[]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":""}}`),
		[]byte(`null`),
		[]byte(``),
		[]byte(`{"jsonrpc":"2.0","id":1,"method":123}`),
		[]byte("\x00\x01\x02{}"),
		[]byte(`{"jsonrpc":"2.0","id":1,"method":"ping","method":"ping"}`),
	} {
		f.Add(seed)
	}

	const rawKey = "fuzz-boundary-test-key"
	hash := sha256.Sum256([]byte(rawKey))
	var upstreamCalls int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt64(&upstreamCalls, 1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{}}`)
	}))
	f.Cleanup(upstream.Close)

	handler, err := gateway.New(gateway.Config{
		UpstreamURL:      upstream.URL,
		UpstreamTimeout:  2 * time.Second,
		MaxRequestBytes:  1 << 20,
		MaxResponseBytes: 1 << 20,
		MaxInFlight:      64,
		APIKeys:          []gateway.APIKey{{ID: "fuzz-client", SHA256: hash}},
		ToolPolicies: []gateway.ToolPolicy{
			{ClientID: "fuzz-client", Tool: "search", Allow: true},
			{ClientID: "fuzz-client", Tool: "blocked", Allow: false},
		},
		RateLimits: []gateway.RateLimit{
			{ClientID: "fuzz-client", Tool: "search", Capacity: 100_000_000, RefillInterval: time.Millisecond},
		},
		Logger: slog.New(slog.NewJSONHandler(io.Discard, nil)),
	})
	if err != nil {
		f.Fatalf("new gateway: %v", err)
	}

	f.Fuzz(func(t *testing.T, body []byte) {
		if len(body) > 4096 {
			t.Skip("bounded fuzz input size")
		}
		before := atomic.LoadInt64(&upstreamCalls)
		request := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(body))
		request.Header.Set("X-MCP-Gateway-Key", rawKey)
		response := httptest.NewRecorder()

		handler.ServeHTTP(response, request)

		if response.Code < 100 || response.Code > 599 {
			t.Fatalf("invalid HTTP status %d", response.Code)
		}
		switch response.Code {
		case http.StatusBadRequest, http.StatusForbidden, http.StatusTooManyRequests, http.StatusRequestEntityTooLarge:
			if after := atomic.LoadInt64(&upstreamCalls); after != before {
				t.Fatalf("status %d must reject before calling upstream, but upstream call count changed %d -> %d", response.Code, before, after)
			}
		}
	})
}

// FuzzAuthenticationHeader fuzzes the raw X-MCP-Gateway-Key header value
// against a handler with one configured API key, checking through exported
// ServeHTTP behavior that authentication succeeds if and only if the fuzzed
// value's SHA-256 digest matches the configured hash (which, absent a
// SHA-256 collision, only the known exact key can produce).
func FuzzAuthenticationHeader(f *testing.F) {
	const rawKey = "fuzz-auth-boundary-secret"
	hash := sha256.Sum256([]byte(rawKey))

	for _, seed := range []string{
		"",
		" ",
		"a,b",
		strings.Repeat("x", 257),
		strings.Repeat("x", 256),
		"\x00",
		"key-with-\ttab",
		rawKey,
		rawKey + ",",
	} {
		f.Add(seed)
	}

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{}}`)
	}))
	f.Cleanup(upstream.Close)

	handler, err := gateway.New(gateway.Config{
		UpstreamURL:      upstream.URL,
		UpstreamTimeout:  2 * time.Second,
		MaxRequestBytes:  1024,
		MaxResponseBytes: 1024,
		MaxInFlight:      64,
		APIKeys:          []gateway.APIKey{{ID: "fuzz-client", SHA256: hash}},
		Logger:           slog.New(slog.NewJSONHandler(io.Discard, nil)),
	})
	if err != nil {
		f.Fatalf("new gateway: %v", err)
	}

	f.Fuzz(func(t *testing.T, key string) {
		if len(key) > 4096 {
			t.Skip("bounded fuzz input size")
		}
		digest := sha256.Sum256([]byte(key))
		expectAuthenticated := digest == hash && len(key) <= 256 && !strings.Contains(key, ",") && strings.TrimSpace(key) != ""

		request := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBufferString(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
		request.Header.Set("X-MCP-Gateway-Key", key)
		response := httptest.NewRecorder()

		handler.ServeHTTP(response, request)

		if expectAuthenticated && response.Code == http.StatusUnauthorized {
			t.Fatalf("key matching configured hash (len=%d) was rejected with 401", len(key))
		}
		if !expectAuthenticated && response.Code != http.StatusUnauthorized {
			t.Fatalf("key not matching configured hash (len=%d) was accepted with status %d", len(key), response.Code)
		}
	})
}
