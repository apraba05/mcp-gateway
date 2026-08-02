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

const legacyTestAPIKey = "mcp_gateway_existing_test_key"

type authenticatedTestHandler struct{ http.Handler }

func (handler authenticatedTestHandler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	request.Header.Set("X-MCP-Gateway-Key", legacyTestAPIKey)
	handler.Handler.ServeHTTP(response, request)
}

func testAPIKeys() []gateway.APIKey {
	hash := sha256.Sum256([]byte(legacyTestAPIKey))
	return []gateway.APIKey{{ID: "legacy-test-client", SHA256: hash}}
}

func newTestGateway(cfg gateway.Config) (http.Handler, error) {
	cfg.APIKeys = testAPIKeys()
	handler, err := gateway.New(cfg)
	if err != nil {
		return nil, err
	}
	return authenticatedTestHandler{Handler: handler}, nil
}

func TestProxyAuthenticatesHashedAPIKeyWithoutForwardingGatewayCredential(t *testing.T) {
	t.Parallel()

	const rawKey = "mcp_test_super_secret_value"
	hash := sha256.Sum256([]byte(rawKey))
	var upstreamCalls int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&upstreamCalls, 1)
		if got := r.Header.Get("X-MCP-Gateway-Key"); got != "" {
			t.Errorf("gateway credential forwarded upstream: %q", got)
		}
		_, _ = io.WriteString(w, `{}`)
	}))
	defer upstream.Close()

	handler, err := gateway.New(gateway.Config{
		UpstreamURL:      upstream.URL,
		UpstreamTimeout:  time.Second,
		MaxRequestBytes:  1024,
		MaxResponseBytes: 1024,
		APIKeys:          []gateway.APIKey{{ID: "client-a", SHA256: hash}},
		Logger:           slog.New(slog.NewJSONHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("new gateway: %v", err)
	}
	request := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBufferString(`{}`))
	request.Header.Set("X-MCP-Gateway-Key", rawKey)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%q", response.Code, response.Body.String())
	}
	if atomic.LoadInt32(&upstreamCalls) != 1 {
		t.Fatalf("upstream calls = %d, want 1", upstreamCalls)
	}
}

func TestProxyDeniesMissingOrInvalidAPIKeyWithoutLeakingCredential(t *testing.T) {
	t.Parallel()

	const validKey = "mcp_valid_secret_value"
	const invalidKey = "mcp_invalid_must_not_leak"
	hash := sha256.Sum256([]byte(validKey))
	var upstreamCalls int32
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		atomic.AddInt32(&upstreamCalls, 1)
	}))
	defer upstream.Close()
	var logs bytes.Buffer
	handler, err := gateway.New(gateway.Config{
		UpstreamURL:      upstream.URL,
		UpstreamTimeout:  time.Second,
		MaxRequestBytes:  1024,
		MaxResponseBytes: 1024,
		APIKeys:          []gateway.APIKey{{ID: "client-a", SHA256: hash}},
		Logger:           slog.New(slog.NewJSONHandler(&logs, nil)),
	})
	if err != nil {
		t.Fatalf("new gateway: %v", err)
	}

	for _, key := range []string{"", invalidKey} {
		request := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{}`))
		request.Header.Set("X-MCP-Gateway-Key", key)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusUnauthorized {
			t.Errorf("key %q: status = %d, want 401", key, response.Code)
		}
		if strings.Contains(response.Body.String(), key) && key != "" {
			t.Errorf("error body leaked credential: %q", response.Body.String())
		}
	}
	if atomic.LoadInt32(&upstreamCalls) != 0 {
		t.Errorf("upstream calls = %d, want 0", upstreamCalls)
	}
	if strings.Contains(logs.String(), validKey) || strings.Contains(logs.String(), invalidKey) {
		t.Fatalf("logs leaked API key: %q", logs.String())
	}
}

func TestNewRejectsEmptyAPIKeySet(t *testing.T) {
	t.Parallel()

	_, err := gateway.New(gateway.Config{
		UpstreamURL:      "http://127.0.0.1:9000/mcp",
		UpstreamTimeout:  time.Second,
		MaxRequestBytes:  1024,
		MaxResponseBytes: 1024,
		Logger:           slog.New(slog.NewJSONHandler(io.Discard, nil)),
	})
	if err == nil {
		t.Fatal("New accepted an empty API key set")
	}
}

func TestNewRejectsDuplicateAPIKeyHashes(t *testing.T) {
	t.Parallel()

	hash := sha256.Sum256([]byte("same-key"))
	_, err := gateway.New(gateway.Config{
		UpstreamURL:      "http://127.0.0.1:9000/mcp",
		UpstreamTimeout:  time.Second,
		MaxRequestBytes:  1024,
		MaxResponseBytes: 1024,
		APIKeys: []gateway.APIKey{
			{ID: "client-a", SHA256: hash},
			{ID: "client-b", SHA256: hash},
		},
		Logger: slog.New(slog.NewJSONHandler(io.Discard, nil)),
	})
	if err == nil {
		t.Fatal("New accepted duplicate API key hashes")
	}
}

func TestNewRejectsZeroValueAPIKeyHash(t *testing.T) {
	t.Parallel()

	_, err := gateway.New(gateway.Config{
		UpstreamURL:      "http://127.0.0.1:9000/mcp",
		UpstreamTimeout:  time.Second,
		MaxRequestBytes:  1024,
		MaxResponseBytes: 1024,
		APIKeys:          []gateway.APIKey{{ID: "client-a", SHA256: [sha256.Size]byte{}}},
		Logger:           slog.New(slog.NewJSONHandler(io.Discard, nil)),
	})
	if err == nil {
		t.Fatal("New accepted an all-zero API key hash")
	}
}

func TestProxyRejectsMultipleAPIKeyHeaderValues(t *testing.T) {
	t.Parallel()

	const validKey = "mcp_valid_secret_value"
	hash := sha256.Sum256([]byte(validKey))
	handler, err := gateway.New(gateway.Config{
		UpstreamURL:      "http://127.0.0.1:9000/mcp",
		UpstreamTimeout:  time.Second,
		MaxRequestBytes:  1024,
		MaxResponseBytes: 1024,
		APIKeys:          []gateway.APIKey{{ID: "client-a", SHA256: hash}},
		Logger:           slog.New(slog.NewJSONHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("new gateway: %v", err)
	}
	request := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{}`))
	request.Header["X-Mcp-Gateway-Key"] = []string{validKey, "second-value"}
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", response.Code)
	}
}

func TestProxyRejectsCommaJoinedAPIKeyHeader(t *testing.T) {
	t.Parallel()

	const rawKey = "first,second"
	hash := sha256.Sum256([]byte(rawKey))
	handler, err := gateway.New(gateway.Config{
		UpstreamURL:      "http://127.0.0.1:9000/mcp",
		UpstreamTimeout:  time.Second,
		MaxRequestBytes:  1024,
		MaxResponseBytes: 1024,
		APIKeys:          []gateway.APIKey{{ID: "client-a", SHA256: hash}},
		Logger:           slog.New(slog.NewJSONHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("new gateway: %v", err)
	}
	request := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{}`))
	request.Header.Set("X-MCP-Gateway-Key", rawKey)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", response.Code)
	}
}

func TestProxyRejectsOversizedAPIKeyEvenIfItsHashIsConfigured(t *testing.T) {
	t.Parallel()

	rawKey := strings.Repeat("k", 257)
	hash := sha256.Sum256([]byte(rawKey))
	handler, err := gateway.New(gateway.Config{
		UpstreamURL:      "http://127.0.0.1:9000/mcp",
		UpstreamTimeout:  time.Second,
		MaxRequestBytes:  1024,
		MaxResponseBytes: 1024,
		APIKeys:          []gateway.APIKey{{ID: "client-a", SHA256: hash}},
		Logger:           slog.New(slog.NewJSONHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("new gateway: %v", err)
	}
	request := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{}`))
	request.Header.Set("X-MCP-Gateway-Key", rawKey)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", response.Code)
	}
}

func TestProxyRejectsWhitespaceOnlyAPIKeyEvenIfItsHashIsConfigured(t *testing.T) {
	t.Parallel()

	const whitespaceKey = "   	"
	hash := sha256.Sum256([]byte(whitespaceKey))
	handler, err := gateway.New(gateway.Config{
		UpstreamURL:      "http://127.0.0.1:9000/mcp",
		UpstreamTimeout:  time.Second,
		MaxRequestBytes:  1024,
		MaxResponseBytes: 1024,
		APIKeys:          []gateway.APIKey{{ID: "client-a", SHA256: hash}},
		Logger:           slog.New(slog.NewJSONHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("new gateway: %v", err)
	}
	request := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{}`))
	request.Header.Set("X-MCP-Gateway-Key", whitespaceKey)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", response.Code)
	}
}
