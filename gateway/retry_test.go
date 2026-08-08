package gateway_test

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/apraba05/mcp-gateway/gateway"
)

func TestSafePingRetriesTransientStatusAndPreservesRequest(t *testing.T) {
	t.Parallel()
	body := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	var calls int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		call := atomic.AddInt32(&calls, 1)
		got, _ := io.ReadAll(r.Body)
		if !bytes.Equal(got, body) {
			t.Errorf("attempt %d body = %q, want exact %q", call, got, body)
		}
		if call == 1 {
			http.Error(w, "transient-secret", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("X-MCP-Session-ID", "session-1")
		w.WriteHeader(http.StatusAccepted)
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	defer upstream.Close()

	handler, err := newTestGateway(gateway.Config{
		UpstreamURL: upstream.URL, UpstreamTimeout: time.Second,
		MaxRequestBytes: 1024, MaxResponseBytes: 1024, MaxInFlight: 4,
		MaxSafeRetries: 1,
		Logger:         slog.New(slog.NewJSONHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(body))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusAccepted || response.Body.String() != `{"ok":true}` {
		t.Fatalf("response = %d %q, want 202 final body", response.Code, response.Body.String())
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Fatalf("upstream calls = %d, want 2", got)
	}
}

func TestUnsafeInitializeIsNeverRetried(t *testing.T) {
	t.Parallel()
	var calls int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&calls, 1)
		http.Error(w, "transient", http.StatusBadGateway)
	}))
	defer upstream.Close()
	handler, err := newTestGateway(gateway.Config{
		UpstreamURL: upstream.URL, UpstreamTimeout: time.Second,
		MaxRequestBytes: 1024, MaxResponseBytes: 1024, MaxInFlight: 4,
		MaxSafeRetries: 3,
		Logger:         slog.New(slog.NewJSONHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBufferString(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if got := atomic.LoadInt32(&calls); response.Code != http.StatusBadGateway || got != 1 {
		t.Fatalf("response/calls = %d/%d, want 502/1", response.Code, got)
	}
}

func TestSafePingRetriesConnectionDrop(t *testing.T) {
	t.Parallel()
	var calls int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if atomic.AddInt32(&calls, 1) == 1 {
			connection, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Errorf("hijack: %v", err)
				return
			}
			_ = connection.Close()
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{}`)
	}))
	defer upstream.Close()
	handler, err := newTestGateway(gateway.Config{
		UpstreamURL: upstream.URL, UpstreamTimeout: time.Second,
		MaxRequestBytes: 1024, MaxResponseBytes: 1024, MaxInFlight: 4,
		MaxSafeRetries: 1,
		Logger:         slog.New(slog.NewJSONHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBufferString(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if got := atomic.LoadInt32(&calls); response.Code != http.StatusOK || got != 2 {
		t.Fatalf("response/calls = %d/%d, want 200/2", response.Code, got)
	}
}

func TestSafePingDoesNotRetryAfterContextDeadline(t *testing.T) {
	t.Parallel()
	var calls int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&calls, 1)
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	handler, err := newTestGateway(gateway.Config{
		UpstreamURL: upstream.URL, UpstreamTimeout: 20 * time.Millisecond,
		MaxRequestBytes: 1024, MaxResponseBytes: 1024, MaxInFlight: 4,
		MaxSafeRetries: 3,
		Logger:         slog.New(slog.NewJSONHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBufferString(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if got := atomic.LoadInt32(&calls); response.Code != http.StatusGatewayTimeout || got != 1 {
		t.Fatalf("response/calls = %d/%d, want 504/1", response.Code, got)
	}
}

func TestToolsCallIsNeverRetried(t *testing.T) {
	t.Parallel()
	var calls int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&calls, 1)
		http.Error(w, "transient", http.StatusServiceUnavailable)
	}))
	defer upstream.Close()
	handler, err := newTestGateway(gateway.Config{
		UpstreamURL: upstream.URL, UpstreamTimeout: time.Second,
		MaxRequestBytes: 1024, MaxResponseBytes: 1024, MaxInFlight: 4,
		MaxSafeRetries: 3,
		ToolPolicies:   []gateway.ToolPolicy{{ClientID: "legacy-test-client", Tool: "search", Allow: true}},
		RateLimits:     []gateway.RateLimit{{ClientID: "legacy-test-client", Tool: "search", Capacity: 2, RefillInterval: time.Second}},
		Logger:         slog.New(slog.NewJSONHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBufferString(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search"}}`))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if got := atomic.LoadInt32(&calls); response.Code != http.StatusServiceUnavailable || got != 1 {
		t.Fatalf("response/calls = %d/%d, want 503/1", response.Code, got)
	}
}

func TestMalformedPingEnvelopeIsNeverRetried(t *testing.T) {
	t.Parallel()
	var calls int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&calls, 1)
		http.Error(w, "transient", http.StatusServiceUnavailable)
	}))
	defer upstream.Close()
	handler, err := newTestGateway(gateway.Config{
		UpstreamURL: upstream.URL, UpstreamTimeout: time.Second,
		MaxRequestBytes: 1024, MaxResponseBytes: 1024, MaxInFlight: 4,
		MaxSafeRetries: 3,
		Logger:         slog.New(slog.NewJSONHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBufferString(`{"jsonrpc":"1.0","id":true,"method":"ping"}`))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if got := atomic.LoadInt32(&calls); response.Code != http.StatusServiceUnavailable || got != 1 {
		t.Fatalf("response/calls = %d/%d, want 503/1", response.Code, got)
	}
}

func TestNewRejectsInvalidMaxSafeRetries(t *testing.T) {
	t.Parallel()
	for _, value := range []int{-1, 4} {
		_, err := gateway.New(gateway.Config{
			UpstreamURL: "http://127.0.0.1:1", UpstreamTimeout: time.Second,
			MaxRequestBytes: 1024, MaxResponseBytes: 1024, MaxInFlight: 4,
			MaxSafeRetries: value, APIKeys: testAPIKeys(),
			Logger: slog.New(slog.NewJSONHandler(io.Discard, nil)),
		})
		if err == nil {
			t.Fatalf("New accepted MaxSafeRetries=%d", value)
		}
	}
}
