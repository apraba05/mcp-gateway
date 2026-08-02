package gateway_test

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/apraba05/mcp-gateway/gateway"
)

func TestProxyPreservesAbsentUpstreamContentType(t *testing.T) {
	t.Parallel()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header()["Content-Type"] = nil
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "body without content type")
	}))
	defer upstream.Close()
	handler, err := gateway.New(gateway.Config{
		UpstreamURL:     upstream.URL,
		UpstreamTimeout: time.Second,
		Logger:          slog.New(slog.NewJSONHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("new gateway: %v", err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()
	response, err := http.Post(server.URL+"/mcp", "application/json", bytes.NewBufferString(`{}`))
	if err != nil {
		t.Fatalf("post gateway: %v", err)
	}
	defer response.Body.Close()

	if _, present := response.Header["Content-Type"]; present {
		t.Errorf("gateway synthesized content type %q", response.Header.Get("Content-Type"))
	}
}

func TestProxyForwardsEndToEndMCPHeaders(t *testing.T) {
	t.Parallel()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for name, want := range map[string]string{
			"Accept":         "application/json, text/event-stream",
			"Authorization":  "Bearer fixture-token",
			"Mcp-Session-Id": "session-123",
			"Last-Event-Id":  "event-9",
		} {
			if got := r.Header.Get(name); got != want {
				t.Errorf("upstream %s = %q, want %q", name, got, want)
			}
		}
		w.Header().Set("Mcp-Session-Id", "session-456")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Request-ID", "upstream-different-id")
		_, _ = io.WriteString(w, `{}`)
	}))
	defer upstream.Close()
	handler, err := gateway.New(gateway.Config{
		UpstreamURL:     upstream.URL,
		UpstreamTimeout: time.Second,
		Logger:          slog.New(slog.NewJSONHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("new gateway: %v", err)
	}
	request := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBufferString(`{}`))
	request.Header.Set("Accept", "application/json, text/event-stream")
	request.Header.Set("Authorization", "Bearer fixture-token")
	request.Header.Set("Mcp-Session-Id", "session-123")
	request.Header.Set("Last-Event-Id", "event-9")
	request.Header.Set("X-Request-ID", "selected-client-id")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if got := response.Header().Get("Mcp-Session-Id"); got != "session-456" {
		t.Errorf("response session ID = %q, want session-456", got)
	}
	if got := response.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("response cache control = %q, want no-store", got)
	}
	if got := response.Header().Values("X-Request-ID"); len(got) != 1 || got[0] != "selected-client-id" {
		t.Errorf("response request IDs = %q, want only selected-client-id", got)
	}
}

func TestNewRejectsUpstreamURLWithoutHostname(t *testing.T) {
	t.Parallel()

	_, err := gateway.New(gateway.Config{
		UpstreamURL:     "http://:8080/mcp",
		UpstreamTimeout: time.Second,
		Logger:          slog.New(slog.NewJSONHandler(io.Discard, nil)),
	})
	if err == nil {
		t.Fatal("New accepted upstream URL without hostname")
	}
}

func TestNewRejectsUpstreamURLCredentials(t *testing.T) {
	t.Parallel()

	_, err := gateway.New(gateway.Config{
		UpstreamURL:     "https://user:password@example.com/mcp",
		UpstreamTimeout: time.Second,
		Logger:          slog.New(slog.NewJSONHandler(io.Discard, nil)),
	})
	if err == nil {
		t.Fatal("New accepted upstream URL credentials")
	}
	if bytes.Contains([]byte(err.Error()), []byte("password")) {
		t.Fatalf("error reflected URL credentials: %q", err)
	}
}

func TestProxyPreservesCompressedUpstreamBodyBytes(t *testing.T) {
	t.Parallel()

	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err := writer.Write([]byte(`{"jsonrpc":"2.0","result":{}}`)); err != nil {
		t.Fatalf("compress fixture response: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close fixture compressor: %v", err)
	}
	expected := append([]byte(nil), compressed.Bytes()...)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Encoding", "gzip")
		_, _ = w.Write(expected)
	}))
	defer upstream.Close()
	handler, err := gateway.New(gateway.Config{
		UpstreamURL:     upstream.URL,
		UpstreamTimeout: time.Second,
		Logger:          slog.New(slog.NewJSONHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("new gateway: %v", err)
	}
	request := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBufferString(`{}`))
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if !bytes.Equal(response.Body.Bytes(), expected) {
		t.Errorf("gateway altered compressed body: got %d bytes, want %d", response.Body.Len(), len(expected))
	}
	if got := response.Header().Get("Content-Encoding"); got != "gzip" {
		t.Errorf("content encoding = %q, want gzip", got)
	}
}

func TestProxyReturnsUpstreamRedirectWithoutFollowingIt(t *testing.T) {
	t.Parallel()

	redirectTargetCalls := 0
	redirectTarget := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		redirectTargetCalls++
		_, _ = io.WriteString(w, "redirect target")
	}))
	defer redirectTarget.Close()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", redirectTarget.URL)
		w.WriteHeader(http.StatusFound)
		_, _ = io.WriteString(w, "upstream redirect")
	}))
	defer upstream.Close()
	handler, err := gateway.New(gateway.Config{
		UpstreamURL:     upstream.URL,
		UpstreamTimeout: time.Second,
		Logger:          slog.New(slog.NewJSONHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("new gateway: %v", err)
	}
	request := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBufferString(`{}`))
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusFound {
		t.Errorf("status = %d, want %d", response.Code, http.StatusFound)
	}
	if response.Body.String() != "upstream redirect" {
		t.Errorf("body = %q, want upstream redirect", response.Body.String())
	}
	if redirectTargetCalls != 0 {
		t.Errorf("redirect target calls = %d, want 0", redirectTargetCalls)
	}
}

func TestProxyWritesPayloadSafeStructuredLog(t *testing.T) {
	t.Parallel()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{}`)
	}))
	defer upstream.Close()
	var logs bytes.Buffer
	handler, err := gateway.New(gateway.Config{
		UpstreamURL:     upstream.URL,
		UpstreamTimeout: time.Second,
		Logger:          slog.New(slog.NewJSONHandler(&logs, nil)),
	})
	if err != nil {
		t.Fatalf("new gateway: %v", err)
	}
	request := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBufferString(`{"secret":"must-not-be-logged"}`))
	request.Header.Set("X-Request-ID", "log-request-1")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	var entry map[string]any
	if err := json.Unmarshal(logs.Bytes(), &entry); err != nil {
		t.Fatalf("decode structured log %q: %v", logs.String(), err)
	}
	if entry["request_id"] != "log-request-1" || entry["method"] != http.MethodPost || entry["path"] != "/mcp" {
		t.Errorf("log fields = %#v", entry)
	}
	if entry["status"] != float64(http.StatusOK) {
		t.Errorf("logged status = %#v, want 200", entry["status"])
	}
	if bytes.Contains(logs.Bytes(), []byte("must-not-be-logged")) {
		t.Fatal("structured log contains request payload")
	}
}

func TestProxyPreservesValidRequestID(t *testing.T) {
	t.Parallel()

	const requestID = "req-valid_123"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-Request-ID"); got != requestID {
			t.Errorf("upstream request ID = %q, want %q", got, requestID)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{}}`)
	}))
	defer upstream.Close()

	handler, err := gateway.New(gateway.Config{
		UpstreamURL:     upstream.URL,
		UpstreamTimeout: time.Second,
		Logger:          slog.New(slog.NewJSONHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("new gateway: %v", err)
	}
	request := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBufferString(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	request.Header.Set("X-Request-ID", requestID)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if got := response.Header().Get("X-Request-ID"); got != requestID {
		t.Errorf("response request ID = %q, want %q", got, requestID)
	}
}

func TestProxyGeneratesRequestIDWhenInboundIDIsUnsafe(t *testing.T) {
	t.Parallel()

	var upstreamRequestID string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamRequestID = r.Header.Get("X-Request-ID")
		_, _ = io.WriteString(w, `{}`)
	}))
	defer upstream.Close()

	handler, err := gateway.New(gateway.Config{
		UpstreamURL:     upstream.URL,
		UpstreamTimeout: time.Second,
		Logger:          slog.New(slog.NewJSONHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("new gateway: %v", err)
	}
	request := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBufferString(`{}`))
	request.Header.Set("X-Request-ID", "unsafe value with spaces")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	responseRequestID := response.Header().Get("X-Request-ID")
	if responseRequestID == "" || responseRequestID == "unsafe value with spaces" {
		t.Fatalf("generated response request ID = %q", responseRequestID)
	}
	if upstreamRequestID != responseRequestID {
		t.Errorf("upstream request ID = %q, response request ID = %q", upstreamRequestID, responseRequestID)
	}
}

func TestHealthEndpointReportsHealthyWithoutCallingUpstream(t *testing.T) {
	t.Parallel()

	upstreamCalls := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		upstreamCalls++
	}))
	defer upstream.Close()
	handler, err := gateway.New(gateway.Config{
		UpstreamURL:     upstream.URL,
		UpstreamTimeout: time.Second,
		Logger:          slog.New(slog.NewJSONHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("new gateway: %v", err)
	}
	request := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", response.Code)
	}
	if response.Body.String() != `{"status":"ok"}`+"\n" {
		t.Errorf("body = %q", response.Body.String())
	}
	if upstreamCalls != 0 {
		t.Errorf("upstream calls = %d, want 0", upstreamCalls)
	}
}

func TestProxyPreservesRequestContentLength(t *testing.T) {
	t.Parallel()

	const body = `{"jsonrpc":"2.0","id":7,"method":"ping"}`
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ContentLength != int64(len(body)) {
			t.Errorf("content length = %d, want %d", r.ContentLength, len(body))
		}
		upstreamBody, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read request body: %v", err)
		}
		_, _ = w.Write(upstreamBody)
	}))
	defer upstream.Close()
	handler, err := gateway.New(gateway.Config{
		UpstreamURL:     upstream.URL,
		UpstreamTimeout: time.Second,
		Logger:          slog.New(slog.NewJSONHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("new gateway: %v", err)
	}
	request := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBufferString(body))
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Body.String() != body {
		t.Errorf("body = %q, want %q", response.Body.String(), body)
	}
}

func TestProxyForwardsJSONRPCRequestAndResponse(t *testing.T) {
	t.Parallel()

	const requestBody = `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`
	const responseBody = `{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}`

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %q, want POST", r.Method)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read upstream request: %v", err)
		}
		if string(body) != requestBody {
			t.Errorf("body = %q, want %q", body, requestBody)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_, _ = io.WriteString(w, responseBody)
	}))
	defer upstream.Close()

	handler, err := gateway.New(gateway.Config{
		UpstreamURL:     upstream.URL,
		UpstreamTimeout: time.Second,
		Logger:          slog.New(slog.NewJSONHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("new gateway: %v", err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()

	resp, err := http.Post(server.URL+"/mcp", "application/json", bytes.NewBufferString(requestBody))
	if err != nil {
		t.Fatalf("post gateway request: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read gateway response: %v", err)
	}
	if resp.StatusCode != http.StatusAccepted {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusAccepted)
	}
	if got := resp.Header.Get("Content-Type"); got != "application/json" {
		t.Errorf("content type = %q, want application/json", got)
	}
	if string(body) != responseBody {
		t.Errorf("body = %q, want %q", body, responseBody)
	}
}
