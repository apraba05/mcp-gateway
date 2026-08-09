// Package main implements a minimal loopback MCP client used by the
// gateway's examples and reproducible demo. It sends one JSON-RPC request
// through the gateway and prints the response. It never accepts the raw
// gateway key as a command-line argument, so the key cannot leak through
// process listings or shell history.
package main

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRunSendsAuthenticatedRequestAndPrintsResponseBody(t *testing.T) {
	t.Parallel()

	var gotKey, gotRequestID, gotBody string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey = r.Header.Get("X-MCP-Gateway-Key")
		gotRequestID = r.Header.Get("X-Request-ID")
		body, _ := io.ReadAll(r.Body)
		gotBody = string(body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"ok":true}}`))
	}))
	t.Cleanup(upstream.Close)

	var stdout bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := run(ctx, runOptions{
		GatewayURL: upstream.URL,
		APIKey:     "fixture-key",
		RequestID:  "demo-1",
		Payload:    []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`),
	}, &stdout)
	if err != nil {
		t.Fatalf("run: %v", err)
	}

	if gotKey != "fixture-key" {
		t.Errorf("gateway key header = %q, want fixture-key", gotKey)
	}
	if gotRequestID != "demo-1" {
		t.Errorf("request id header = %q, want demo-1", gotRequestID)
	}
	if gotBody != `{"jsonrpc":"2.0","id":1,"method":"ping"}` {
		t.Errorf("request body = %q", gotBody)
	}
	if !strings.Contains(stdout.String(), `"ok":true`) {
		t.Errorf("stdout = %q, want response body printed", stdout.String())
	}
}

func TestRunRejectsEmptyAPIKeyWithoutSendingRequest(t *testing.T) {
	t.Parallel()

	called := false
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))
	t.Cleanup(upstream.Close)

	var stdout bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := run(ctx, runOptions{
		GatewayURL: upstream.URL,
		APIKey:     "",
		RequestID:  "demo-2",
		Payload:    []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`),
	}, &stdout)

	if err == nil {
		t.Fatal("run: want error for empty API key, got nil")
	}
	if called {
		t.Error("run: sent request despite empty API key")
	}
}

func TestRunRejectsNonSuccessWithoutReflectingResponseBody(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "sensitive-upstream-diagnostic", http.StatusUnauthorized)
	}))
	t.Cleanup(server.Close)

	var stdout bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := run(ctx, runOptions{
		GatewayURL: server.URL,
		APIKey:     "fixture-key",
		Payload:    []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`),
	}, &stdout)

	if err == nil {
		t.Fatal("run: want bounded error for non-success status")
	}
	if strings.Contains(err.Error(), "sensitive-upstream-diagnostic") || stdout.Len() != 0 {
		t.Fatalf("run reflected response: error = %q, stdout = %q", err, stdout.String())
	}
}

func TestRunRejectsOversizedSuccessResponseWithoutPrintingPartialBody(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("x", 1<<20+1)))
	}))
	t.Cleanup(server.Close)

	var stdout bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := run(ctx, runOptions{
		GatewayURL: server.URL,
		APIKey:     "fixture-key",
		Payload:    []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`),
	}, &stdout)

	if err == nil {
		t.Fatal("run: want error for oversized response")
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout length = %d, want no partial response", stdout.Len())
	}
}
