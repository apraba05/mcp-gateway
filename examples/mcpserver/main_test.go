// Package main implements a minimal, deterministic loopback MCP HTTP server
// used by the gateway's examples and reproducible demo. Behavior is
// intentionally tiny: it exists to exercise the gateway end to end, not to
// be a general-purpose MCP server.
package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestToolsListReturnsEchoTool(t *testing.T) {
	t.Parallel()

	handler := newHandler()
	request := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
	var decoded struct {
		Result struct {
			Tools []struct {
				Name string `json:"name"`
			} `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &decoded); err != nil {
		t.Fatalf("decode response: %v; body = %s", err, response.Body.String())
	}
	if len(decoded.Result.Tools) != 1 || decoded.Result.Tools[0].Name != "echo" {
		t.Fatalf("tools = %#v, want exactly one tool named echo", decoded.Result.Tools)
	}
}

func TestToolsCallEchoReturnsProvidedTextDeterministically(t *testing.T) {
	t.Parallel()

	handler := newHandler()
	body := `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{"text":"hello-mcp"}}}`
	request := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
	var decoded struct {
		Result struct {
			Content []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"content"`
		} `json:"result"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &decoded); err != nil {
		t.Fatalf("decode response: %v; body = %s", err, response.Body.String())
	}
	if len(decoded.Result.Content) != 1 || decoded.Result.Content[0].Type != "text" || decoded.Result.Content[0].Text != "hello-mcp" {
		t.Fatalf("content = %#v, want echoed text", decoded.Result.Content)
	}
}

func TestToolsCallUnknownToolReturnsJSONRPCError(t *testing.T) {
	t.Parallel()

	handler := newHandler()
	body := `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"does-not-exist","arguments":{}}}`
	request := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	var decoded struct {
		Error *struct {
			Code int `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &decoded); err != nil {
		t.Fatalf("decode response: %v; body = %s", err, response.Body.String())
	}
	if decoded.Error == nil || decoded.Error.Code != -32602 {
		t.Fatalf("error = %#v, want code -32602", decoded.Error)
	}
}

func TestPingReturnsEmptyResult(t *testing.T) {
	t.Parallel()

	handler := newHandler()
	request := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":4,"method":"ping"}`))
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	var decoded struct {
		Result map[string]any `json:"result"`
		Error  *rpcErrorBody  `json:"error"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &decoded); err != nil {
		t.Fatalf("decode response: %v; body = %s", err, response.Body.String())
	}
	if decoded.Error != nil || decoded.Result == nil {
		t.Fatalf("result = %#v, error = %#v, want empty non-nil result", decoded.Result, decoded.Error)
	}
}

type rpcErrorBody struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func TestMalformedJSONReturnsParseError(t *testing.T) {
	t.Parallel()

	handler := newHandler()
	request := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{not-json`))
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	var decoded struct {
		Error *rpcErrorBody `json:"error"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &decoded); err != nil {
		t.Fatalf("decode response: %v; body = %s", err, response.Body.String())
	}
	if decoded.Error == nil || decoded.Error.Code != -32700 {
		t.Fatalf("error = %#v, want parse error -32700", decoded.Error)
	}
}

func TestNewServerSetsBoundedTimeouts(t *testing.T) {
	t.Parallel()

	server := newServer(newHandler())

	if server.ReadHeaderTimeout <= 0 || server.ReadHeaderTimeout > 30*time.Second {
		t.Fatalf("ReadHeaderTimeout = %v, want a positive bound <= 30s", server.ReadHeaderTimeout)
	}
	if server.ReadTimeout <= 0 || server.ReadTimeout > 30*time.Second {
		t.Fatalf("ReadTimeout = %v, want a positive bound <= 30s", server.ReadTimeout)
	}
	if server.WriteTimeout <= 0 || server.WriteTimeout > 30*time.Second {
		t.Fatalf("WriteTimeout = %v, want a positive bound <= 30s", server.WriteTimeout)
	}
	if server.IdleTimeout <= 0 || server.IdleTimeout > 60*time.Second {
		t.Fatalf("IdleTimeout = %v, want a positive bound <= 60s", server.IdleTimeout)
	}
}

func TestOversizedBodyIsRejected(t *testing.T) {
	t.Parallel()

	handler := newHandler()
	oversized := strings.Repeat("a", 1<<20+1)
	request := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"echo","arguments":{"text":"`+oversized+`"}}}`))
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusRequestEntityTooLarge)
	}
}
