// Command mcpserver is a minimal, deterministic loopback MCP HTTP server. It
// exists so the gateway's quickstart, examples, and demo have a real
// upstream to exercise, without any external dependency or network call. It
// implements exactly enough of MCP JSON-RPC (ping, tools/list, tools/call
// for a single "echo" tool) to demonstrate the gateway end to end.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// maxRequestBytes bounds the example server's inbound body, mirroring the
// gateway's own admission bounds so the demo never buffers unbounded input.
const maxRequestBytes = 1 << 20

func newHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/mcp", handleMCP)
	mux.HandleFunc("/healthz", handleHealth)
	return mux
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"status":"ok"}` + "\n"))
}

func handleMCP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBytes)

	var request struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Method  string          `json:"method"`
		Params  json.RawMessage `json:"params"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		if isMaxBytesError(err) {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		writeResult(w, nil, nil, &rpcError{Code: -32700, Message: "parse error"})
		return
	}

	switch request.Method {
	case "ping":
		writeResult(w, request.ID, map[string]any{}, nil)
	case "tools/list":
		writeResult(w, request.ID, map[string]any{
			"tools": []map[string]any{
				{"name": "echo", "description": "Echoes the provided text back deterministically."},
			},
		}, nil)
	case "tools/call":
		handleToolsCall(w, request.ID, request.Params)
	default:
		writeResult(w, request.ID, nil, &rpcError{Code: -32601, Message: "method not found"})
	}
}

// isMaxBytesError reports whether err was caused by http.MaxBytesReader
// rejecting an oversized body.
func isMaxBytesError(err error) bool {
	var maxBytesError *http.MaxBytesError
	return errors.As(err, &maxBytesError)
}

func handleToolsCall(w http.ResponseWriter, id json.RawMessage, params json.RawMessage) {
	var call struct {
		Name      string `json:"name"`
		Arguments struct {
			Text string `json:"text"`
		} `json:"arguments"`
	}
	if err := json.Unmarshal(params, &call); err != nil {
		writeResult(w, id, nil, &rpcError{Code: -32602, Message: "invalid params"})
		return
	}
	if call.Name != "echo" {
		writeResult(w, id, nil, &rpcError{Code: -32602, Message: "unknown tool"})
		return
	}
	writeResult(w, id, map[string]any{
		"content": []map[string]any{
			{"type": "text", "text": call.Arguments.Text},
		},
	}, nil)
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func writeResult(w http.ResponseWriter, id json.RawMessage, result any, rpcErr *rpcError) {
	w.Header().Set("Content-Type", "application/json")
	body := map[string]any{"jsonrpc": "2.0", "id": id}
	if rpcErr != nil {
		body["error"] = rpcErr
	} else {
		body["result"] = result
	}
	_ = json.NewEncoder(w).Encode(body)
}

// main binds a loopback-only listener (127.0.0.1, or an explicit
// 127.0.0.1:port via -addr) so the example server never accepts non-local
// traffic. Port 0 lets the OS pick a free ephemeral port; the resolved
// address is printed as a single deterministic line so scripts (the demo,
// tests) can parse it without sleeping or guessing a port.
func main() {
	addr := flag.String("addr", "127.0.0.1:0", "loopback address to listen on (host must be 127.0.0.1)")
	flag.Parse()

	host, _, err := net.SplitHostPort(*addr)
	if err != nil || host != "127.0.0.1" {
		log.Fatalf("mcpserver: -addr must be a 127.0.0.1 address, got %q", *addr)
	}

	listener, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatalf("mcpserver: listen: %v", err)
	}

	server := &http.Server{Handler: newHandler()}
	serverErrors := make(chan error, 1)
	go func() {
		serverErrors <- server.Serve(listener)
	}()

	fmt.Printf("MCP_SERVER_ADDR=%s\n", listener.Addr().String())

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(signals)

	select {
	case err := <-serverErrors:
		if !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("mcpserver: serve: %v", err)
		}
	case <-signals:
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			_ = server.Close()
			log.Fatalf("mcpserver: shutdown: %v", err)
		}
	}
}
