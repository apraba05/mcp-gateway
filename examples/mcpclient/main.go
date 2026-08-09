// Command mcpclient sends one MCP JSON-RPC request through the gateway's
// /mcp endpoint and prints the response body. It exists so the gateway's
// examples and reproducible demo can exercise a real client binary against
// a loopback gateway, without any external dependency or paid API call.
package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

// requestTimeout bounds the whole client invocation so a stalled loopback
// gateway or upstream cannot hang the demo or a manual run indefinitely.
const requestTimeout = 10 * time.Second

// maxPayloadBytes bounds how much of stdin the client will buffer as the
// JSON-RPC request body.
const maxPayloadBytes = 1 << 20

// runOptions holds one client invocation's inputs. APIKey is intentionally
// never sourced from a command-line flag (see main): it is only accepted as
// a Go value here, populated from an environment variable, so it cannot
// appear in process argument listings or shell history.
type runOptions struct {
	GatewayURL string
	APIKey     string
	RequestID  string
	Payload    []byte
}

// run sends one authenticated MCP request and writes the response body to
// stdout. It never logs the API key or reflects it in any error message.
func run(ctx context.Context, opts runOptions, stdout io.Writer) error {
	if opts.APIKey == "" {
		return errors.New("gateway API key is required (set MCP_CLIENT_KEY)")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, opts.GatewayURL, bytes.NewReader(opts.Payload))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-MCP-Gateway-Key", opts.APIKey)
	if opts.RequestID != "" {
		request.Header.Set("X-Request-ID", opts.RequestID)
	}

	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return errors.New("gateway request failed")
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("gateway returned HTTP %d", response.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(response.Body, maxPayloadBytes+1))
	if err != nil {
		return errors.New("reading gateway response failed")
	}
	if len(body) > maxPayloadBytes {
		return errors.New("gateway response exceeds the client bound")
	}
	if _, err := stdout.Write(body); err != nil {
		return err
	}
	_, err = fmt.Fprintln(stdout)
	return err
}

// main reads the gateway key from MCP_CLIENT_KEY (never from a flag or
// positional argument) so it cannot appear in process argument listings,
// shell history, or the audit/error output below. The JSON-RPC request body
// is read from stdin, matching the README quickstart's curl usage.
func main() {
	gatewayURL := flag.String("gateway-url", "http://127.0.0.1:8080/mcp", "gateway /mcp endpoint URL")
	requestID := flag.String("request-id", "", "optional X-Request-ID to send")
	flag.Parse()

	apiKey := os.Getenv("MCP_CLIENT_KEY")

	payload, err := io.ReadAll(io.LimitReader(os.Stdin, maxPayloadBytes+1))
	if err != nil {
		fmt.Fprintln(os.Stderr, "mcpclient: reading stdin failed")
		os.Exit(1)
	}
	if len(payload) > maxPayloadBytes {
		fmt.Fprintln(os.Stderr, "mcpclient: request body exceeds the client's bound")
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()

	if err := run(ctx, runOptions{
		GatewayURL: *gatewayURL,
		APIKey:     apiKey,
		RequestID:  *requestID,
		Payload:    payload,
	}, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "mcpclient: %v\n", err)
		os.Exit(1)
	}
}
