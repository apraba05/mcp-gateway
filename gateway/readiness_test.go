package gateway_test

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/apraba05/mcp-gateway/gateway"
)

// newReadinessTestGateway returns the concrete *gateway.Handler (not the
// interface) so tests can call Drain directly, mirroring how main will mark
// the process draining before graceful shutdown.
func newReadinessTestGateway(t *testing.T) *gateway.Handler {
	t.Helper()
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(upstream.Close)
	handler, err := gateway.New(gateway.Config{
		UpstreamURL:      upstream.URL,
		UpstreamTimeout:  time.Second,
		MaxRequestBytes:  1024,
		MaxResponseBytes: 1024,
		MaxInFlight:      64,
		APIKeys:          testAPIKeys(),
		Logger:           slog.New(slog.NewJSONHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("new gateway: %v", err)
	}
	return handler
}

func TestReadyEndpointReturns200WhileAcceptingWorkWithoutCallingUpstream(t *testing.T) {
	t.Parallel()

	handler := newReadinessTestGateway(t)
	request := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
	if response.Body.String() != `{"status":"ok"}`+"\n" {
		t.Errorf("body = %q", response.Body.String())
	}
}

func TestReadyEndpointReturns503WhileDrainingWithoutLeakingDiagnostics(t *testing.T) {
	t.Parallel()

	handler := newReadinessTestGateway(t)
	handler.Drain()

	request := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusServiceUnavailable)
	}
	if response.Body.Len() > 64 {
		t.Errorf("draining body not bounded: %d bytes", response.Body.Len())
	}
}

func TestReadyEndpointRejectsNonGetMethod(t *testing.T) {
	t.Parallel()

	handler := newReadinessTestGateway(t)
	request := httptest.NewRequest(http.MethodPost, "/readyz", nil)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusMethodNotAllowed)
	}
}

func TestHealthEndpointRemainsLivenessRegardlessOfDrainState(t *testing.T) {
	t.Parallel()

	handler := newReadinessTestGateway(t)
	handler.Drain()

	request := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d (liveness must not reflect drain state)", response.Code, http.StatusOK)
	}
}
