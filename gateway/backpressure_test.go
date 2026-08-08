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

func TestNewRejectsInvalidMaxInFlight(t *testing.T) {
	t.Parallel()

	upstream := httptest.NewServer(nil)
	defer upstream.Close()

	for _, testCase := range []struct {
		name        string
		maxInFlight int
	}{
		{"zero", 0},
		{"negative", -1},
		{"far above strict bound", 100_000_001},
	} {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			_, err := gateway.New(gateway.Config{
				UpstreamURL:      upstream.URL,
				UpstreamTimeout:  time.Second,
				MaxRequestBytes:  1024,
				MaxResponseBytes: 1024,
				MaxInFlight:      testCase.maxInFlight,
				APIKeys:          testAPIKeys(),
				Logger:           slog.New(slog.NewJSONHandler(io.Discard, nil)),
			})
			if err == nil {
				t.Fatalf("New accepted MaxInFlight=%d", testCase.maxInFlight)
			}
		})
	}
}

func TestPOSTRejectsExcessConcurrentRequestsWithBoundedServiceUnavailable(t *testing.T) {
	t.Parallel()

	release := make(chan struct{})
	requestStarted := make(chan struct{}, 1)
	var upstreamCalls int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&upstreamCalls, 1)
		requestStarted <- struct{}{}
		<-release
		_, _ = io.WriteString(w, `{}`)
	}))
	defer upstream.Close()

	handler, err := newTestGateway(gateway.Config{
		UpstreamURL:      upstream.URL,
		UpstreamTimeout:  5 * time.Second,
		MaxRequestBytes:  1024,
		MaxResponseBytes: 1024,
		MaxInFlight:      1,
		Logger:           slog.New(slog.NewJSONHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("new gateway: %v", err)
	}

	firstDone := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		request := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBufferString(`{}`))
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		firstDone <- response
	}()

	select {
	case <-requestStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("first request never reached upstream")
	}

	secondRequest := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBufferString(`{}`))
	secondResponse := httptest.NewRecorder()
	handler.ServeHTTP(secondResponse, secondRequest)

	if secondResponse.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", secondResponse.Code, http.StatusServiceUnavailable)
	}
	if got := secondResponse.Header().Get("Retry-After"); got == "" {
		t.Errorf("missing Retry-After header on backpressure response")
	}
	if secondResponse.Body.Len() > 64 {
		t.Errorf("backpressure body not bounded: %d bytes", secondResponse.Body.Len())
	}

	close(release)
	select {
	case first := <-firstDone:
		if first.Code != http.StatusOK {
			t.Errorf("first request status = %d, want 200", first.Code)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("first request did not complete after release")
	}

	if atomic.LoadInt32(&upstreamCalls) != 1 {
		t.Errorf("upstream calls = %d, want 1 (rejected request must not reach upstream)", upstreamCalls)
	}
}
