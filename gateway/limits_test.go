package gateway_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/apraba05/mcp-gateway/gateway"
)

func newLimitsTestGateway(t *testing.T, upstreamURL string, maxRequestBytes, maxResponseBytes int64, upstreamTimeout time.Duration, logs io.Writer) http.Handler {
	t.Helper()
	if logs == nil {
		logs = io.Discard
	}
	handler, err := newTestGateway(gateway.Config{
		UpstreamURL:      upstreamURL,
		UpstreamTimeout:  upstreamTimeout,
		MaxRequestBytes:  maxRequestBytes,
		MaxResponseBytes: maxResponseBytes,
		Logger:           slog.New(slog.NewJSONHandler(logs, nil)),
	})
	if err != nil {
		t.Fatalf("new gateway: %v", err)
	}
	return handler
}

type failingResponseWriter struct {
	header http.Header
}

func (writer *failingResponseWriter) Header() http.Header { return writer.header }
func (*failingResponseWriter) WriteHeader(int)            {}
func (*failingResponseWriter) Write([]byte) (int, error) {
	return 0, errors.New("sensitive-adversarial-writer-detail")
}

func TestResponseWriteFailureDoesNotReflectRawDiagnosticInLogs(t *testing.T) {
	t.Parallel()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{}`)
	}))
	defer upstream.Close()
	var logs bytes.Buffer
	handler := newLimitsTestGateway(t, upstream.URL, 1024, 1024, time.Second, &logs)
	request := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBufferString(`{}`))
	response := &failingResponseWriter{header: make(http.Header)}

	handler.ServeHTTP(response, request)

	if strings.Contains(logs.String(), "sensitive-adversarial-writer-detail") {
		t.Fatalf("log reflected raw response-writer diagnostic: %q", logs.String())
	}
}

func TestNewRejectsNonPositiveByteCaps(t *testing.T) {
	t.Parallel()

	upstream := httptest.NewServer(nil)
	defer upstream.Close()

	for _, testCase := range []struct {
		name             string
		maxRequestBytes  int64
		maxResponseBytes int64
	}{
		{"zero request cap", 0, 1024},
		{"negative request cap", -1, 1024},
		{"zero response cap", 1024, 0},
		{"negative response cap", 1024, -1},
		{"oversized request cap", math.MaxInt64, 1024},
		{"oversized response cap", 1024, math.MaxInt64},
	} {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			_, err := gateway.New(gateway.Config{
				UpstreamURL:      upstream.URL,
				UpstreamTimeout:  time.Second,
				MaxRequestBytes:  testCase.maxRequestBytes,
				MaxResponseBytes: testCase.maxResponseBytes,
				APIKeys:          testAPIKeys(),
				Logger:           slog.New(slog.NewJSONHandler(io.Discard, nil)),
			})
			if err == nil {
				t.Fatalf("New accepted maxRequestBytes=%d maxResponseBytes=%d", testCase.maxRequestBytes, testCase.maxResponseBytes)
			}
		})
	}
}

func TestOversizedRequestByContentLengthIsRejectedBeforeUpstreamCall(t *testing.T) {
	t.Parallel()

	var upstreamCalls int32
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		atomic.AddInt32(&upstreamCalls, 1)
	}))
	defer upstream.Close()

	handler := newLimitsTestGateway(t, upstream.URL, 16, 1024, time.Second, nil)
	request := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBufferString(`{"too":"much data here"}`))
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusRequestEntityTooLarge)
	}
	if atomic.LoadInt32(&upstreamCalls) != 0 {
		t.Errorf("upstream calls = %d, want 0", upstreamCalls)
	}
}

func TestOversizedUpstreamResponseIsRejectedNotPartiallyForwarded(t *testing.T) {
	t.Parallel()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, strings.Repeat("x", 64))
	}))
	defer upstream.Close()

	handler := newLimitsTestGateway(t, upstream.URL, 1024, 16, time.Second, nil)
	request := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBufferString(`{}`))
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusBadGateway)
	}
	if strings.Contains(response.Body.String(), "xxxx") {
		t.Errorf("body leaked oversized upstream payload: %q", response.Body.String())
	}
}

func TestMalformedUpstreamHTTPResponseMapsToBoundedBadGateway(t *testing.T) {
	t.Parallel()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 4096)
		_, _ = conn.Read(buf)
		_, _ = conn.Write([]byte("NOT AN HTTP RESPONSE\r\n\r\n"))
	}()

	handler := newLimitsTestGateway(t, "http://"+listener.Addr().String()+"/mcp", 1024, 1024, time.Second, nil)
	request := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBufferString(`{}`))
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusBadGateway)
	}
	if response.Body.Len() > 256 {
		t.Errorf("error body not bounded: %d bytes", response.Body.Len())
	}
	if strings.Contains(response.Body.String(), "NOT AN HTTP RESPONSE") {
		t.Errorf("error body reflected raw upstream bytes: %q", response.Body.String())
	}
}

func TestHungUpstreamMapsToBoundedGatewayTimeout(t *testing.T) {
	t.Parallel()

	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		<-time.After(250 * time.Millisecond)
	}))
	defer upstream.Close()

	var logs bytes.Buffer
	handler := newLimitsTestGateway(t, upstream.URL, 1024, 1024, 50*time.Millisecond, &logs)
	request := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBufferString(`{}`))
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusGatewayTimeout {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusGatewayTimeout)
	}
	var entry map[string]any
	if err := json.Unmarshal(logs.Bytes(), &entry); err != nil {
		t.Fatalf("decode structured log %q: %v", logs.String(), err)
	}
	if entry["reason"] != "upstream_timeout" {
		t.Errorf("log reason = %#v, want upstream_timeout", entry["reason"])
	}
}

func TestClientCancellationPropagatesToUpstreamAndMapsToBoundedStatus(t *testing.T) {
	t.Parallel()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()
	upstreamStarted := make(chan struct{})
	upstreamConnectionClosed := make(chan struct{})
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer connection.Close()
		reader := bufio.NewReader(connection)
		for {
			line, readErr := reader.ReadString('\n')
			if readErr != nil {
				return
			}
			if line == "\r\n" {
				break
			}
		}
		close(upstreamStarted)
		_, _ = io.Copy(io.Discard, reader)
		close(upstreamConnectionClosed)
	}()

	var logs bytes.Buffer
	handler := newLimitsTestGateway(t, "http://"+listener.Addr().String()+"/mcp", 1024, 1024, 10*time.Second, &logs)
	ctx, cancel := context.WithCancel(context.Background())
	request := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBufferString(`{}`)).WithContext(ctx)
	response := httptest.NewRecorder()

	done := make(chan struct{})
	go func() {
		handler.ServeHTTP(response, request)
		close(done)
	}()

	select {
	case <-upstreamStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("upstream never received request")
	}
	cancel()

	select {
	case <-upstreamConnectionClosed:
	case <-time.After(2 * time.Second):
		t.Fatal("cancellation did not close the upstream transport")
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not return promptly after cancellation")
	}

	if response.Code != statusClientClosedRequestForTest {
		t.Fatalf("status = %d, want %d", response.Code, statusClientClosedRequestForTest)
	}
	var entry map[string]any
	if err := json.Unmarshal(logs.Bytes(), &entry); err != nil {
		t.Fatalf("decode structured log %q: %v", logs.String(), err)
	}
	if entry["reason"] != "client_canceled" {
		t.Errorf("log reason = %#v, want client_canceled", entry["reason"])
	}
}

const statusClientClosedRequestForTest = 499

func TestOversizedChunkedRequestIsRejectedBeforeUpstreamCall(t *testing.T) {
	t.Parallel()

	var upstreamCalls int32
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		atomic.AddInt32(&upstreamCalls, 1)
	}))
	defer upstream.Close()

	handler := newLimitsTestGateway(t, upstream.URL, 16, 1024, time.Second, nil)
	request := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBufferString(strings.Repeat("a", 64)))
	request.ContentLength = -1 // simulate unknown-length (chunked) body
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusRequestEntityTooLarge)
	}
	if atomic.LoadInt32(&upstreamCalls) != 0 {
		t.Errorf("upstream calls = %d, want 0", upstreamCalls)
	}
}
