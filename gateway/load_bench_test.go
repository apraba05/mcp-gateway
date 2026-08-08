package gateway_test

import (
	"bytes"
	"crypto/sha256"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sort"
	"sync/atomic"
	"testing"
	"time"

	"github.com/apraba05/mcp-gateway/gateway"
)

// loadMeasurementKey is a fixture credential local to this benchmark; it is
// never a real secret and is never logged.
const loadMeasurementKey = "load-measurement-fixture-key"

// newLoadMeasurementGateway builds a Handler wired to a local, in-process
// upstream fixture (an httptest.Server bound to loopback) that returns a
// small fixed JSON-RPC response. It never contacts a real network service,
// so measurements are reproducible on an isolated host and independent of
// external network conditions.
func newLoadMeasurementGateway(b *testing.B) (http.Handler, func()) {
	b.Helper()
	hash := sha256.Sum256([]byte(loadMeasurementKey))
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"ok":true}}`)
	}))
	handler, err := gateway.New(gateway.Config{
		UpstreamURL:      upstream.URL,
		UpstreamTimeout:  2 * time.Second,
		MaxRequestBytes:  1 << 16,
		MaxResponseBytes: 1 << 16,
		MaxInFlight:      256,
		APIKeys:          []gateway.APIKey{{ID: "load-client", SHA256: hash}},
		ToolPolicies:     []gateway.ToolPolicy{{ClientID: "load-client", Tool: "search", Allow: true}},
		RateLimits: []gateway.RateLimit{
			{ClientID: "load-client", Tool: "search", Capacity: 100_000_000, RefillInterval: time.Millisecond},
		},
		Logger: slog.New(slog.NewJSONHandler(io.Discard, nil)),
	})
	if err != nil {
		upstream.Close()
		b.Fatalf("new gateway: %v", err)
	}
	return handler, upstream.Close
}

func loadMeasurementRequest() *http.Request {
	const body = `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search","arguments":{"query":"fixture"}}}`
	request := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBufferString(body))
	request.Header.Set("X-MCP-Gateway-Key", loadMeasurementKey)
	return request
}

// reportLatencyPercentiles adds p50/p95/p99 per-request latency as custom
// benchmark metrics alongside the standard ns/op mean. These are reported
// measurements only; nothing here asserts a threshold, so a slow or noisy
// host changes the numbers, never the PASS/FAIL outcome.
func reportLatencyPercentiles(b *testing.B, durations []time.Duration) {
	b.Helper()
	if len(durations) == 0 {
		return
	}
	sorted := append([]time.Duration(nil), durations...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	percentile := func(p float64) time.Duration {
		index := int(p * float64(len(sorted)-1))
		return sorted[index]
	}
	b.ReportMetric(float64(percentile(0.50)), "p50-ns/op")
	b.ReportMetric(float64(percentile(0.95)), "p95-ns/op")
	b.ReportMetric(float64(percentile(0.99)), "p99-ns/op")
}

// BenchmarkGatewayServeHTTPSequential is the reproducible, resource-bounded
// load measurement path for one permitted tools/call round trip end to end
// through the exported Handler.ServeHTTP, against the local in-process
// upstream fixture above (never a real network service, never logging
// request/response payloads or credentials). Correctness (every response
// reaching the fixture's 200) is checked in the benchmark goroutine itself,
// kept separate from the reported timing metrics.
//
// Reproduce on a host matching the 1 vCPU / 4 GB target:
//
//	GOMAXPROCS=1 go test -run '^$' -bench '^BenchmarkGatewayServeHTTPSequential$' -benchtime 2000x -cpu 1 -timeout 60s ./gateway/
func BenchmarkGatewayServeHTTPSequential(b *testing.B) {
	handler, cleanup := newLoadMeasurementGateway(b)
	defer cleanup()

	durations := make([]time.Duration, 0, b.N)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		request := loadMeasurementRequest()
		response := httptest.NewRecorder()
		start := time.Now()
		handler.ServeHTTP(response, request)
		durations = append(durations, time.Since(start))
		if response.Code != http.StatusOK {
			b.Fatalf("unexpected status %d on iteration %d", response.Code, i)
		}
	}
	b.StopTimer()
	reportLatencyPercentiles(b, durations)
}

// BenchmarkGatewayServeHTTPParallel measures throughput under bounded
// concurrent admission (MaxInFlight=256) against the same local fixture.
// Per-request failures are counted with an atomic and reported once from the
// benchmark's own goroutine after RunParallel returns: calling b.Fatal from
// the worker goroutines RunParallel spawns is unsupported by testing.B.
//
// Reproduce on a host matching the 1 vCPU / 4 GB target:
//
//	GOMAXPROCS=1 go test -run '^$' -bench '^BenchmarkGatewayServeHTTPParallel$' -benchtime 2000x -cpu 1 -timeout 60s ./gateway/
func BenchmarkGatewayServeHTTPParallel(b *testing.B) {
	handler, cleanup := newLoadMeasurementGateway(b)
	defer cleanup()

	var unexpected int64
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			request := loadMeasurementRequest()
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusOK {
				atomic.AddInt64(&unexpected, 1)
			}
		}
	})
	b.StopTimer()
	if unexpected != 0 {
		b.Fatalf("%d requests returned an unexpected status", unexpected)
	}
}
