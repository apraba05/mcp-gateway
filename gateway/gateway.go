// Package gateway provides an HTTP gateway for MCP JSON-RPC traffic.
package gateway

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

var validRequestID = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

var hopByHopHeaders = map[string]struct{}{
	"Connection":          {},
	"Keep-Alive":          {},
	"Proxy-Authenticate":  {},
	"Proxy-Authorization": {},
	"Proxy-Connection":    {},
	"Te":                  {},
	"Trailer":             {},
	"Transfer-Encoding":   {},
	"Upgrade":             {},
}

// Config contains the gateway's runtime dependencies and upstream settings.
type Config struct {
	UpstreamURL     string
	UpstreamTimeout time.Duration
	Logger          *slog.Logger
}

type handler struct {
	upstream *url.URL
	client   *http.Client
	logger   *slog.Logger
}

// New validates config and returns an MCP gateway HTTP handler.
func New(cfg Config) (http.Handler, error) {
	upstream, err := url.ParseRequestURI(cfg.UpstreamURL)
	if err != nil || (upstream.Scheme != "http" && upstream.Scheme != "https") || upstream.Hostname() == "" || upstream.User != nil {
		return nil, errors.New("upstream URL must be an absolute HTTP(S) URL without user information")
	}
	if cfg.UpstreamTimeout <= 0 {
		return nil, errors.New("upstream timeout must be positive")
	}
	if cfg.Logger == nil {
		return nil, errors.New("logger is required")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DisableCompression = true
	return &handler{
		upstream: upstream,
		client: &http.Client{
			Timeout:   cfg.UpstreamTimeout,
			Transport: transport,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		logger: cfg.Logger,
	}, nil
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/healthz" {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "{\"status\":\"ok\"}\n")
		return
	}
	if r.URL.Path != "/mcp" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	upstreamRequest, err := http.NewRequestWithContext(r.Context(), http.MethodPost, h.upstream.String(), r.Body)
	if err != nil {
		http.Error(w, "gateway request failed", http.StatusBadGateway)
		return
	}
	copyEndToEndHeaders(upstreamRequest.Header, r.Header)
	upstreamRequest.ContentLength = r.ContentLength
	requestID := r.Header.Get("X-Request-ID")
	if !validRequestID.MatchString(requestID) {
		requestID, err = newRequestID()
		if err != nil {
			http.Error(w, "gateway request failed", http.StatusInternalServerError)
			return
		}
	}
	upstreamRequest.Header.Set("X-Request-ID", requestID)
	w.Header().Set("X-Request-ID", requestID)

	started := time.Now()
	response, err := h.client.Do(upstreamRequest)
	if err != nil {
		status := http.StatusBadGateway
		if errors.Is(err, context.DeadlineExceeded) {
			status = http.StatusGatewayTimeout
		}
		h.logger.Warn("mcp request completed", "request_id", requestID, "method", r.Method, "path", r.URL.Path, "status", status, "latency_ms", time.Since(started).Milliseconds())
		http.Error(w, http.StatusText(status), status)
		return
	}
	defer response.Body.Close()

	copyEndToEndHeaders(w.Header(), response.Header)
	w.Header().Set("X-Request-ID", requestID)
	if _, present := response.Header["Content-Type"]; !present {
		w.Header()["Content-Type"] = nil
	}
	w.WriteHeader(response.StatusCode)
	if _, err := io.Copy(w, response.Body); err != nil {
		h.logger.Error("copy upstream response", "request_id", requestID, "error", err)
	}
	h.logger.Info("mcp request completed", "request_id", requestID, "method", r.Method, "path", r.URL.Path, "status", response.StatusCode, "latency_ms", time.Since(started).Milliseconds())
}

func newRequestID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(value[:]), nil
}

func copyEndToEndHeaders(destination, source http.Header) {
	connectionHeaders := make(map[string]struct{})
	for _, value := range source.Values("Connection") {
		for _, name := range strings.Split(value, ",") {
			if name = http.CanonicalHeaderKey(strings.TrimSpace(name)); name != "" {
				connectionHeaders[name] = struct{}{}
			}
		}
	}
	for name, values := range source {
		canonicalName := http.CanonicalHeaderKey(name)
		if _, blocked := hopByHopHeaders[canonicalName]; blocked {
			continue
		}
		if _, blocked := connectionHeaders[canonicalName]; blocked {
			continue
		}
		for _, value := range values {
			destination.Add(canonicalName, value)
		}
	}
}
