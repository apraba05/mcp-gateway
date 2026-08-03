// Package gateway provides an HTTP gateway for MCP JSON-RPC traffic.
package gateway

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
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
var validAPIKeyID = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
var validToolName = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

// statusClientClosedRequest mirrors the widely used (non-standard) nginx
// convention for a request whose client disconnected before completion.
const statusClientClosedRequest = 499

const maxBodyBytes int64 = 64 * 1024 * 1024

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
	UpstreamURL      string
	UpstreamTimeout  time.Duration
	MaxRequestBytes  int64
	MaxResponseBytes int64
	APIKeys          []APIKey
	ToolPolicies     []ToolPolicy
	Logger           *slog.Logger
}

// APIKey identifies a client without retaining its raw credential. SHA256 is
// the SHA-256 digest of the value clients send in X-MCP-Gateway-Key.
type APIKey struct {
	ID     string
	SHA256 [sha256.Size]byte
}

// ToolPolicy grants or denies one authenticated client permission to invoke
// one MCP tool by name via tools/call. Any (client, tool) pair without a
// matching policy is denied by default.
type ToolPolicy struct {
	ClientID string
	Tool     string
	Allow    bool
}

type handler struct {
	upstream         *url.URL
	client           *http.Client
	maxRequestBytes  int64
	maxResponseBytes int64
	apiKeys          []APIKey
	toolPolicies     map[string]map[string]bool
	logger           *slog.Logger
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
	if cfg.MaxRequestBytes <= 0 || cfg.MaxRequestBytes > maxBodyBytes {
		return nil, errors.New("max request bytes must be between 1 and 67108864")
	}
	if cfg.MaxResponseBytes <= 0 || cfg.MaxResponseBytes > maxBodyBytes {
		return nil, errors.New("max response bytes must be between 1 and 67108864")
	}
	if cfg.Logger == nil {
		return nil, errors.New("logger is required")
	}
	if len(cfg.APIKeys) == 0 {
		return nil, errors.New("at least one hashed API key is required")
	}
	if len(cfg.APIKeys) > 1000 {
		return nil, errors.New("at most 1000 API keys are supported")
	}
	seenKeyIDs := make(map[string]struct{}, len(cfg.APIKeys))
	seenKeyHashes := make(map[[sha256.Size]byte]struct{}, len(cfg.APIKeys))
	var zeroHash [sha256.Size]byte
	for _, key := range cfg.APIKeys {
		if !validAPIKeyID.MatchString(key.ID) {
			return nil, errors.New("API key identifier must contain only letters, digits, dot, underscore, or hyphen and be at most 64 characters")
		}
		if key.SHA256 == zeroHash {
			return nil, errors.New("API key hash must not be all zeroes")
		}
		if _, exists := seenKeyIDs[key.ID]; exists {
			return nil, errors.New("API key identifiers must be unique")
		}
		if _, exists := seenKeyHashes[key.SHA256]; exists {
			return nil, errors.New("API key hashes must be unique")
		}
		seenKeyIDs[key.ID] = struct{}{}
		seenKeyHashes[key.SHA256] = struct{}{}
	}
	if len(cfg.ToolPolicies) > 1000 {
		return nil, errors.New("at most 1000 tool policies are supported")
	}
	toolPolicies := make(map[string]map[string]bool, len(cfg.ToolPolicies))
	seenToolPolicies := make(map[[2]string]struct{}, len(cfg.ToolPolicies))
	for _, policy := range cfg.ToolPolicies {
		if !validAPIKeyID.MatchString(policy.ClientID) {
			return nil, errors.New("tool policy client identifier must contain only letters, digits, dot, underscore, or hyphen and be at most 64 characters")
		}
		if !validToolName.MatchString(policy.Tool) {
			return nil, errors.New("tool policy tool name must contain only letters, digits, dot, underscore, or hyphen and be at most 128 characters")
		}
		if _, exists := seenKeyIDs[policy.ClientID]; !exists {
			return nil, errors.New("tool policy client identifier must match a configured API key identifier")
		}
		key := [2]string{policy.ClientID, policy.Tool}
		if _, exists := seenToolPolicies[key]; exists {
			return nil, errors.New("tool policies must be unique per client and tool")
		}
		seenToolPolicies[key] = struct{}{}
		if toolPolicies[policy.ClientID] == nil {
			toolPolicies[policy.ClientID] = make(map[string]bool)
		}
		toolPolicies[policy.ClientID][policy.Tool] = policy.Allow
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
		maxRequestBytes:  cfg.MaxRequestBytes,
		maxResponseBytes: cfg.MaxResponseBytes,
		apiKeys:          append([]APIKey(nil), cfg.APIKeys...),
		toolPolicies:     toolPolicies,
		logger:           cfg.Logger,
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

	requestID := r.Header.Get("X-Request-ID")
	if !validRequestID.MatchString(requestID) {
		var err error
		requestID, err = newRequestID()
		if err != nil {
			http.Error(w, "gateway request failed", http.StatusInternalServerError)
			return
		}
	}
	w.Header().Set("X-Request-ID", requestID)

	started := time.Now()
	clientID, authenticated := h.authenticate(r.Header.Values("X-MCP-Gateway-Key"))
	if len(h.apiKeys) > 0 && !authenticated {
		h.writeError(w, r, requestID, started, http.StatusUnauthorized, "authentication_failed")
		return
	}

	if r.ContentLength > h.maxRequestBytes {
		h.writeError(w, r, requestID, started, http.StatusRequestEntityTooLarge, "request_too_large")
		return
	}
	requestBody, err := io.ReadAll(io.LimitReader(r.Body, h.maxRequestBytes+1))
	if err != nil {
		status, reason := classifyContextError(r.Context())
		h.writeError(w, r, requestID, started, status, reason)
		return
	}
	if int64(len(requestBody)) > h.maxRequestBytes {
		h.writeError(w, r, requestID, started, http.StatusRequestEntityTooLarge, "request_too_large")
		return
	}
	if status := h.authorizeToolCall(requestBody, clientID); status != 0 {
		reason := "authorization_denied"
		if status == http.StatusBadRequest {
			reason = "invalid_tool_call"
		}
		h.writeError(w, r, requestID, started, status, reason)
		return
	}

	upstreamRequest, err := http.NewRequestWithContext(r.Context(), http.MethodPost, h.upstream.String(), bytes.NewReader(requestBody))
	if err != nil {
		http.Error(w, "gateway request failed", http.StatusBadGateway)
		return
	}
	copyEndToEndHeaders(upstreamRequest.Header, r.Header)
	upstreamRequest.Header.Del("X-MCP-Gateway-Key")
	upstreamRequest.Header.Set("X-Request-ID", requestID)

	response, err := h.client.Do(upstreamRequest)
	if err != nil {
		status, reason := classifyUpstreamError(err)
		h.writeError(w, r, requestID, started, status, reason)
		return
	}
	defer response.Body.Close()

	responseBody, err := io.ReadAll(io.LimitReader(response.Body, h.maxResponseBytes+1))
	if err != nil {
		status, reason := classifyUpstreamError(err)
		h.writeError(w, r, requestID, started, status, reason)
		return
	}
	if int64(len(responseBody)) > h.maxResponseBytes {
		h.writeError(w, r, requestID, started, http.StatusBadGateway, "upstream_response_too_large")
		return
	}

	copyEndToEndHeaders(w.Header(), response.Header)
	w.Header().Set("X-Request-ID", requestID)
	if _, present := response.Header["Content-Type"]; !present {
		w.Header()["Content-Type"] = nil
	}
	w.WriteHeader(response.StatusCode)
	if _, err := w.Write(responseBody); err != nil {
		h.logger.Error("write gateway response", "request_id", requestID, "reason", "client_write_failed")
	}
	h.logger.Info("mcp request completed", "request_id", requestID, "client_id", clientID, "method", r.Method, "path", r.URL.Path, "status", response.StatusCode, "latency_ms", time.Since(started).Milliseconds())
}

func (h *handler) authorizeToolCall(body []byte, clientID string) int {
	request, ok := decodeUniqueJSONObject(body)
	if !ok {
		return http.StatusBadRequest
	}
	methodValue, present := request["method"]
	if !present {
		return 0
	}
	var method string
	if err := json.Unmarshal(methodValue, &method); err != nil {
		return http.StatusBadRequest
	}
	if method != "tools/call" {
		return 0
	}
	paramsValue, present := request["params"]
	if !present {
		return http.StatusBadRequest
	}
	params, ok := decodeUniqueJSONObject(paramsValue)
	if !ok {
		return http.StatusBadRequest
	}
	nameValue, present := params["name"]
	if !present {
		return http.StatusBadRequest
	}
	var name string
	if err := json.Unmarshal(nameValue, &name); err != nil || !validToolName.MatchString(name) {
		return http.StatusBadRequest
	}
	if !h.toolPolicies[clientID][name] {
		return http.StatusForbidden
	}
	return 0
}

func decodeUniqueJSONObject(value []byte) (map[string]json.RawMessage, bool) {
	decoder := json.NewDecoder(bytes.NewReader(value))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return nil, false
	}
	fields := make(map[string]json.RawMessage)
	for decoder.More() {
		token, err = decoder.Token()
		name, isString := token.(string)
		if err != nil || !isString {
			return nil, false
		}
		if _, duplicate := fields[name]; duplicate {
			return nil, false
		}
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err != nil {
			return nil, false
		}
		fields[name] = raw
	}
	if token, err = decoder.Token(); err != nil || token != json.Delim('}') {
		return nil, false
	}
	if token, err = decoder.Token(); err != io.EOF {
		return nil, false
	}
	return fields, true
}

func (h *handler) authenticate(values []string) (string, bool) {
	if len(values) != 1 {
		return "", false
	}
	raw := values[0]
	if len(raw) > 256 || strings.Contains(raw, ",") {
		return "", false
	}
	digest := sha256.Sum256([]byte(raw))
	matchedID := ""
	matched := 0
	for _, key := range h.apiKeys {
		equal := subtle.ConstantTimeCompare(digest[:], key.SHA256[:])
		if equal == 1 {
			matchedID = key.ID
		}
		matched |= equal
	}
	return matchedID, matched == 1 && strings.TrimSpace(raw) != ""
}

// writeError logs a bounded, deterministic diagnostic and sends a generic
// error body. It never reflects upstream or request payload content.
func (h *handler) writeError(w http.ResponseWriter, r *http.Request, requestID string, started time.Time, status int, reason string) {
	h.logger.Warn("mcp request completed", "request_id", requestID, "method", r.Method, "path", r.URL.Path, "status", status, "reason", reason, "latency_ms", time.Since(started).Milliseconds())
	http.Error(w, errorText(status), status)
}

// classifyContextError maps a failure reading the inbound request body to a
// deterministic status and bounded reason, without reflecting the raw error.
func classifyContextError(ctx context.Context) (int, string) {
	switch {
	case errors.Is(ctx.Err(), context.Canceled):
		return statusClientClosedRequest, "client_canceled"
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		return http.StatusRequestTimeout, "client_timeout"
	default:
		return http.StatusBadRequest, "invalid_request_body"
	}
}

// classifyUpstreamError maps an upstream transport failure to a deterministic
// status and bounded reason, without reflecting the raw upstream error text.
func classifyUpstreamError(err error) (int, string) {
	switch {
	case errors.Is(err, context.Canceled):
		return statusClientClosedRequest, "client_canceled"
	case errors.Is(err, context.DeadlineExceeded):
		return http.StatusGatewayTimeout, "upstream_timeout"
	default:
		return http.StatusBadGateway, "upstream_error"
	}
}

// errorText returns bounded, fixed status text, including for the
// non-standard statusClientClosedRequest code that net/http does not know.
func errorText(status int) string {
	if status == statusClientClosedRequest {
		return "Client Closed Request"
	}
	if text := http.StatusText(status); text != "" {
		return text
	}
	return "gateway error"
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
