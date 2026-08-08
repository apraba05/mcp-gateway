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
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
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

// maxRateLimitCapacity and maxRateLimitInterval bound a single token
// bucket's configuration so a misconfigured or malicious value cannot
// request unbounded memory or overflow duration arithmetic during refill.
const maxRateLimitCapacity = 100_000_000

const maxRateLimitInterval = 5 * time.Minute

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
	RateLimits       []RateLimit
	// RedactAuditMetadata may contain request_id, client_id, and tool. Selected
	// metadata is replaced with a fixed marker before logging and hashing.
	RedactAuditMetadata []string
	Logger              *slog.Logger
	// Clock defaults to time.Now when nil. Tests may inject a deterministic
	// clock; production always uses the default.
	Clock func() time.Time
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

// RateLimit bounds one authenticated client's tools/call rate for one MCP
// tool with a token bucket that starts full, holds at most Capacity tokens,
// and refills one token every RefillInterval. Every allow ToolPolicy must
// have exactly one matching RateLimit; deny policies must have none.
type RateLimit struct {
	ClientID       string
	Tool           string
	Capacity       uint32
	RefillInterval time.Duration
}

type handler struct {
	upstream         *url.URL
	client           *http.Client
	maxRequestBytes  int64
	maxResponseBytes int64
	apiKeys          []APIKey
	toolPolicies     map[string]map[string]bool
	rateLimiters     map[string]map[string]*tokenBucket
	audit            *auditChain
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
	seenRedactions := make(map[string]struct{}, len(cfg.RedactAuditMetadata))
	for _, field := range cfg.RedactAuditMetadata {
		if field != "request_id" && field != "client_id" && field != "tool" {
			return nil, errors.New("audit metadata redaction fields must be request_id, client_id, or tool")
		}
		if _, exists := seenRedactions[field]; exists {
			return nil, errors.New("audit metadata redaction fields must be unique")
		}
		seenRedactions[field] = struct{}{}
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
	if len(cfg.RateLimits) > 1000 {
		return nil, errors.New("at most 1000 rate limits are supported")
	}
	allowedPairs := make(map[[2]string]struct{}, len(cfg.ToolPolicies))
	deniedPairs := make(map[[2]string]struct{}, len(cfg.ToolPolicies))
	for _, policy := range cfg.ToolPolicies {
		pair := [2]string{policy.ClientID, policy.Tool}
		if policy.Allow {
			allowedPairs[pair] = struct{}{}
		} else {
			deniedPairs[pair] = struct{}{}
		}
	}
	rateLimiters := make(map[string]map[string]*tokenBucket, len(cfg.RateLimits))
	seenRateLimits := make(map[[2]string]struct{}, len(cfg.RateLimits))
	clock := cfg.Clock
	if clock == nil {
		clock = time.Now
	}
	for _, limit := range cfg.RateLimits {
		if !validAPIKeyID.MatchString(limit.ClientID) {
			return nil, errors.New("rate limit client identifier must contain only letters, digits, dot, underscore, or hyphen and be at most 64 characters")
		}
		if !validToolName.MatchString(limit.Tool) {
			return nil, errors.New("rate limit tool name must contain only letters, digits, dot, underscore, or hyphen and be at most 128 characters")
		}
		if limit.Capacity < 1 || limit.Capacity > maxRateLimitCapacity {
			return nil, fmt.Errorf("rate limit capacity must be between 1 and %d", maxRateLimitCapacity)
		}
		if limit.RefillInterval <= 0 || limit.RefillInterval > maxRateLimitInterval {
			return nil, fmt.Errorf("rate limit refill interval must be a positive duration no greater than %s", maxRateLimitInterval)
		}
		pair := [2]string{limit.ClientID, limit.Tool}
		if _, exists := seenRateLimits[pair]; exists {
			return nil, errors.New("rate limits must be unique per client and tool")
		}
		if _, allowed := allowedPairs[pair]; !allowed {
			if _, denied := deniedPairs[pair]; denied {
				return nil, errors.New("rate limits must not be configured for a denied tool policy")
			}
			return nil, errors.New("rate limits must not be configured without a matching allow tool policy")
		}
		seenRateLimits[pair] = struct{}{}
		if rateLimiters[limit.ClientID] == nil {
			rateLimiters[limit.ClientID] = make(map[string]*tokenBucket)
		}
		rateLimiters[limit.ClientID][limit.Tool] = newTokenBucket(limit.Capacity, limit.RefillInterval, clock)
	}
	for pair := range allowedPairs {
		if _, exists := seenRateLimits[pair]; !exists {
			return nil, errors.New("every allowed tool policy requires exactly one matching rate limit")
		}
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
		rateLimiters:     rateLimiters,
		audit:            newAuditChain(cfg.Logger, cfg.RedactAuditMetadata),
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
		h.writeError(w, requestID, started, "", "", "deny", "denied", http.StatusUnauthorized, "authentication_failed")
		return
	}

	if r.ContentLength > h.maxRequestBytes {
		h.writeError(w, requestID, started, clientID, "", "deny", "rejected", http.StatusRequestEntityTooLarge, "request_too_large")
		return
	}
	requestBody, err := io.ReadAll(io.LimitReader(r.Body, h.maxRequestBytes+1))
	if err != nil {
		status, reason := classifyContextError(r.Context())
		h.writeError(w, requestID, started, clientID, "", "deny", "rejected", status, reason)
		return
	}
	if int64(len(requestBody)) > h.maxRequestBytes {
		h.writeError(w, requestID, started, clientID, "", "deny", "rejected", http.StatusRequestEntityTooLarge, "request_too_large")
		return
	}
	toolName, status := h.authorizeToolCall(requestBody, clientID)
	if status != 0 {
		reason, result := "authorization_denied", "denied"
		if status == http.StatusBadRequest {
			reason, result = "invalid_tool_call", "rejected"
		}
		h.writeError(w, requestID, started, clientID, toolName, "deny", result, status, reason)
		return
	}
	if toolName != "" {
		allowed, retryAfter := h.rateLimiters[clientID][toolName].allow()
		if !allowed {
			retryMilliseconds := (retryAfter + time.Millisecond - 1) / time.Millisecond
			if retryMilliseconds < 1 {
				retryMilliseconds = 1
			}
			retrySeconds := (retryAfter + time.Second - 1) / time.Second
			if retrySeconds < 1 {
				retrySeconds = 1
			}
			w.Header().Set("Retry-After", strconv.FormatInt(int64(retrySeconds), 10))
			w.Header().Set("X-RateLimit-Retry-After-Ms", strconv.FormatInt(int64(retryMilliseconds), 10))
			h.writeError(w, requestID, started, clientID, toolName, "deny", "rate_limited", http.StatusTooManyRequests, "rate_limited")
			return
		}
	}

	upstreamRequest, err := http.NewRequestWithContext(r.Context(), http.MethodPost, h.upstream.String(), bytes.NewReader(requestBody))
	if err != nil {
		h.writeError(w, requestID, started, clientID, toolName, "allow", "upstream_error", http.StatusBadGateway, "upstream_error")
		return
	}
	copyEndToEndHeaders(upstreamRequest.Header, r.Header)
	upstreamRequest.Header.Del("X-MCP-Gateway-Key")
	upstreamRequest.Header.Set("X-Request-ID", requestID)

	response, err := h.client.Do(upstreamRequest)
	if err != nil {
		status, reason := classifyUpstreamError(err)
		h.writeError(w, requestID, started, clientID, toolName, "allow", "upstream_error", status, reason)
		return
	}
	defer response.Body.Close()

	responseBody, err := io.ReadAll(io.LimitReader(response.Body, h.maxResponseBytes+1))
	if err != nil {
		status, reason := classifyUpstreamError(err)
		h.writeError(w, requestID, started, clientID, toolName, "allow", "upstream_error", status, reason)
		return
	}
	if int64(len(responseBody)) > h.maxResponseBytes {
		h.writeError(w, requestID, started, clientID, toolName, "allow", "upstream_error", http.StatusBadGateway, "upstream_response_too_large")
		return
	}

	copyEndToEndHeaders(w.Header(), response.Header)
	w.Header().Set("X-Request-ID", requestID)
	if _, present := response.Header["Content-Type"]; !present {
		w.Header()["Content-Type"] = nil
	}
	w.WriteHeader(response.StatusCode)
	result, reason := resultClass(response.StatusCode), ""
	if _, err := w.Write(responseBody); err != nil {
		result, reason = "client_write_error", "client_write_failed"
	}
	h.audit.record(requestID, clientID, toolName, "allow", result, response.StatusCode, time.Since(started).Milliseconds(), reason)
}

func resultClass(status int) string {
	switch {
	case status >= 200 && status < 400:
		return "success"
	case status >= 500:
		return "upstream_error"
	default:
		return "client_error"
	}
}

func (h *handler) authorizeToolCall(body []byte, clientID string) (string, int) {
	request, ok := decodeUniqueJSONObject(body)
	if !ok {
		return "", http.StatusBadRequest
	}
	methodValue, present := request["method"]
	if !present {
		return "", 0
	}
	var method string
	if err := json.Unmarshal(methodValue, &method); err != nil {
		return "", http.StatusBadRequest
	}
	if method != "tools/call" {
		return "", 0
	}
	paramsValue, present := request["params"]
	if !present {
		return "", http.StatusBadRequest
	}
	params, ok := decodeUniqueJSONObject(paramsValue)
	if !ok {
		return "", http.StatusBadRequest
	}
	nameValue, present := params["name"]
	if !present {
		return "", http.StatusBadRequest
	}
	var name string
	if err := json.Unmarshal(nameValue, &name); err != nil || !validToolName.MatchString(name) {
		return "", http.StatusBadRequest
	}
	if !h.toolPolicies[clientID][name] {
		return name, http.StatusForbidden
	}
	return name, 0
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

// writeError logs a bounded audit event and sends a generic error body. It
// never reflects upstream diagnostics, request payloads, or credentials.
func (h *handler) writeError(w http.ResponseWriter, requestID string, started time.Time, clientID, tool, decision, resultClass string, status int, reason string) {
	h.audit.record(requestID, clientID, tool, decision, resultClass, status, time.Since(started).Milliseconds(), reason)
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
