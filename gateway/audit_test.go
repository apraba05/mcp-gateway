package gateway_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/apraba05/mcp-gateway/gateway"
)

// genesisAuditHash is the fixed 64-character hex chain root every process
// (re)start begins from, since the audit chain is held only in memory.
const genesisAuditHash = "0000000000000000000000000000000000000000000000000000000000000000"

func TestAuditMetadataRedactionPrecedesLoggingAndHashing(t *testing.T) {
	t.Parallel()

	var logs bytes.Buffer
	handler, err := newTestGateway(gateway.Config{
		UpstreamURL: "http://127.0.0.1:1", UpstreamTimeout: time.Second,
		MaxRequestBytes: 1024, MaxResponseBytes: 1024,
		ToolPolicies:        []gateway.ToolPolicy{{ClientID: "legacy-test-client", Tool: "private.tool", Allow: false}},
		RedactAuditMetadata: []string{"request_id", "client_id", "tool"},
		Logger:              slog.New(slog.NewJSONHandler(&logs, nil)),
	})
	if err != nil {
		t.Fatalf("new gateway: %v", err)
	}
	request := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBufferString(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"private.tool"}}`))
	request.Header.Set("X-Request-ID", "private-request")
	handler.ServeHTTP(httptest.NewRecorder(), request)

	var entry map[string]any
	if err := json.Unmarshal(logs.Bytes(), &entry); err != nil {
		t.Fatalf("decode audit log: %v", err)
	}
	for _, field := range []string{"request_id", "client_id", "tool"} {
		if entry[field] != "[REDACTED]" {
			t.Errorf("%s = %#v, want redacted marker", field, entry[field])
		}
	}
	for _, secret := range []string{"private-request", "legacy-test-client", "private.tool"} {
		if bytes.Contains(logs.Bytes(), []byte(secret)) {
			t.Errorf("audit output retained redacted metadata %q", secret)
		}
	}
}

func TestAuditHashCoversEveryAuditMetadataFieldIncludingReason(t *testing.T) {
	t.Parallel()

	var logs bytes.Buffer
	handler, err := newTestGateway(gateway.Config{
		UpstreamURL: "http://127.0.0.1:1", UpstreamTimeout: time.Second,
		MaxRequestBytes: 1024, MaxResponseBytes: 1024,
		Logger: slog.New(slog.NewJSONHandler(&logs, nil)),
	})
	if err != nil {
		t.Fatalf("new gateway: %v", err)
	}
	request := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBufferString(`not-json`))
	request.Header.Set("X-Request-ID", "hash-coverage-1")
	handler.ServeHTTP(httptest.NewRecorder(), request)

	var entry map[string]any
	if err := json.Unmarshal(logs.Bytes(), &entry); err != nil {
		t.Fatalf("decode audit log: %v", err)
	}
	canonical := struct {
		Sequence    uint64 `json:"sequence"`
		Previous    string `json:"previous"`
		RequestID   string `json:"request_id"`
		ClientID    string `json:"client_id"`
		Tool        string `json:"tool"`
		Decision    string `json:"decision"`
		ResultClass string `json:"result_class"`
		Method      string `json:"method"`
		Path        string `json:"path"`
		Reason      string `json:"reason"`
		Status      int    `json:"status"`
		LatencyMS   int64  `json:"latency_ms"`
	}{
		Sequence: 1, Previous: entry["audit_prev_hash"].(string),
		RequestID: entry["request_id"].(string), ClientID: entry["client_id"].(string),
		Tool: entry["tool"].(string), Decision: entry["decision"].(string),
		ResultClass: entry["result_class"].(string), Method: entry["method"].(string),
		Path: entry["path"].(string), Reason: entry["reason"].(string),
		Status: int(entry["status"].(float64)), LatencyMS: int64(entry["latency_ms"].(float64)),
	}
	encoded, err := json.Marshal(canonical)
	if err != nil {
		t.Fatalf("marshal canonical event: %v", err)
	}
	want := sha256.Sum256(encoded)
	if entry["audit_hash"] != hex.EncodeToString(want[:]) {
		t.Errorf("audit hash does not cover complete emitted event: got %v want %x", entry["audit_hash"], want)
	}
}

func TestAuditRecordIncludesDeniedToolWithoutPayloadOrCredential(t *testing.T) {
	t.Parallel()

	var logs bytes.Buffer
	handler, err := newTestGateway(gateway.Config{
		UpstreamURL:      "http://127.0.0.1:1",
		UpstreamTimeout:  time.Second,
		MaxRequestBytes:  1 << 20,
		MaxResponseBytes: 1 << 20,
		ToolPolicies: []gateway.ToolPolicy{{
			ClientID: "legacy-test-client", Tool: "filesystem.delete", Allow: false,
		}},
		Logger: slog.New(slog.NewJSONHandler(&logs, nil)),
	})
	if err != nil {
		t.Fatalf("new gateway: %v", err)
	}
	const secretArgument = "payload-secret-must-not-appear"
	request := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBufferString(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"filesystem.delete","arguments":{"token":"`+secretArgument+`"}}}`))
	request.Header.Set("X-Request-ID", "deny-1")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", response.Code)
	}
	var entry map[string]any
	if err := json.Unmarshal(logs.Bytes(), &entry); err != nil {
		t.Fatalf("decode structured log %q: %v", logs.String(), err)
	}
	if entry["client_id"] != "legacy-test-client" || entry["tool"] != "filesystem.delete" {
		t.Errorf("actor/tool = %#v/%#v", entry["client_id"], entry["tool"])
	}
	if entry["decision"] != "deny" || entry["result_class"] != "denied" {
		t.Errorf("decision/result = %#v/%#v", entry["decision"], entry["result_class"])
	}
	if bytes.Contains(logs.Bytes(), []byte(secretArgument)) || bytes.Contains(logs.Bytes(), []byte(legacyTestAPIKey)) {
		t.Fatal("audit log contains payload or credential")
	}
}

func TestAuditRecordIncludesDecisionResultClassAndChainFieldsOnSuccess(t *testing.T) {
	t.Parallel()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{}`)
	}))
	defer upstream.Close()
	var logs bytes.Buffer
	handler, err := newTestGateway(gateway.Config{
		UpstreamURL:      upstream.URL,
		UpstreamTimeout:  time.Second,
		MaxRequestBytes:  1 << 20,
		MaxResponseBytes: 1 << 20,
		Logger:           slog.New(slog.NewJSONHandler(&logs, nil)),
	})
	if err != nil {
		t.Fatalf("new gateway: %v", err)
	}
	request := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBufferString(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	var entry map[string]any
	if err := json.Unmarshal(logs.Bytes(), &entry); err != nil {
		t.Fatalf("decode structured log %q: %v", logs.String(), err)
	}
	if entry["decision"] != "allow" {
		t.Errorf("decision = %#v, want allow", entry["decision"])
	}
	if entry["result_class"] != "success" {
		t.Errorf("result_class = %#v, want success", entry["result_class"])
	}
	if reason, present := entry["reason"]; !present || reason != "" {
		t.Errorf("reason = %#v (present=%v), want explicit empty string", reason, present)
	}
	if entry["tool"] != "" {
		t.Errorf("tool = %#v, want empty (non tools/call method)", entry["tool"])
	}
	if entry["audit_seq"] != float64(1) {
		t.Errorf("audit_seq = %#v, want 1", entry["audit_seq"])
	}
	prevHash, _ := entry["audit_prev_hash"].(string)
	if prevHash != genesisAuditHash {
		t.Errorf("audit_prev_hash = %#v, want genesis", entry["audit_prev_hash"])
	}
	hash, ok := entry["audit_hash"].(string)
	if !ok || len(hash) != 64 || hash == prevHash {
		t.Errorf("audit_hash = %#v, want distinct 64-hex-char value", entry["audit_hash"])
	}
}
