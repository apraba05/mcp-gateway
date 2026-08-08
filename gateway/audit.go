package gateway

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"sync"
)

const redactedAuditValue = "[REDACTED]"

type auditChain struct {
	mu       sync.Mutex
	sequence uint64
	previous [sha256.Size]byte
	logger   *slog.Logger
	redact   map[string]bool
}

type auditCanonical struct {
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
}

func newAuditChain(logger *slog.Logger, redactedFields []string) *auditChain {
	redact := make(map[string]bool, len(redactedFields))
	for _, field := range redactedFields {
		redact[field] = true
	}
	return &auditChain{logger: logger, redact: redact}
}

func (a *auditChain) record(requestID, clientID, tool, decision, resultClass string, status int, latencyMS int64, reason string) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.redact["request_id"] {
		requestID = redactedAuditValue
	}
	if a.redact["client_id"] {
		clientID = redactedAuditValue
	}
	if a.redact["tool"] && tool != "" {
		tool = redactedAuditValue
	}
	a.sequence++
	previous := hex.EncodeToString(a.previous[:])
	canonical := auditCanonical{
		Sequence: a.sequence, Previous: previous, RequestID: requestID,
		ClientID: clientID, Tool: tool, Decision: decision,
		ResultClass: resultClass, Method: "POST", Path: "/mcp", Reason: reason,
		Status: status, LatencyMS: latencyMS,
	}
	encoded, _ := json.Marshal(canonical) // fixed fields cannot fail to marshal
	hash := sha256.Sum256(encoded)
	a.previous = hash
	attributes := []any{
		"request_id", requestID, "client_id", clientID, "tool", tool,
		"decision", decision, "result_class", resultClass, "status", status,
		"method", "POST", "path", "/mcp", "reason", reason,
		"latency_ms", latencyMS, "audit_seq", a.sequence,
		"audit_prev_hash", previous, "audit_hash", hex.EncodeToString(hash[:]),
	}
	a.logger.Info("mcp audit event", attributes...)
}
