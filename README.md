# MCP Gateway

MCP Gateway is a small, observable HTTP control point for Model Context Protocol JSON-RPC traffic. The Day 20 milestone adds payload-safe, tamper-evident audit events to per-tool rate limits, deny-by-default authorization, hashed API-key authentication, the bounded transparent proxy, correlation IDs, typed startup configuration, and health checks.

## Quickstart

Start any HTTP MCP server on `127.0.0.1:9000`, then run:

```bash
export MCP_GATEWAY_UPSTREAM_URL=http://127.0.0.1:9000/mcp
export MCP_GATEWAY_LISTEN_ADDRESS=127.0.0.1:8080
export MCP_GATEWAY_UPSTREAM_TIMEOUT=10s
export MCP_GATEWAY_READ_TIMEOUT=10s
export MCP_GATEWAY_WRITE_TIMEOUT=15s
export MCP_GATEWAY_IDLE_TIMEOUT=60s
export MCP_GATEWAY_MAX_REQUEST_BYTES=1048576
export MCP_GATEWAY_MAX_RESPONSE_BYTES=4194304
# Store only a SHA-256 digest in gateway configuration. Use a high-entropy key.
read -rsp 'Gateway API key: ' MCP_CLIENT_KEY; echo
export MCP_GATEWAY_API_KEYS="local-demo=$(printf %s "$MCP_CLIENT_KEY" | sha256sum | cut -d' ' -f1)"
# Unlisted client/tool pairs and explicit deny entries cannot call upstream.
export MCP_GATEWAY_TOOL_POLICIES='local-demo:weather.lookup=allow,local-demo:filesystem.delete=deny'
# Every allowed client/tool pair has exactly one token bucket. This bucket
# starts with 10 tokens and refills one token per second.
export MCP_GATEWAY_TOOL_RATE_LIMITS='local-demo:weather.lookup=10/1s'
# Optional: replace selected safe metadata before both logging and hashing.
export MCP_GATEWAY_AUDIT_REDACT='client_id,tool'
go run ./cmd/mcp-gateway
```

Send an MCP JSON-RPC request:

```bash
printf '%s\n' \
  "header = \"X-MCP-Gateway-Key: $MCP_CLIENT_KEY\"" \
  'header = "Content-Type: application/json"' \
  'header = "X-Request-ID: demo-1"' \
  'data = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}"' \
  | curl -i --config - http://127.0.0.1:8080/mcp
```

Check process health without contacting the upstream:

```bash
curl -i http://127.0.0.1:8080/healthz
```

## HTTP contract

| Endpoint | Method | Behavior |
| --- | --- | --- |
| `/mcp` | `POST` | Requires a valid `X-MCP-Gateway-Key`. `tools/call` requests also require an explicit allow policy for that client and tool; other valid JSON-RPC methods pass through. Permitted requests preserve the body and end-to-end MCP headers. The gateway credential and hop-by-hop HTTP headers are removed. |
| `/healthz` | `GET` | Returns `200` and `{"status":"ok"}` without a client credential when the gateway process is serving. |

A valid inbound `X-Request-ID` (`A-Z`, `a-z`, digits, `.`, `_`, or `-`; at most 128 characters) is preserved. Missing or unsafe IDs are replaced with a cryptographically random ID. The selected ID is sent upstream and returned to the client.

Missing, invalid, empty, whitespace-only, ambiguous repeated/comma-joined, and over-256-byte gateway keys return a generic `401` without an upstream call. Explicitly denied and unlisted `tools/call` pairs return a generic `403`; malformed JSON, top-level JSON-RPC batch arrays (not currently supported), ambiguous duplicate JSON-RPC fields, and tool calls without one safe 1–128 character tool name return a generic `400`. An exhausted permitted tool bucket returns generic `429` before upstream with integer-seconds `Retry-After` (rounded up, minimum 1) and `X-RateLimit-Retry-After-Ms` (rounded up, minimum 1) headers. A permitted attempt consumes a token even if upstream later fails. Buckets are isolated by configured client ID and tool; non-`tools/call` methods do not consume tokens. These failures occur before the upstream call and do not reflect tool names, arguments, or credentials. Other HTTP methods return `405`; unknown paths return `404`. Requests above the configured cap are rejected with `413` before an upstream call. Responses above their cap are fully discarded and replaced with `502`, so partial upstream success is never published. Hung upstreams map to `504`; malformed upstream HTTP and other transport failures map to `502`. Client cancellation propagates through the outbound request. Error bodies and logged reason codes are fixed and bounded rather than reflecting request payloads, credentials, or upstream diagnostics.

## Configuration

All settings are validated before the listener starts. `MCP_GATEWAY_TOOL_POLICIES` and `MCP_GATEWAY_TOOL_RATE_LIMITS` may both be omitted to deny every `tools/call`. Every allow policy otherwise requires exactly one matching rate limit; deny and unknown pairs cannot have one. Durations use Go syntax such as `500ms`, `10s`, or `1m` and must be positive and no greater than five minutes.

| Environment variable | Meaning |
| --- | --- |
| `MCP_GATEWAY_UPSTREAM_URL` | Absolute `http` or `https` MCP endpoint; embedded user information is rejected. |
| `MCP_GATEWAY_LISTEN_ADDRESS` | Listener in `host:port` form. Use a loopback host for local-only access. |
| `MCP_GATEWAY_UPSTREAM_TIMEOUT` | End-to-end upstream HTTP timeout. |
| `MCP_GATEWAY_READ_TIMEOUT` | Client request and header read timeout. |
| `MCP_GATEWAY_WRITE_TIMEOUT` | Client response write timeout. |
| `MCP_GATEWAY_IDLE_TIMEOUT` | Keep-alive idle timeout. |
| `MCP_GATEWAY_MAX_REQUEST_BYTES` | Maximum inbound MCP request body in bytes (1–67,108,864). |
| `MCP_GATEWAY_MAX_RESPONSE_BYTES` | Maximum upstream response body in bytes (1–67,108,864). |
| `MCP_GATEWAY_API_KEYS` | Required comma-separated `safe-client-id=sha256-hex` entries. IDs use 1–64 letters, digits, `.`, `_`, or `-`; IDs and hashes must be unique; at most 1,000 entries. |
| `MCP_GATEWAY_TOOL_POLICIES` | Optional comma-separated `client-id:tool=allow\|deny` entries. Client IDs must identify configured API keys; tool names use 1–128 letters, digits, `.`, `_`, or `-`; each client/tool pair is unique; at most 1,000 entries. Empty/unset means all `tools/call` requests are denied. |
| `MCP_GATEWAY_TOOL_RATE_LIMITS` | Comma-separated `client-id:tool=capacity/refill-interval` entries, one for every allow policy and none for deny/unknown pairs. Capacity is 1–100,000,000; interval is positive and at most five minutes; pairs are unique; at most 1,000 fixed buckets. Example: `local-demo:weather.lookup=10/1s`. |
| `MCP_GATEWAY_AUDIT_REDACT` | Optional comma-separated unique fields to replace with `[REDACTED]` before logging and hashing: `request_id`, `client_id`, and/or `tool`. Empty means safe configured metadata is retained. |

## Observability and safety

Logs are newline-delimited JSON emitted to stdout. Every handled `/mcp` request produces one `mcp audit event` after a request ID is available. Events contain the authenticated safe client ID (or empty for failed authentication), safe configured tool name when one was parsed, allow/deny decision, bounded result class and reason, HTTP status, latency, method/path, and correlation ID. Request and response payloads, tool arguments, presented credentials, authorization values, URL credentials, and upstream diagnostics are never logged. Optional metadata redaction happens before both output and hashing.

Audit events carry a process-local sequence, previous hash, and SHA-256 event hash. The hash covers the sequence, previous hash, emitted/redacted request ID, client ID, tool, decision, result class, method, path, reason, status, and latency using the canonical JSON field order implemented by `auditCanonical`. Event emission and chain mutation share one mutex, so concurrent requests cannot fork or reorder the chain. The first event after each process start uses 64 zeroes as its previous hash; chain state is intentionally not persisted, so restarts begin a new verifiable segment. Copy logs to append-only external storage if restart continuity or stronger deletion resistance is required. Chaining detects field modification and insertion/reordering within a retained segment; it does not prevent deletion of an entire tail or compromise of the running process.

Runtime rate-limit state has fixed startup-bounded cardinality: request-controlled client IDs or tool names never allocate buckets.

Use independently generated high-entropy API keys: plain SHA-256 digests do not protect weak, guessable secrets from offline guessing. Restrict access to the configuration environment because its hashes are authentication material. The quickstart supplies curl's credential header through standard input rather than exposing the raw key in curl's process arguments.

The gateway currently exposes liveness rather than upstream readiness. Rate limits are process-local and reset on restart; distributed deployments need a shared limiter if fleet-wide enforcement is required. The audit chain is process-local as described above. Body caps bound per-request buffering, but a later concurrency milestone will add aggregate admission control.

## Architecture

```text
MCP client --HTTP JSON-RPC--> gateway handler --bounded HTTP client--> MCP upstream
                   |                |
                   |                +-- JSON structured logs (metadata only)
                   +-- /healthz and X-Request-ID correlation
```

The executable loads typed configuration, constructs a bounded `http.Server`, and handles `SIGINT`/`SIGTERM` with a ten-second graceful-shutdown deadline.

## Verification

```bash
gofmt -w gateway internal cmd
go test ./...
go test -race ./...
go vet ./...
go build ./cmd/mcp-gateway
```

## License

MIT — see [LICENSE](LICENSE).
