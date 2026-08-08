# MCP Gateway

MCP Gateway is a small, observable HTTP control point for Model Context Protocol JSON-RPC traffic. The Day 22 milestone adds bounded protocol/authentication fuzzing and a reproducible one-vCPU load measurement to the readiness, backpressure, safe retries, payload-safe audit logs, per-tool controls, hashed authentication, and bounded transparent proxy.

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
export MCP_GATEWAY_MAX_IN_FLIGHT=64
# Zero disables retries; at most 3 retries are allowed.
export MCP_GATEWAY_MAX_SAFE_RETRIES=1
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
curl -i http://127.0.0.1:8080/readyz
```

## HTTP contract

| Endpoint | Method | Behavior |
| --- | --- | --- |
| `/mcp` | `POST` | Requires a valid `X-MCP-Gateway-Key`. `tools/call` requests also require an explicit allow policy for that client and tool; other valid JSON-RPC methods pass through. Permitted requests preserve the body and end-to-end MCP headers. The gateway credential and hop-by-hop HTTP headers are removed. |
| `/healthz` | `GET` | Returns `200` and `{"status":"ok"}` without a client credential when the gateway process is serving. |
| `/readyz` | `GET` | Intentionally credential-free for orchestrator probes. Returns `200` while new work is accepted and bounded `503` after shutdown draining begins. It never contacts the upstream or exposes configuration. |

A valid inbound `X-Request-ID` (`A-Z`, `a-z`, digits, `.`, `_`, or `-`; at most 128 characters) is preserved. Missing or unsafe IDs are replaced with a cryptographically random ID. The selected ID is sent upstream and returned to the client.

Missing, invalid, empty, whitespace-only, ambiguous repeated/comma-joined, and over-256-byte gateway keys return a generic `401` without an upstream call. Explicitly denied and unlisted `tools/call` pairs return a generic `403`; malformed JSON, top-level JSON-RPC batch arrays (not currently supported), ambiguous duplicate JSON-RPC fields, and tool calls without one safe 1–128 character tool name return a generic `400`. An exhausted permitted tool bucket returns generic `429` before upstream with integer-seconds `Retry-After` (rounded up, minimum 1) and `X-RateLimit-Retry-After-Ms` (rounded up, minimum 1) headers. A permitted attempt consumes a token even if upstream later fails. Buckets are isolated by configured client ID and tool; non-`tools/call` methods do not consume tokens. These failures occur before the upstream call and do not reflect tool names, arguments, or credentials. Other HTTP methods return `405`; unknown paths return `404`. Requests above the configured cap are rejected with `413` before an upstream call. Responses above their cap are fully discarded and replaced with `502`, so partial upstream success is never published. Hung upstreams map to `504`; malformed upstream HTTP and other transport failures map to `502`. Client cancellation propagates through the outbound request. Error bodies and logged reason codes are fixed and bounded rather than reflecting request payloads, credentials, or upstream diagnostics.

At most `MCP_GATEWAY_MAX_IN_FLIGHT` authenticated MCP requests can occupy the process concurrently. Excess work and new work after draining begins are rejected before upstream with generic `503` and `Retry-After: 1`; liveness remains available while readiness reports draining. Safe retries use an explicit allowlist (`ping`, `tools/list`, `resources/list`, `resources/read`, `prompts/list`, and `prompts/get`) and require a non-null JSON-RPC request ID. They apply only to EOF/unexpected-EOF or network errors classified as temporary/timeout, plus upstream `502`, `503`, and `504`; permanent TLS verification and other permanent transport failures are not retried. Attempts reuse the exact bounded body and end-to-end headers and remain inside the configured upstream timeout. `tools/call`, `initialize`, notifications, malformed requests, cancellations, deadlines, and all unlisted/future methods are never retried. Discarded retry responses are closed and never exposed or logged.

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
| `MCP_GATEWAY_MAX_IN_FLIGHT` | Required process-local concurrent MCP request cap (1–100,000). Excess work receives `503` before upstream. |
| `MCP_GATEWAY_MAX_SAFE_RETRIES` | Required integer retry count from 0 (disabled) through 3, applied only to the explicit safe-method rules above. |
| `MCP_GATEWAY_API_KEYS` | Required comma-separated `safe-client-id=sha256-hex` entries. IDs use 1–64 letters, digits, `.`, `_`, or `-`; IDs and hashes must be unique; at most 1,000 entries. |
| `MCP_GATEWAY_TOOL_POLICIES` | Optional comma-separated `client-id:tool=allow\|deny` entries. Client IDs must identify configured API keys; tool names use 1–128 letters, digits, `.`, `_`, or `-`; each client/tool pair is unique; at most 1,000 entries. Empty/unset means all `tools/call` requests are denied. |
| `MCP_GATEWAY_TOOL_RATE_LIMITS` | Comma-separated `client-id:tool=capacity/refill-interval` entries, one for every allow policy and none for deny/unknown pairs. Capacity is 1–100,000,000; interval is positive and at most five minutes; pairs are unique; at most 1,000 fixed buckets. Example: `local-demo:weather.lookup=10/1s`. |
| `MCP_GATEWAY_AUDIT_REDACT` | Optional comma-separated unique fields to replace with `[REDACTED]` before logging and hashing: `request_id`, `client_id`, and/or `tool`. Empty means safe configured metadata is retained. |

## Observability and safety

Logs are newline-delimited JSON emitted to stdout. Every handled `/mcp` request produces one `mcp audit event` after a request ID is available. Events contain the authenticated safe client ID (or empty for failed authentication), safe configured tool name when one was parsed, allow/deny decision, bounded result class and reason, HTTP status, latency, method/path, and correlation ID. Request and response payloads, tool arguments, presented credentials, authorization values, URL credentials, and upstream diagnostics are never logged. Optional metadata redaction happens before both output and hashing.

Audit events carry a process-local sequence, previous hash, and SHA-256 event hash. The hash covers the sequence, previous hash, emitted/redacted request ID, client ID, tool, decision, result class, method, path, reason, status, and latency using the canonical JSON field order implemented by `auditCanonical`. Event emission and chain mutation share one mutex, so concurrent requests cannot fork or reorder the chain. The first event after each process start uses 64 zeroes as its previous hash; chain state is intentionally not persisted, so restarts begin a new verifiable segment. Copy logs to append-only external storage if restart continuity or stronger deletion resistance is required. Chaining detects field modification and insertion/reordering within a retained segment; it does not prevent deletion of an entire tail or compromise of the running process.

Runtime rate-limit state has fixed startup-bounded cardinality: request-controlled client IDs or tool names never allocate buckets.

Use independently generated high-entropy API keys: plain SHA-256 digests do not protect weak, guessable secrets from offline guessing. Restrict access to the configuration environment because its hashes are authentication material. The quickstart supplies curl's credential header through standard input rather than exposing the raw key in curl's process arguments.

Readiness represents this process accepting work; it deliberately does not probe upstream health. Admission and rate limits are process-local, so multiple processes or replicas need an external host/fleet-wide concurrency budget and shared limiter. Rate limits reset on restart. The audit chain is process-local as described above. Body caps bound each admitted request/response; worst-case buffered body memory still scales with the configured admission cap.

## Architecture

```text
MCP client --HTTP JSON-RPC--> gateway handler --bounded HTTP client--> MCP upstream
                   |                |
                   |                +-- JSON structured logs (metadata only)
                   +-- /healthz, /readyz, admission, and X-Request-ID
```

The executable loads typed configuration, constructs a bounded `http.Server`, marks readiness draining on `SIGINT`/`SIGTERM`, and then uses a ten-second graceful-shutdown deadline. In-flight requests may finish during that window; new MCP work receives `503` until the listener closes.

## Verification

The standard deterministic gate is:

```bash
GOMAXPROCS=1 gofmt -w gateway internal cmd
GOMAXPROCS=1 go test -p=1 -count=1 ./...
GOMAXPROCS=1 go test -p=1 -race -count=1 ./...
GOMAXPROCS=1 go vet ./...
GOMAXPROCS=1 go build ./cmd/mcp-gateway
```

Two fuzz targets exercise exported HTTP behavior at the protocol/policy and authentication boundaries. Each fuzz input is capped at 4 KiB; use one worker and an explicit wall-time bound on constrained hosts:

```bash
GOMAXPROCS=1 go test -p=1 ./gateway -run '^(FuzzServeHTTPBoundaries|FuzzAuthenticationHeader)$' -count=1
GOMAXPROCS=1 go test -p=1 ./gateway -run '^$' -fuzz '^FuzzServeHTTPBoundaries$' -fuzztime=30s -parallel=1
GOMAXPROCS=1 go test -p=1 ./gateway -run '^$' -fuzz '^FuzzAuthenticationHeader$' -fuzztime=30s -parallel=1
```

On 2026-08-08, bounded five-second runs completed 6,738 protocol/policy executions (2 new interesting inputs) and 56,063 authentication executions without a failure. Fuzzing increases confidence but does not prove the absence of parser, authorization, or denial-of-service defects.

### Reproducible local load measurement

The benchmark sends permitted `tools/call` requests through the exported gateway handler to a loopback `httptest` upstream. It verifies every status but applies no timing threshold, so host noise changes measurements rather than causing a flaky test failure.

```bash
GOMAXPROCS=1 go test -p=1 ./gateway -run '^$' \
  -bench '^BenchmarkGatewayServeHTTP(Sequential|Parallel)$' \
  -benchtime=2000x -count=3 -cpu=1
```

Observed on 2026-08-08 with Linux 6.8, Go 1.26.5, one available vCPU (AMD EPYC 9354P host), and 3.8 GiB RAM:

| Path | Three-run mean range | Median run throughput | Sequential latency percentiles |
| --- | ---: | ---: | --- |
| Sequential | 63.6–66.3 µs/op | 15,604 requests/s | p50 53.4 µs, p95 88.8 µs, p99 228.9 µs |
| `RunParallel` constrained to one CPU | 62.0–62.8 µs/op | 16,022 requests/s | Not sampled |

These are local microbenchmark observations, not production capacity or an SLO. They exclude external network latency, TLS termination, a real upstream implementation, client socket handling, multi-process coordination, and durable audit storage. The gateway still buffers admitted request/response bodies; aggregate memory scales with configured body and in-flight caps. Admission, rate limits, and the audit chain are process-local and reset on restart. JSON-RPC batches remain unsupported. The standard-library-only module had no third-party dependencies to enumerate; `staticcheck`, `govulncheck`, `gosec`, and `gitleaks` were unavailable on the measurement host, so Go tests/race/vet, focused fuzzing, dependency inspection, targeted secret patterns, and independent review form the published gate.

## License

MIT — see [LICENSE](LICENSE).
