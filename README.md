# MCP Gateway

MCP Gateway is a small, observable HTTP control point for Model Context Protocol JSON-RPC traffic. The Day 17 milestone adds deny-by-default hashed API-key authentication and safe client identifiers to the bounded transparent proxy, correlation IDs, typed startup configuration, health endpoint, and payload-safe structured logs.

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
| `/mcp` | `POST` | Requires a valid `X-MCP-Gateway-Key`, then forwards the body and end-to-end MCP headers to the configured upstream and preserves its response. The gateway credential and hop-by-hop HTTP headers are removed. |
| `/healthz` | `GET` | Returns `200` and `{"status":"ok"}` without a client credential when the gateway process is serving. |

A valid inbound `X-Request-ID` (`A-Z`, `a-z`, digits, `.`, `_`, or `-`; at most 128 characters) is preserved. Missing or unsafe IDs are replaced with a cryptographically random ID. The selected ID is sent upstream and returned to the client.

Missing, invalid, empty, whitespace-only, ambiguous repeated/comma-joined, and over-256-byte gateway keys return a generic `401` without an upstream call. Other methods return `405`; unknown paths return `404`. Requests above the configured cap are rejected with `413` before an upstream call. Responses above their cap are fully discarded and replaced with `502`, so partial upstream success is never published. Hung upstreams map to `504`; malformed upstream HTTP and other transport failures map to `502`. Client cancellation propagates through the outbound request. Error bodies and logged reason codes are fixed and bounded rather than reflecting request payloads, credentials, or upstream diagnostics.

## Configuration

Every setting is required and validated before the listener starts. Durations use Go syntax such as `500ms`, `10s`, or `1m` and must be positive and no greater than five minutes.

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

## Observability and safety

Logs are newline-delimited JSON emitted to stdout. Successful request completion records contain the safe client ID, request ID, HTTP method, path, status, and latency. Authentication failures use a fixed reason and never log the presented credential. Request and response payloads, authorization values, gateway keys, and URL credentials are never logged.

Use independently generated high-entropy API keys: plain SHA-256 digests do not protect weak, guessable secrets from offline guessing. Restrict access to the configuration environment because its hashes are authentication material. The quickstart supplies curl's credential header through standard input rather than exposing the raw key in curl's process arguments.

The gateway currently exposes liveness rather than upstream readiness. Per-tool authorization, rate limiting, and audit chaining are planned later milestones. Body caps bound per-request buffering, but a later concurrency milestone will add aggregate admission control.

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
