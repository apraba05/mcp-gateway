# MCP Gateway

MCP Gateway is a small, observable HTTP control point for Model Context Protocol JSON-RPC traffic. The Day 15 milestone provides a transparent upstream proxy, correlation IDs, typed startup configuration, a health endpoint, and payload-safe structured logs.

## Quickstart

Start any HTTP MCP server on `127.0.0.1:9000`, then run:

```bash
export MCP_GATEWAY_UPSTREAM_URL=http://127.0.0.1:9000/mcp
export MCP_GATEWAY_LISTEN_ADDRESS=127.0.0.1:8080
export MCP_GATEWAY_UPSTREAM_TIMEOUT=10s
export MCP_GATEWAY_READ_TIMEOUT=10s
export MCP_GATEWAY_WRITE_TIMEOUT=15s
export MCP_GATEWAY_IDLE_TIMEOUT=60s
go run ./cmd/mcp-gateway
```

Send an MCP JSON-RPC request:

```bash
curl -i http://127.0.0.1:8080/mcp \
  -H 'Content-Type: application/json' \
  -H 'X-Request-ID: demo-1' \
  --data '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

Check process health without contacting the upstream:

```bash
curl -i http://127.0.0.1:8080/healthz
```

## HTTP contract

| Endpoint | Method | Behavior |
| --- | --- | --- |
| `/mcp` | `POST` | Forwards the body and end-to-end MCP headers to the configured upstream, then preserves its status, end-to-end headers, and body. Hop-by-hop HTTP headers are removed. |
| `/healthz` | `GET` | Returns `200` and `{"status":"ok"}` when the gateway process is serving. |

A valid inbound `X-Request-ID` (`A-Z`, `a-z`, digits, `.`, `_`, or `-`; at most 128 characters) is preserved. Missing or unsafe IDs are replaced with a cryptographically random ID. The selected ID is sent upstream and returned to the client.

Other methods return `405`; unknown paths return `404`. Upstream transport failures produce a bounded generic `502` or `504` response rather than reflecting upstream error details.

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

## Observability and safety

Logs are newline-delimited JSON emitted to stdout. Request completion records contain the request ID, HTTP method, path, status, and latency. Request and response payloads, authorization values, and URL credentials are never logged.

The gateway currently exposes liveness rather than upstream readiness. Authentication, authorization, size caps, rate limiting, and audit chaining are planned later milestones; do not expose this Day 15 build directly to an untrusted network.

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
