# Configuration reference

MCP Gateway reads configuration exclusively from environment variables and validates every value before opening the listener. Unknown environment variables are ignored by the process, so deployment manifests should still be reviewed for misspellings. Durations use Go syntax (`500ms`, `10s`, `1m`).

| Variable | Required | Valid values | Security/operational notes |
| --- | --- | --- | --- |
| `MCP_GATEWAY_UPSTREAM_URL` | Yes | Absolute `http` or `https` URL with a hostname | User information is rejected. Redirect following and automatic decompression are disabled. Apply egress policy against DNS rebinding/private destinations. |
| `MCP_GATEWAY_LISTEN_ADDRESS` | Yes | `host:port`, port 1–65535 | Use `127.0.0.1` for host-local use or `0.0.0.0:8080` in a network-isolated container. |
| `MCP_GATEWAY_UPSTREAM_TIMEOUT` | Yes | Positive duration ≤ 5m | One end-to-end budget shared by retry attempts. |
| `MCP_GATEWAY_READ_TIMEOUT` | Yes | Positive duration ≤ 5m | Covers request/header reads at the HTTP server. |
| `MCP_GATEWAY_WRITE_TIMEOUT` | Yes | Positive duration ≤ 5m | Must accommodate the intended upstream timeout and shutdown behavior. |
| `MCP_GATEWAY_IDLE_TIMEOUT` | Yes | Positive duration ≤ 5m | HTTP keep-alive idle timeout. |
| `MCP_GATEWAY_MAX_REQUEST_BYTES` | Yes | Integer 1–67,108,864 | Declared and chunked oversized bodies receive `413` before upstream. |
| `MCP_GATEWAY_MAX_RESPONSE_BYTES` | Yes | Integer 1–67,108,864 | Oversized upstream bodies are discarded and replaced by `502` without partial success. |
| `MCP_GATEWAY_MAX_IN_FLIGHT` | Yes | Integer 1–100,000 | Process-local authenticated MCP admission cap; excess requests receive `503` before body read/upstream. |
| `MCP_GATEWAY_MAX_SAFE_RETRIES` | Yes | Integer 0–3 | Applies only to the documented explicit safe-method allowlist; `0` disables retries. |
| `MCP_GATEWAY_API_KEYS` | Yes | Comma-separated `safe-id=64-char-sha256-hex`; 1–1,000 unique IDs and hashes | Safe IDs are 1–64 ASCII letters, digits, `.`, `_`, `-`. All-zero digests are rejected. Configure only high-entropy key digests. |
| `MCP_GATEWAY_TOOL_POLICIES` | No | Comma-separated `client-id:tool=allow\|deny`; ≤1,000 unique pairs | Client must exist in API keys. Tool is 1–128 ASCII letters, digits, `.`, `_`, `-`. Missing pairs deny. Empty denies every `tools/call`. |
| `MCP_GATEWAY_TOOL_RATE_LIMITS` | Conditional | Comma-separated `client-id:tool=capacity/refill`; ≤1,000 pairs | Exactly one entry for each allow policy and none for deny/unknown pairs. Capacity 1–100,000,000; refill interval positive ≤5m. Buckets start full and refill one token per interval. |
| `MCP_GATEWAY_AUDIT_REDACT` | No | Unique comma-separated subset of `request_id`, `client_id`, `tool` | Replaces selected metadata with `[REDACTED]` before output and event hashing. Empty preserves safe metadata. |

## Complete local example

```bash
export MCP_GATEWAY_UPSTREAM_URL=http://127.0.0.1:9000/mcp
export MCP_GATEWAY_LISTEN_ADDRESS=127.0.0.1:8080
export MCP_GATEWAY_UPSTREAM_TIMEOUT=5s
export MCP_GATEWAY_READ_TIMEOUT=5s
export MCP_GATEWAY_WRITE_TIMEOUT=8s
export MCP_GATEWAY_IDLE_TIMEOUT=30s
export MCP_GATEWAY_MAX_REQUEST_BYTES=1048576
export MCP_GATEWAY_MAX_RESPONSE_BYTES=1048576
export MCP_GATEWAY_MAX_IN_FLIGHT=16
export MCP_GATEWAY_MAX_SAFE_RETRIES=0
read -rsp 'Gateway key: ' MCP_CLIENT_KEY; echo
export MCP_GATEWAY_API_KEYS="local=$(printf %s "$MCP_CLIENT_KEY" | sha256sum | cut -d' ' -f1)"
export MCP_GATEWAY_TOOL_POLICIES='local:echo=allow'
export MCP_GATEWAY_TOOL_RATE_LIMITS='local:echo=10/1s'
export MCP_GATEWAY_AUDIT_REDACT='request_id'
go run ./cmd/mcp-gateway
```

Configuration values can contain authentication material (digests) and internal topology. Supply them with the deployment platform's secret/configuration mechanism; do not bake them into images or commit them to source.
