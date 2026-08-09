# Threat model

## Scope and assets

MCP Gateway protects one operator-selected HTTP MCP upstream from unauthorized or excessive client tool calls while preserving bounded protocol traffic. Assets include upstream availability, API-key material, policy integrity, request/response payload confidentiality, audit metadata integrity, and host resources.

## Trust assumptions

- Operators control the executable/container, environment, upstream URL, network policy, and log destination.
- API keys are independently generated high-entropy values delivered to clients out of band. Only SHA-256 digests are configured in the gateway.
- TLS authenticity depends on the runtime CA bundle and DNS/network environment. Termination and client-to-gateway TLS are deployment responsibilities.
- The configured upstream is trusted to process permitted payloads. The gateway is not a content firewall and does not validate tool arguments semantically.
- A compromised gateway process or host is outside the protection boundary.

## Threats and controls

| Threat | Control | Residual risk |
| --- | --- | --- |
| Stolen or guessed client key | Generic deny-by-default authentication; constant-time comparison across configured digests; credentials stripped before upstream and excluded from diagnostics | Plain SHA-256 permits offline guessing of weak keys; there is no key rotation protocol |
| Unauthorized tool invocation | Startup-validated per-client allow/deny policy; unknown pairs deny; ambiguous/malformed calls fail closed | Non-`tools/call` methods remain transparent by design |
| Request smuggling/header confusion | Go HTTP parser; hop-by-hop stripping; repeated/comma-joined gateway keys rejected; gateway owns the correlation ID sent upstream | Front-proxy normalization must be configured consistently |
| SSRF/redirect expansion | Fixed operator-configured absolute HTTP(S) upstream; no userinfo; redirects disabled | A malicious operator configuration or later DNS change can still target sensitive networks; use egress policy |
| Decompression or oversized-body denial of service | Automatic decompression disabled; strict request/response caps; response buffered before publication; process-local admission | Memory scales with cap × admitted work; streaming is not implemented |
| Tool-rate memory abuse | Token buckets are allocated only from bounded startup configuration | Limits are process-local and reset on restart |
| Retry amplification/duplicate side effects | Explicit read-method allowlist, non-null IDs, bounded attempts, one timeout budget; `tools/call` and initialize are never retried | A nominally safe upstream method could have non-idempotent server behavior |
| Payload/secret leakage in logs | Fixed bounded errors and reason codes; audit logs contain safe metadata only; optional metadata redaction before hashing | Client/tool IDs may still be sensitive unless redacted; stdout destination is operator-controlled |
| Audit modification | Canonical SHA-256 event chain with serialized sequence and previous hash | Process restart starts a new segment; tail deletion and host/process compromise are not prevented; export to append-only storage |
| Overload during shutdown | Readiness drains before bounded graceful shutdown; new MCP work receives `503` | In-flight work may be terminated after the deadline |
| Container breakout | Scratch image, numeric non-root user, no shell or embedded credentials | Containers are not a complete security boundary; deployment must drop capabilities, use read-only filesystems, limits, seccomp, and network policy |

## Explicit non-goals

The gateway does not provide TLS termination, mTLS, OAuth/OIDC, distributed rate limiting, durable audit storage, payload malware/prompt-injection scanning, schema validation for tool arguments, JSON-RPC batch support, upstream discovery, secret management, billing, or a complete hostile-code isolation boundary.

## Security verification

The deterministic gate includes unit/integration tests, race detection, vet, build, bounded protocol/auth fuzzing, targeted added-line secret and dangerous-code patterns, a real loopback demo, container smoke when Podman/Docker is available, and independent final-tree review. See [the README verification section](../README.md#verification) for exact commands and limitations.
