# MCP Gateway Days 15–24 Retrospective

This document closes the approved MCP Gateway source backlog. It describes the
source on `main`; it is not a release announcement. No tag, GitHub release, hosted
deployment, or production SLO is implied.

## What shipped

| Day | Milestone | Result |
| --- | --- | --- |
| 15 | Observable proxy contract | Transparent bounded HTTP/JSON-RPC proxy, correlation IDs, health, typed configuration, structured logs, redirect and compression safeguards. |
| 16 | Bounded upstream transport | Request/response caps, cancellation, timeouts, deterministic bounded gateway errors, and no partial oversized responses. |
| 17 | API-key authentication | Startup-validated SHA-256 key digests, constant-time matching, safe client IDs, generic deny-by-default failures, and credential stripping. |
| 18 | Per-tool authorization | Startup-validated allow/deny policy, fail-closed duplicate-safe JSON parsing, and pre-upstream denial of unknown or denied tool calls. |
| 19 | Per-tool rate limiting | Fixed-cardinality, concurrency-safe per-client/per-tool buckets with deterministic refill and explicit bounded retry metadata. |
| 20 | Payload-safe audit logs | One bounded semantic audit event per handled MCP request, configurable metadata redaction, and process-local SHA-256 event chaining. |
| 21 | Reliability hardening | Readiness/draining semantics, process-local admission, graceful shutdown, and bounded retries restricted to an explicit safe-method allowlist. |
| 22 | Security and load verification | Input-capped fuzz targets, race testing, dependency inspection, and threshold-free one-vCPU microbenchmarks. |
| 23 | v0.1 source polish | Non-root shell-free container, real example client/server, deterministic demo, architecture, threat model, and configuration reference. |
| 24 | Final verification and wrap | Clean-clone verification, fixture-server timeout hardening, this retrospective, and draft-only technical/social content. |

The final source has no third-party Go module dependencies. The gateway path is
covered by unit, integration, race, fuzz-seed, demo, and container smoke tests.
Every published milestone received an independent final-tree review after its
latest code change.

## Verification record

The deterministic source gate is documented in the README and is designed for a
one-vCPU runner. Day 24 additionally verifies a fresh local clone of the final
commit rather than relying on build caches or untracked files from the working
copy. The closeout record includes:

- formatting and diff checks;
- uncached full and race-enabled Go suites;
- `go vet` and cold binary builds for the gateway and both examples;
- Python compilation/tests and byte-stable demo regeneration;
- local Markdown link and SVG parsing checks;
- standard-library-only dependency inspection and targeted secret/dangerous-code scans;
- an immutable-base Podman build plus a read-only, non-root container smoke;
- a fresh independent review of the exact staged tree.

Exact command output, the reviewed tree fingerprint, commit, and remote SHA are
recorded in the project delivery tracker and build journal. This avoids turning
transient host measurements into claims embedded permanently in source.

## Measured behavior, not promises

On 2026-08-08, three one-vCPU 2,000-request loopback handler runs observed:

- sequential: 63.6–66.3 µs/op, median-run 15,604 requests/s, p50 53.4 µs,
  p95 88.8 µs, and p99 228.9 µs;
- `RunParallel` constrained to one CPU: 62.0–62.8 µs/op, median-run 16,022
  requests/s.

These are reproducible local microbenchmarks, not production capacity, an SLO,
or a hosted-service result. They exclude real network/TLS latency, a production
upstream, socket-level client load, durable log shipping, and multi-replica
coordination.

## Security and reliability lessons

1. **Transparent proxies still need an explicit HTTP threat model.** Redirects,
   automatic decompression, hop-by-hop headers, correlation-ID conflicts, and
   partial responses can violate transparency or security even when JSON-RPC is
   forwarded unchanged.
2. **Preflight must be semantic and fail closed.** Authentication, policy, rate
   limits, retry eligibility, and constructor/configuration parity are checked
   before upstream work. Ambiguous credentials and duplicate JSON fields are
   rejected rather than guessed.
3. **Bounded diagnostics are part of the security boundary.** Payloads,
   credentials, tool arguments, and raw upstream errors are excluded from logs
   and client errors. Audit metadata is bounded before emission.
4. **Retries require a positive safety model.** Only six explicitly listed read
   methods with non-null IDs are eligible; tool calls, initialization,
   notifications, cancellations, malformed requests, and permanent TLS failures
   are not retried.
5. **A hash chain is not durable audit storage.** The chain detects retained
   segment modification/reordering, but it resets on restart and cannot prevent
   tail deletion or compromise of the running process.

## Known limitations and residual risks

- JSON-RPC batch arrays are not supported.
- Requests and responses are buffered; aggregate memory scales with body caps and
  the process-local in-flight limit.
- Admission, rate limits, and audit-chain state are process-local and reset on
  restart. Replicas need shared/fleet-wide controls and append-only external log
  storage.
- Readiness reports whether this process accepts work; it deliberately does not
  probe upstream health.
- SHA-256 digests do not make weak API keys resistant to offline guessing. Keys
  must be independently generated with high entropy, and configuration hashes
  remain authentication material.
- SSRF protection is configuration-time URL validation plus redirect refusal; it
  is not DNS/IP allowlisting or network-policy enforcement. Deployments should
  add egress controls appropriate to their environment.
- The example MCP server and demo are bounded development fixtures, not a
  production MCP server or hostile-code boundary.
- Microbenchmarks do not cover production networking, TLS termination, durable
  audit sinks, restarts, or multiple replicas.
- Fuzzing and race tests increase confidence but do not prove the absence of
  parser, authorization, concurrency, or denial-of-service defects.

## Scope boundary

The source milestone is suitable for evaluation and controlled deployment with
its documented assumptions. A production rollout would still require an
operator-owned threat model, network policy, secret distribution/rotation,
centralized rate/admission state where replicas are used, append-only audit
shipping, monitoring, and environment-specific load tests. Tags, releases,
hosting, and production deployment remain separate decisions.
