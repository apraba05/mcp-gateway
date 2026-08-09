# Example MCP server and client

These standard-library-only programs support the reproducible local demo. They are intentionally small fixtures, not production MCP implementations.

- `mcpserver` binds only `127.0.0.1`, reports its selected address, and implements `ping`, `tools/list`, and the deterministic `echo` tool.
- `mcpclient` reads one JSON-RPC request from stdin and the gateway key from `MCP_CLIENT_KEY`. The key is not accepted on the command line and errors do not reflect it.

Run the complete exercised path from the repository root:

```bash
python3 scripts/demo.py
python3 scripts/demo.py --check
```

The first command builds all three real binaries in a temporary directory, starts loopback processes, calls `echo` through the gateway, checks the successful audit event, proves the fixture value is absent from client output and gateway logs, writes `docs/demo-output.md`, and cleans up. The second reruns the path and fails if the checked artifact is stale. Every subprocess and network operation has a deadline.
