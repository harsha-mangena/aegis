# PR: Runnable MCP security proxy

Turns the tested `MCPGuard` engine into an actual MCP proxy a client (Claude Desktop, Cursor, any MCP client) can connect to. **39/39 tests pass**, including a **real subprocess stdio roundtrip** and a standalone-process smoke test.

## What it does
The proxy speaks MCP (JSON-RPC 2.0) to a client on one side and to one or more downstream MCP servers on the other. The MCP protocol is implemented directly — no heavy SDK dependency, transport-agnostic core, thin transports.

Two defenses at two points:
- **`tools/list` — poisoned/rug-pulled/shadowed tools are stripped before the client/model ever sees them.** The malicious description never enters the model's context, so it cannot inject via it. Prevention at the source, not just at call time.
- **`tools/call` — every call is routed through the enforcement runtime** (capability attenuation + policy DSL + provenance + approval + hash-chained audit). Blocked or approval-gated calls return an MCP tool error (`isError: true`) and never execute — fail closed.

## Components (`mcp_proxy.py`)
- JSON-RPC 2.0 helpers; MCP dispatch for `initialize`, `tools/list`, `tools/call`, `ping`, notifications.
- `InProcessDownstream` — tool defs + Python handlers (tests/demos).
- `StdioDownstream` — spawns a real subprocess MCP server, does the `initialize` handshake, and speaks newline-delimited JSON-RPC over its pipes.
- `MCPProxy` — wires a guard + agent identity + downstreams; `refresh()` re-discovers and re-scans downstream tools (catches rug pulls that happen after connect); exposes tools as `serverid__toolname`.
- `StdioServer` — the proxy as a connectable stdio MCP server.

## Verified
- In-process: initialize/list/call, allowed call executes, blocked call returns tool error.
- **Poisoned tool stripped** from `tools/list` (in-process and against the real subprocess server with `CAPGUARD_DEMO_POISON=1`).
- **Rug pull on `refresh()`**: a downstream that silently redefines a tool with a malicious description drops out of the exposed list.
- **Real subprocess roundtrip** via `examples/echo_mcp_server.py`.
- **Standalone process** (`examples/run_proxy.py`) driven by piped JSON-RPC: init → list (only clean tool) → call (executes) → unknown tool (fails closed).

## Run it
```bash
# drive the standalone proxy with raw JSON-RPC
printf '%s\n' \
 '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' \
 '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
 '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo__echo","arguments":{"msg":"hi"}}}' \
 | python examples/run_proxy.py
```
Client config (Claude Desktop / Cursor):
```json
{ "mcpServers": { "guarded-echo": { "command": "python", "args": ["examples/run_proxy.py"] } } }
```

## Connect-the-dots
- Stripping poisoned tools from `tools/list` is a stronger ASI04/ASI07 control than call-time blocking alone: it removes the attack from the model's context entirely.
- The proxy makes every prior layer (caps, DSL, provenance, approval, tamper-evident audit) apply to any MCP toolchain with zero changes to the agent or the downstream servers — drop-in adoption.

## Files
- `capguard/mcp_proxy.py` (new)
- `examples/echo_mcp_server.py` (new — real MCP stdio server)
- `examples/run_proxy.py` (new — launcher)
- `capguard/__init__.py` (exports)
- `tests/test_mcp_proxy.py` (new, 8 tests incl. live subprocess)

## Next (roadmap)
- Streamable-HTTP transport (remote MCP) alongside stdio.
- Per-tool/per-arg default provenance config + a provenance-propagating client shim.
- Verifiable agent identity at the proxy boundary (blocker #5).
- Sandbox execution backends for shell/code (ASI05).
- Live-LLM AgentDojo adapter feeding the benchmark harness.
