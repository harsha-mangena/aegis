# PR: MCP security engine + replay-safe approvals (Phase 2 + blocker #3)

Builds on the core-hardening PR. Adds the MCP security engine (the standalone hero feature) and fixes the broken human-approval loop with replay-safe, args-bound tokens. **29/29 tests pass; verified end-to-end** (rug-pull quarantined, poisoning blocked, approve→replay executes).

## New: MCP security engine (`mcp_guard.py`)

A deterministic, transport-agnostic security core that sits between an MCP client and downstream servers. It operates on tool *definitions* and *calls*, so it can back a stdio/HTTP proxy, an in-process client wrapper, or a gateway — the defensible logic is independent of the wire transport.

- **Tool-definition pinning** — each tool gets a SHA-256 fingerprint over `(name, description, input_schema)`. Pins are stored on first clean discovery.
- **Rug-pull detection (ASI04)** — re-discovery with a changed fingerprint quarantines the tool until a human calls `approve_change(...)`. Calls re-check the fingerprint at call time (drift defense).
- **Tool-poisoning scan (ASI04)** — deterministic static scan of the description and every nested schema `description`: instruction-override, concealment, exfiltration, coerced tool-use patterns, plus invisible/zero-width and format-control character smuggling. Findings carry severity; HIGH+ quarantines.
- **Shadowing/squatting detection (ASI07)** — cross-server name collisions and identical descriptions flag the later (untrusted) server; the trusted original stays callable.
- **Enforcement routing (ASI02/ASI01)** — every `guard_call` goes through `AgentRuntime`, so capability attenuation, the policy DSL, argument enforcement, provenance, and hash-chained audit all apply to MCP calls too. Unknown/unpinned tools are not callable (confused-deputy guard).
- **Capability mapping** — `deny_by_default_mapper` (unknown tool → custom cap @ HIGH severity → forces human approval) or `explicit_mapper({name: (caps, severity)})` for known tools.

```python
guard = MCPGuard(approval_store=store, capability_mapper=explicit_mapper({...}))
report = guard.register_server("filesystem", tool_defs, invoker)   # scans + pins
guard.guard_call("filesystem", "read_file", {"path": "a.txt"}, agent=agent)
```

## Fixed blocker #3: replay-safe approvals (`approval.py`)

The old approval queue replayed the request to a gateway that re-evaluated policy → `approval_required` again (infinite loop), and nothing bound the approval to the reviewed arguments (approve $10, replay $10,000).

- An approval is a **token bound to `(agent_id, tool_name, args_digest)`** + expiry + single-use nonce, **HMAC-signed** for integrity.
- `verify_and_consume` accepts only an approved, unexpired token whose args digest matches **exactly** (TOCTOU defense), and consumes it once (anti-replay).
- Runtime integration: on `REQUIRE_APPROVAL`, `invoke_tool` either (a) accepts a valid `approval_token=` and proceeds, (b) calls an inline `approval_handler`, or (c) issues a pending token and raises `ApprovalRequired(token_id=...)`. The FastAPI approvals service becomes a thin store over this same logic — no broken loop.

## Connect-the-dots (threat coverage added this session)
- MCP poisoning/rug-pull/shadowing → ASI04/ASI07 now covered deterministically.
- Approval tokens make the ASI09 human-in-the-loop control actually resumable and TOCTOU-safe.
- Provenance + DSL now reach MCP calls → ASI01/ASI02 extend to the MCP surface.

## Files
- `capguard/mcp_guard.py` (new)
- `capguard/approval.py` (new)
- `capguard/runtime.py` (approval-token integration)
- `capguard/core.py` (`ApprovalRequired.token_id`)
- `capguard/registry.py` (`unregister`, `has`)
- `capguard/__init__.py` (exports)
- `tests/test_mcp_and_approval.py` (new, 14 tests)

## Next (per roadmap)
- Thin MCP transport adapters (stdio/HTTP) wrapping this engine into a runnable proxy.
- Verifiable gateway identity (blocker #5) — kill self-asserted `agent_id`.
- Sandbox execution backends (Docker → microVM) for shell/code (ASI05).
- AgentDojo/ASB/InjecAgent benchmark harness in CI — publish ASR numbers.
