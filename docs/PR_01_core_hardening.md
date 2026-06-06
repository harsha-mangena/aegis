# PR: CapGuard core hardening — real enforcement, attenuation, DSL, tamper-evident audit

This replaces the v0.0.1 core. It fixes the three blocker defects from the strategy review and lands the Phase-1 enforcement core. All 15 new tests pass; verified end-to-end (shell injection blocked, audit chain valid on disk).

## What changed and why

### 1. `Policy.evaluate` no longer crashes; capabilities now *attenuate* (`core.py`)
The old `frozenset(c.params.items())` raised `TypeError` on any list-valued param (`allowlist`, `domains`, `paths`) and, even ignoring the crash, used exact-set equality — wrong semantics for least privilege. New model: a capability is an **attenuable grant**, and `Capability.covers(requested)` is a refinement check:
- `shell_exec`: requested commands ⊆ granted; requested timeout ≤ granted; `"*"` = wildcard.
- `network_http`: requested domains ⊆ granted; `"*"` = all; `.example.com` = subdomain match.
- `file_read/write`: each requested path-pattern must sit under a granted root.
- `db_query`: write authority covers read; read-only covers only read.

### 2. Capabilities are ENFORCED, not decorative (`core.py` + `runtime.py`)
The old `safe_shell` ran `subprocess.run(cmd, shell=True)` with the allow-list never checked — `rm -rf /` would run. Now `Capability.enforce(value)` validates the **concrete argument** before dispatch, using the agent's *granted* bound:
- shell: rejects shell metacharacters (`; | & < > ` $ \n`), then checks `argv[0]` against the allow-list.
- http: validates URL host against allowed domains.
- file: resolves realpath and checks containment (blocks `../` traversal).
- db: read-only grants reject non-read queries.

This runs as an independent layer (defense in depth) regardless of the policy gate.

### 3. Concurrency-safe runtime (`runtime.py`)
The old `CapabilityMiddleware` mutated `runtime._agent` under try/finally — unsafe under FastAPI's threadpool (identity bleed across requests). The runtime is now stateless w.r.t. identity; identity flows through an immutable `CallContext`. Proven by a 100-call concurrent test with two disjoint agents (no leak).

### 4. Tamper-evident audit (`audit.py`)
Replaces plain-append JSONL (which the README wrongly called "tamper-proof") with a SHA-256 **hash chain** (`prev_hash` + canonical body → `hash`). `verify_chain` / `verify_file` detect any retroactive edit. Raw payloads are never logged — only digests. Thread-safe sinks: `HashChainedSink` (disk), `MemorySink`, `PrintSink`.

### 5. Programmable, argument-level policy DSL (`policy_dsl.py`) — NEW
Progent/AgentSpec-inspired `trigger → predicate → effect`. Restrict by specific tool call AND use case:
```python
engine = PolicyEngine().add(
    Rule(name="big-transfers", trigger=tool_is("transfer"),
         when=Arg("amount") > 1000, effect=Effect.REQUIRE_APPROVAL)
)
```
Effects: `ALLOW | DENY | REQUIRE_APPROVAL | RATE_LIMIT` (rate overflow escalates to deny). Deny-overrides precedence: a rule can only tighten the baseline gate. Fluent builders: `Arg(...)`, `Provenance(...)`, `AND/OR/NOT`, `role_in`, `tool_is`.

### 6. Data-provenance predicates (`policy_dsl.py`) — NEW (CaMeL-style)
Tag tool I/O with trust labels; block untrusted data flowing into a sink:
```python
Rule(name="trusted-recipient-only", trigger=tool_is("send_email"),
     when=(Provenance("to") != "trusted"), effect=Effect.DENY)
```
This is the deterministic indirect-prompt-injection defense (an injected recipient is `untrusted_web` → blocked). Partial taint model (tool-boundary tagging) — full propagation is a later phase.

## Pipeline (every `invoke_tool`)
1. baseline capability gate (attenuation + severity)
2. policy DSL (argument/use-case/rate/provenance)
3. capability argument enforcement ← teeth
4. dispatch
5. hash-chained audit at every exit

## Not in this PR (next, per roadmap)
- Approval **replay** fix (blocker #3) + verifiable gateway identity (#5) — gateway/approvals rework.
- MCP proxy + tool-definition pinning (Phase 2, biggest market lever).
- Sandbox execution backends (Docker → microVM) for shell/code.
- AgentDojo/ASB/InjecAgent benchmark harness in CI.

## Files
- `capguard/core.py` (rewritten)
- `capguard/runtime.py` (rewritten)
- `capguard/audit.py` (rewritten)
- `capguard/registry.py` (updated)
- `capguard/policy_dsl.py` (new)
- `capguard/__init__.py` (updated exports)
- `tests/test_capguard.py` (new, 15 tests)
