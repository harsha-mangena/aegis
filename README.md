# CapGuard — the deterministic security runtime for AI agents

> Least privilege for AI agents, **enforced**. A non-bypassable layer that sits inline on every tool call and every MCP message.

CapGuard is an embeddable Python SDK that makes any agent stack (LangGraph, CrewAI, AutoGen, OpenAI Agents, custom loops, or raw MCP) safe by default. It is **not** a prompt classifier and **not** a guardrail that tries to guess intent. It is a deterministic enforcement runtime: it decides — from capabilities, policy, and data provenance — whether a concrete tool call is allowed, denied, or needs human approval, and it backs that decision with hard isolation and a tamper-evident audit trail.

**Status:** active development. Core is implemented and tested. **50 tests passing**; deterministic security benchmark at **0% attack-success rate / 100% utility / ~0.03 ms per-call overhead**.

```bash
pip install -e .        # or: poetry install
PYTHONPATH=. pytest -q  # 50 passed
PYTHONPATH=. python -m capguard.bench.run_bench   # prints the security benchmark table
```

---

## Why CapGuard

The 2026 **OWASP Top 10 for Agentic Applications** (ASI01–ASI10) makes clear that the dangerous moments in an agent's life are at the **action boundary**: which tool runs, with which arguments, on whose authority, fed by which data. Prompt filters and classifiers operate *around* the model and are probabilistic — they can be talked past. Generic authorization engines (Permit, Oso, Cedar) decide policy but don't sit on the agent runtime, don't track data provenance, and don't secure MCP.

CapGuard fills that gap. It is the deterministic backstop: even when a model is fooled into *attempting* a malicious call, CapGuard blocks it because the call violates capability, policy, or provenance — not because a classifier flagged it.

---

## What it does

| Layer | Module | What it gives you |
|-------|--------|-------------------|
| **Attenuable capabilities** | `core` | Capabilities are grants that can only be *narrowed*. An agent holding `network_http(domains=[a,b])` cannot reach `c`; `shell_exec(allowlist=[ls])` cannot run `rm`. Authorization is a subset/refinement check, never an expansion. |
| **Real argument enforcement** | `core`, `runtime` | The capability is enforced against the **actual** call value before dispatch: shell metacharacters and non-allow-listed commands are rejected, URLs checked against allowed domains, file paths resolved and contained (defeats `../`), read-only DB grants reject writes. |
| **Programmable policy DSL** | `policy_dsl` | Restrict by specific tool **and** use case: `Arg("amount") > 1000 → REQUIRE_APPROVAL`, rate limits, role checks. Deny-overrides precedence — a rule can only tighten. |
| **Data provenance** | `policy_dsl`, `runtime` | Tag tool I/O with trust labels and block untrusted data flowing into a sink: `Provenance("recipient") != "trusted" → DENY`. A deterministic defense against indirect prompt injection (CaMeL-style). |
| **Replay-safe approvals** | `approval` | Human-in-the-loop tokens bound to `(agent, tool, exact-args)`, HMAC-signed, single-use. Approving a $10 transfer cannot be replayed as $10,000 (TOCTOU defense). |
| **Tamper-evident audit** | `audit` | Every decision is hash-chained (`prev_hash` + event → `hash`); any retroactive edit breaks the chain. Logs digests, not raw payloads. |
| **MCP security engine** | `mcp_guard` | Pins tool definitions by fingerprint, detects **rug pulls** (changed defs), **shadowing** (cross-server name/description collisions), and **tool poisoning** (instruction-override / concealment / exfiltration / zero-width smuggling in descriptions). |
| **Runnable MCP proxy** | `mcp_proxy` | A JSON-RPC proxy any MCP client connects to. Poisoned/rug-pulled/shadowed tools are **stripped from `tools/list`** so the malicious description never reaches the model; every `tools/call` is enforced and audited. |
| **Sandboxed execution** | `sandbox` | Execution backends with isolation tiers: hardened `SubprocessBackend` (POSIX rlimits, no-shell, env scrub, timeout-kill), ephemeral `DockerBackend` (`--network none`, read-only, caps dropped), and `DenyBackend`. |
| **Benchmark harness** | `bench` | Deterministic AgentDojo-structured suite measuring ASR / utility / latency, wired as a CI gate. |

---

## The pipeline (every tool call)

```
invoke_tool(name, agent=…, provenance=…, approval_token=…, **args)
  1. capability gate      — agent must hold a capability that covers the tool's need
  2. policy DSL           — argument / use-case / rate / provenance rules (deny-overrides)
  3. argument enforcement — the concrete value is checked against the granted bound  ← the teeth
  4. dispatch             — via the configured execution backend
  5. audit                — hash-chained event at every exit
```

Identity flows through an immutable per-call context, so concurrent calls cannot bleed permissions into one another.

---

## 60-second example

```python
from capguard import (
    AgentIdentity, AgentRuntime, Capability, Policy, Severity, ToolRegistry,
    PolicyEngine, Rule, Arg, tool_is, Effect,
)
from capguard.audit import HashChainedSink

reg = ToolRegistry()

@reg.tool(capabilities=[Capability.custom("transfer")], severity=Severity.LOW)
def transfer(amount: int, recipient: str) -> str:
    return f"sent {amount} to {recipient}"

# Restrict by use case: large transfers need a human; untrusted recipients are denied.
engine = (PolicyEngine()
    .add(Rule("limit", trigger=tool_is("transfer"), when=Arg("amount") > 1000,
              effect=Effect.REQUIRE_APPROVAL))
)

agent = AgentIdentity(id="fin-bot", allowed_capabilities=[Capability.custom("transfer")])
rt = AgentRuntime(registry=reg, engine=engine, audit_sink=HashChainedSink("audit.jsonl"),
                  default_agent=agent)

rt.invoke_tool("transfer", amount=100, recipient="alice")    # ok
rt.invoke_tool("transfer", amount=9999, recipient="alice")   # ApprovalRequired
```

Guard a real MCP server in front of any client:

```bash
python examples/run_proxy.py     # stdio MCP proxy; point Claude Desktop / Cursor at it
```

---

## Security benchmark

One general policy profile, 13 attacks across 7 domains (banking, email, web, files, shell, messaging, destructive ops):

```
metric                 baseline   CapGuard
attack success rate     100.0%      0.0%
benign utility          100.0%    100.0%
overhead / call          —       ~0.03 ms
```

CapGuard measures **deterministic enforcement** — does it block the malicious call when attempted — not LLM susceptibility. It composes underneath classifier defenses (LlamaFirewall, CaMeL) as the non-bypassable layer. See [`docs/BENCHMARK_RESULTS.md`](docs/BENCHMARK_RESULTS.md).

---

## OWASP ASI 2026 coverage

| Risk | Status | Mechanism |
|------|--------|-----------|
| ASI01 Goal/behavior hijack | ◑ | provenance predicates |
| ASI02 Tool misuse | ✓ | attenuation + argument-level DSL |
| ASI03 Identity & privilege abuse | ◑ | attenuation, JIT grants (verifiable identity on roadmap) |
| ASI04 Agentic supply chain | ✓ | signed plugins, MCP pinning, poisoning scan |
| ASI05 Unexpected code execution | ✓ | sandbox backends |
| ASI06 Memory/context poisoning | ◑ | provenance on writes |
| ASI07 Insecure inter-agent comms | ✓ | shadowing detection + list-strip |
| ASI08 Cascading failures | ✓ | rate limits, resource caps, blast-radius |
| ASI09 Human-agent trust | ✓ | replay-safe approvals |
| ASI10 Rogue agents | ✗ | sequence anomaly detection (roadmap) |

✓ covered · ◑ partial · ✗ planned. See [`ROADMAP.md`](ROADMAP.md).

---

## Repository layout

```
capguard/
  core.py          capabilities, attenuation, argument enforcement, policy, severity
  registry.py      tool registry (decorator API)
  runtime.py       enforcement pipeline (stateless, concurrency-safe)
  policy_dsl.py    trigger → predicate → effect rules; Arg/Provenance builders
  audit.py         hash-chained tamper-evident audit + sinks
  approval.py      replay-safe, args-bound approval tokens
  mcp_guard.py     MCP pinning, rug-pull / shadowing / poisoning detection
  mcp_proxy.py     runnable JSON-RPC MCP proxy (stdio) + downstream clients
  sandbox.py       execution backends (subprocess / docker / deny) + tool factories
  bench/           deterministic security benchmark + CI gate
tests/             50 tests
examples/          runnable MCP server + guarded proxy launcher
docs/              strategy memo, per-PR notes, benchmark results
```

---

## Documents

- [`docs/STRATEGY.md`](docs/STRATEGY.md) — market analysis, research grounding (CaMeL, Progent, AgentSpec, MCP-Guard), positioning and moat.
- [`docs/BENCHMARK_RESULTS.md`](docs/BENCHMARK_RESULTS.md) — methodology and numbers.
- [`docs/PR_01..04`](docs/) — change notes for each build phase.
- [`ROADMAP.md`](ROADMAP.md) — what's next.

## License

Apache 2.0 (core library, plugin spec, adapters). Hosted control plane / advanced policy packs may be licensed separately later.
