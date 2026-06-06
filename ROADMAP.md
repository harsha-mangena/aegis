# CapGuard Roadmap

This is the forward plan. It builds on the shipped core (capabilities, policy DSL, provenance, approvals, MCP guard + proxy, sandbox, benchmark). Items are ordered by leverage; each is independently shippable.

Legend: ✅ done · 🔜 next · 🔭 later · status against the 2026 OWASP Top 10 for Agentic Applications (ASIxx).

---

## Shipped

- ✅ **Attenuable capability model** with real argument enforcement (shell/http/file/db). *(ASI02, ASI03)*
- ✅ **Stateless, concurrency-safe runtime** pipeline. *(correctness)*
- ✅ **Programmable policy DSL** — trigger → predicate → effect, argument-level, rate limits, deny-overrides. *(ASI01, ASI02)*
- ✅ **Data-provenance predicates** — deterministic indirect-prompt-injection defense. *(ASI01, ASI06)*
- ✅ **Replay-safe approval tokens** — args-bound, HMAC-signed, single-use. *(ASI09)*
- ✅ **Tamper-evident hash-chained audit.** *(ASI10 evidence)*
- ✅ **MCP security engine** — pinning, rug-pull, shadowing, tool-poisoning scan. *(ASI04, ASI07)*
- ✅ **Runnable MCP proxy** — strips poisoned tools from `tools/list`, enforces every call. *(ASI04, ASI07)*
- ✅ **Sandboxed execution backends** — subprocess (rlimits) / docker / deny. *(ASI05, ASI08)*
- ✅ **Deterministic security benchmark** — ASR/utility/latency, CI gate.

---

## 🔜 Next (target: v0.1)

### 1. Verifiable agent identity *(ASI03 — the last "trust me" hole)*
Today `agent_id` is self-asserted at the proxy/gateway boundary. Plan:
- Signed identity assertions (Ed25519, reuse the plugin-signing keys) binding an agent to a **human principal + tenant**.
- Verification at the proxy/gateway boundary; reject unsigned or mismatched identities.
- **Zero standing permissions** + just-in-time capability grants (the `ephemeral` grant path becomes the norm).
- Map to the OWASP Non-Human-Identity Top 10.

### 2. Live-LLM AgentDojo adapter
- Wire the real AgentDojo (and ASB / InjecAgent) into the benchmark harness behind the existing `Scenario` interface.
- Publish end-to-end ASR with CapGuard as the enforcement layer, alongside the deterministic numbers.
- Goal: a reproducible, citable comparison vs Progent / CaMeL / LlamaFirewall.

### 3. Streamable-HTTP MCP transport
- Add the remote MCP transport (Streamable HTTP / SSE) next to stdio, so the proxy guards hosted MCP servers, not just local subprocesses.
- Per-tool / per-arg default provenance config; a provenance-propagating client shim.

### 4. Policy-pack compiler
- Translate the existing YAML policy packs (OWASP baseline, finance, healthcare) directly into `PolicyEngine` rules + capability templates, so a pack is a one-line import.
- Ship more packs (data-exfiltration baseline, coding-agent baseline, browser-agent baseline).

### 5. Packaging & docs
- Finalize `pyproject` (console scripts: `capguard-proxy`, `capguard-bench`), CI workflow (lint + test + benchmark gate), publish to PyPI.
- Quickstart + recipe docs per framework (LangGraph, CrewAI, OpenAI Agents, raw MCP).

---

## 🔭 Later

### Stronger isolation
- gVisor (`runtime=runsc`) and Firecracker/microVM execution backends for hostile code at scale.
- eBPF-based egress and filesystem enforcement for the subprocess tier (true network isolation without a container).

### Rogue-agent detection *(ASI10)*
- Sequence-level anomaly detection over the hash-chained audit stream: unusual tool-call sequences, privilege drift, blast-radius breaches → alert + kill switch.
- Per-agent/session budgets and circuit breakers feeding back into the DSL.

### Full provenance / taint
- Move from tool-boundary tagging to propagation across tool I/O (toward CaMeL-style soundness), while keeping it a library hook, not a forked interpreter.
- Optional advisory detectors (PromptGuard2 / AlignmentCheck) as predicates — deterministic-first, probabilistic-assist.

### Framework adapters (first-class)
- LangGraph node/tool wrappers, CrewAI tool wrapper, OpenAI Agents SDK tool shim, LlamaIndex — each routing through the runtime with zero ceremony.
- A Cedar/OPA predicate backend so teams can bring their existing policy engine and use CapGuard purely as the enforcement point.

### Inter-agent (A2A) security *(ASI07)*
- Signed inter-agent messages, identity propagation across hops, and capability attenuation along delegation chains.

### Control plane (commercial)
- Hosted multi-tenant policy management, central tamper-evident audit, dashboards, and replay/digital-twin testing for cascading-failure analysis.

---

## Guiding principles

1. **Deterministic-first.** Enforcement never depends on a model guessing intent; classifiers are optional advisory inputs, never the gate.
2. **Least privilege by construction.** Capabilities only narrow; unknown is denied or escalated.
3. **Composability over lock-in.** Bring your framework, your policy engine, your classifier — CapGuard is the enforcement point underneath.
4. **Prove it.** Every security claim has a test and a benchmark number; security regressions fail CI.
