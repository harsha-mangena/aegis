<![CDATA[<p align="center">
  <img src="docs/logo-animated.svg" width="280" alt="Aegisguard logo" />
</p>

# Aegisguard

**Deterministic security runtime for AI agents. One decorator. Any framework. Full enforcement.**

[![PyPI](https://img.shields.io/pypi/v/aegisguard.svg)](https://pypi.org/project/aegisguard/)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://pypi.org/project/aegisguard/)
[![Tests](https://img.shields.io/badge/tests-298%20passed-brightgreen.svg)](#)
[![OWASP](https://img.shields.io/badge/OWASP%20ASI--2026-10%2F10%20covered-brightgreen.svg)](#owasp-asi-2026-coverage)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![ASR](https://img.shields.io/badge/attack%20success%20rate-0%25-brightgreen.svg)](#benchmark)

```bash
pip install aegisguard
```

```python
from aegis import guard

@guard(network=["api.openai.com"])
def call_llm(url: str) -> str:
    return requests.get(url).text    # only api.openai.com allowed — everything else blocked

@guard(shell=["ls", "cat"])
def run_cmd(cmd: str) -> str:
    return subprocess.check_output(cmd).decode()  # rm, curl, semicolons — all blocked

@guard(file_read="/data")
def read_doc(path: str) -> str:
    return open(path).read()         # /etc/passwd, ../../ traversal — blocked
```

That's the entire API. Three lines of security for each tool. Works with OpenAI, LangChain, CrewAI, RAG pipelines, voice agents, MCP servers — anything callable.

---

## What is Aegisguard?

Aegisguard is a **deterministic enforcement runtime** that sits inline on every AI agent tool call. It doesn't guess intent with prompts or classifiers — it enforces **hard capability boundaries** on what tools can actually do.

When a model is tricked into calling `rm -rf /`, Aegisguard blocks it — not because a classifier flagged it, but because the shell capability only allows `["ls", "cat"]`. When a prompt injection tries to exfiltrate data to `evil.com`, it's blocked because the network capability only permits `["api.openai.com"]`. No probability. No bypass. Deterministic.

**What it is not:** a prompt filter, a guardrail that wraps the LLM, or a classifier. Those are probabilistic and can be talked past. Aegisguard is the non-bypassable backstop underneath.

---

## 30-Second Quickstart

### Zero-config (module-level)

```python
from aegis import guard

@guard(network=True)
def search(query: str) -> str:
    return requests.get(f"https://api.example.com?q={query}").text

search("AI safety")  # works
```

### Configured (with policy pack + audit)

```python
from aegis import Aegis

ag = Aegis(
    pack="owasp-baseline",        # OWASP ASI-2026 security profile
    audit="audit.jsonl",          # tamper-evident hash-chained log
    agent_id="research-bot",
)

@ag.guard(network=["api.openai.com"], source="web")
def call_llm(url: str) -> str: ...

@ag.guard(shell=["ls", "cat", "grep"])
def run_cmd(cmd: str) -> str: ...

@ag.guard(file_read="/data/reports")
def read_report(path: str) -> str: ...

@ag.guard(custom="send_email", risk="high")   # requires human approval
def send_email(to: str, body: str) -> str: ...
```

### With OpenAI Agents

```python
from openai import OpenAI
from aegis import Aegis

client = OpenAI()
ag = Aegis(pack="owasp-baseline")

@ag.guard(network=["api.openai.com"])
def search(url: str) -> str:
    return requests.get(url).text

# Use search() as a tool in your OpenAI function-calling agent.
# Aegisguard enforces capabilities on every call the LLM makes.
result = search("https://api.openai.com/v1/models")  # allowed
result = search("https://evil.com/steal")             # BLOCKED
```

---

## What Gets Enforced

Every `@guard()` call passes through a defense-in-depth pipeline before the function body executes:

```
@guard(shell=["ls", "cat"])
def run(cmd): ...

run("ls -la")           → allowed
run("rm -rf /")          → BLOCKED: 'rm' not in allowlist
run("ls; curl evil.com") → BLOCKED: shell metacharacters
run("ls `cat /etc/shadow`") → BLOCKED: shell metacharacters
```

| Capability | What's enforced | Examples |
|---|---|---|
| `network=["domain"]` | URL domain whitelist | `evil.com` blocked, subdomain spoofing blocked |
| `network=True` | Any domain (unrestricted) | All URLs allowed |
| `file_read="/data"` | Path containment | `/etc/passwd` blocked, `../../` traversal blocked |
| `shell=["ls","cat"]` | Command allowlist + metachar rejection | `rm` blocked, `;` `\|` `` ` `` `$()` `&&` all blocked |
| `db=True` | Read-only SQL only | `SELECT` allowed, `DROP`/`DELETE`/`INSERT` blocked |
| `db_write=True` | Read + write SQL | Everything allowed |
| `risk="high"` | Requires human approval | Blocks unless approval token provided |
| `source="web"` | Taints output as untrusted | Provenance tracks through downstream calls |

### Beyond argument enforcement

Aegisguard's engine runs a full pipeline on every call:

```
Circuit breaker → Budget gate → Task scope → Capability check →
Advisory detectors → Policy DSL (deny-overrides) → Argument enforcement →
Dispatch → Provenance propagation → Hash-chained audit
```

---

## Key Features

### Capability-Based Security
Capabilities are grants that can only narrow, never expand. An agent holding `network_http(domains=["a.com"])` cannot reach `b.com`. A delegated sub-agent can only have fewer permissions than its parent.

### Policy DSL
Programmable rules beyond capabilities — restrict by argument value, rate-limit, require approval above a threshold:

```python
# In a policy pack: deny transfers above $1000 without approval
Rule: Arg("amount") > 1000 → REQUIRE_APPROVAL
```

### Data Provenance
A trust/confidentiality label lattice propagated across tool I/O. Data pulled from an untrusted web source stays tainted even if laundered through multiple tool calls. Deterministic indirect-prompt-injection defense.

### MCP Security
Pins tool definitions by fingerprint. Detects rug pulls (changed definitions), shadowing (cross-server collisions), and tool poisoning (instruction-override, exfiltration, zero-width smuggling in descriptions). Poisoned tools are stripped from `tools/list` before the model sees them.

### Tamper-Evident Audit
Every decision is hash-chained (`prev_hash + event → hash`). Any retroactive edit breaks the chain. The forensic flow reconstructor rebuilds data-flow graphs from the audit log for incident response.

### Sandboxed Execution
Configurable backends: hardened subprocess (POSIX rlimits, no-shell, env scrub), ephemeral Docker (`--network none`, read-only, caps dropped), or deny-all.

### Rogue Agent Detection
Deterministic sliding-window anomaly detection over the audit stream — call-rate spikes, denial-rate probing, blast-radius expansion, novel-tool usage — trips a per-agent circuit breaker that fail-closes the agent.

### 6 Built-in Policy Packs

| Pack | Use case |
|---|---|
| `owasp-baseline` | General OWASP ASI-2026 coverage |
| `finance` | Financial agents, transfer limits |
| `data-exfil` | Block data exfiltration patterns |
| `healthcare` | HIPAA-aware constraints |
| `coding-agent` | Safe code execution |
| `browser-agent` | Browser automation guardrails |

---

## Benchmark

One general policy profile, 15 attacks across 7 domains (banking, email, web, files, shell, messaging, destructive ops), including laundering attacks blocked only by propagated provenance:

```
Metric                  No Guard    Aegisguard
────────────────────────────────────────────────
Attack success rate      100.0%        0.0%
Benign utility           100.0%      100.0%
Overhead per call          —         ~0.04 ms
```

**AgentDojo** (97 user + 35 injection tasks, deterministic ground-truth replay):

```
Suite         User  Inj   Utility    ASR
──────────────────────────────────────────
banking         16    9   100.0%    0.0%
slack           21    5   100.0%    0.0%
travel          20    7   100.0%    0.0%
workspace       40   14   100.0%    0.0%
TOTAL           97   35   100.0%    0.0%
```

Aegisguard measures deterministic enforcement — does it block the malicious call when attempted — not LLM susceptibility. It composes underneath probabilistic defenses (LlamaFirewall, PromptGuard, CaMeL) as the non-bypassable layer.

---

## OWASP ASI-2026 Coverage

All 10 risks covered with deterministic shipped mechanisms:

| Risk | Description | Mechanism |
|---|---|---|
| ASI01 | Goal/behavior hijack | Propagated provenance + advisory detectors |
| ASI02 | Tool misuse | Attenuation + argument enforcement + task-scoped envelopes |
| ASI03 | Identity & privilege abuse | Signed identity (HMAC/Ed25519), delegation-only-attenuates |
| ASI04 | Agentic supply chain | MCP pinning, poisoning scan, signed plugins |
| ASI05 | Unexpected code execution | Sandbox backends (subprocess/docker/deny) |
| ASI06 | Memory/context poisoning | Provenance-preserving memory (taint survives write→read) |
| ASI07 | Insecure inter-agent comms | Signed A2A messages + per-message capability attenuation |
| ASI08 | Cascading failures | Call/token/$ budgets + circuit-breaker kill switch |
| ASI09 | Human-agent trust | Replay-safe approval tokens (args-bound, single-use) |
| ASI10 | Rogue agents | Sequence-anomaly detection → circuit breaker |

---

## Local Testing

```bash
git clone https://github.com/harsha-mangena/capguard.git
cd capguard
python3 -m venv .venv && source .venv/bin/activate
pip install -e .

# Validate enforcement engine (no API key needed) — 40 tests
python examples/demo_local_no_api.py

# With OpenAI (requires OPENAI_API_KEY)
pip install openai
python examples/demo_with_aegis.py       # protected agent
python examples/demo_comparison.py       # side-by-side: unprotected vs protected

# Full test suite
pip install -e ".[dev,yaml]"
pytest -q                                # 298 tests
```

---

## Architecture

```
aegis/                     # PUBLIC API — what you import
  __init__.py              #   from aegis import guard, Aegis, configure
  core.py                  #   Aegis class, @guard decorator, module-level API

capguard/                  # INTERNAL ENGINE (27 modules, 6800+ LOC)
  core.py                  #   capabilities, attenuation, argument enforcement
  runtime.py               #   defense-in-depth pipeline (stateless, concurrency-safe)
  policy_dsl.py            #   programmable rules (deny-overrides)
  provenance.py            #   trust×confidentiality label lattice
  identity.py              #   signed identity + delegation attenuation
  a2a.py                   #   signed inter-agent messages
  mcp_guard.py             #   MCP pinning, rug-pull, shadowing, poisoning scan
  mcp_proxy.py             #   JSON-RPC MCP proxy (stdio + HTTP)
  mcp_auth.py              #   OAuth 2.1 resource-server auth
  monitor.py               #   anomaly detection + circuit breaker
  budget.py                #   call/token/$ budgets
  memory.py                #   provenance-preserving memory/RAG
  audit.py                 #   hash-chained tamper-evident audit
  audit_graph.py           #   forensic data-flow reconstruction
  sandbox.py               #   execution backends (subprocess/docker/deny)
  packs.py                 #   policy-pack compiler + 6 builtin packs
  ...                      #   + approval, adapters, detectors, taskscope, etc.
```

---

## How It Compares

| Feature | Aegisguard | Guardrails AI | LlamaGuard | Varden | AgentSeal |
|---|---|---|---|---|---|
| Enforcement method | Deterministic capability | Prompt validation | LLM classifier | Policy rules | Probe scanning |
| Argument-level blocking | Yes | No | No | Partial | No |
| Shell injection prevention | Yes (metachar + allowlist) | No | No | No | No |
| Path traversal prevention | Yes (realpath containment) | No | No | No | No |
| Data provenance tracking | Yes (lattice propagation) | No | No | No | No |
| MCP security (poisoning/rug-pull) | Yes | No | No | No | Yes (scan only) |
| Tamper-evident audit | Yes (hash-chained) | No | No | No | No |
| Framework agnostic | Yes (any callable) | Partial | LLM-only | Partial | LLM-only |
| Bypassable by prompt injection | No | Yes | Yes | Partial | N/A (scanner) |
| 0% ASR on AgentDojo | Yes | N/A | N/A | N/A | N/A |

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Security bugs: see [SECURITY.md](SECURITY.md) — please report privately.

## License

Apache 2.0. See [LICENSE](LICENSE).
]]>