# PR: Sandboxed execution backends (ASI05)

Closes the last blocker-class gap. The capability layer already controlled *which* commands an agent may run; this adds control over *how* they run, so an allow-listed command can no longer hang, fork-bomb, fill the disk, or phone home. **50/50 tests pass (1 Docker test skipped where no daemon); CPU-bomb killed in 1.0s in the live demo.**

## Design (`sandbox.py`)
A pluggable `ExecutionBackend` with isolation tiers:

- **`SubprocessBackend`** (single host, no daemon): no shell, scrubbed env (PATH/LC only unless explicitly passed), working-dir jail, closed fds, timeout with **process-group kill**, output truncation, and POSIX **rlimits** — `RLIMIT_CPU`, `RLIMIT_AS` (memory), `RLIMIT_FSIZE`, `RLIMIT_NPROC`, `RLIMIT_CORE=0`. Degrades gracefully on non-POSIX (still no-shell + timeout).
- **`DockerBackend`**: ephemeral container per call — `--network none` by default, `--read-only` rootfs, `--cap-drop ALL`, `--security-opt no-new-privileges`, non-root, memory/cpu/pids limits, tmpfs work dir. Adds network + filesystem isolation. (`runsc`/microVM would slot in here.) `DockerBackend.available()` gates use.
- **`DenyBackend`**: refuses all execution — a safe default for untrusted agents.

## Batteries-included tool factories
`shell_tool(...)` and `python_tool(...)` register a tool that is **both** capability-gated and sandboxed, so three independent layers compose on every call:
1. capability attenuation (agent must hold a covering grant),
2. argument enforcement (metacharacter/allow-list/path checks before exec),
3. backend isolation (rlimits/timeout/jail/network).

`python_tool` defaults to **HIGH severity** → human approval required unless the deploying policy raises the ceiling, because code execution should be reviewed by default.

## Proven (tests + live)
- runs + captures output; **no-shell** means `a;b && c` is a literal arg, not chained commands.
- **timeout** kills a 30s sleep within ~1s; **CPU rlimit** kills `while True: pass` in ~1s (SIGXCPU).
- **output truncation** to a byte cap; **env scrubbed** (a host secret is invisible to the child); explicit env passthrough works.
- `DenyBackend` refuses; `shell_tool` runs `echo`, blocks `rm -rf /` (allow-list) and `echo hi; curl evil.com` (metacharacter) **before** the backend ever runs.
- `python_tool` executes `2+2`, times out an infinite loop, and requires approval at default HIGH severity.
- Docker test (network isolation) included, skipped automatically when no daemon.

## Connect-the-dots
- The unsafe path (shell/code exec) is now defense-in-depth: even if a policy or capability mistake lets a call through, the backend still caps blast radius (CPU/mem/time/network). That is exactly the ASI05 + ASI08 (cascading failure / blast-radius) posture the OWASP guidance calls for.
- Backends are injectable, so an operator picks the tier per agent/tenant: `DenyBackend` for untrusted, `SubprocessBackend` for trusted single-host, `DockerBackend` for hostile code.

## Files
- `capguard/sandbox.py` (new)
- `capguard/__init__.py` (exports)
- `tests/test_sandbox.py` (new, 11 tests + 1 docker-gated)

## Next (roadmap)
- gVisor/Firecracker backend variant (`runtime=runsc` / microVM) for hostile code at scale.
- Verifiable agent identity at the gateway/proxy boundary (blocker #5).
- Streamable-HTTP MCP transport; live-LLM AgentDojo adapter.
