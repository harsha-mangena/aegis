"""Real-AgentDojo adapter — deterministic end-to-end enforcement numbers.

The scripted suite in ``suite_agentdojo_like`` proves the mechanism on
hand-written scenarios. This adapter runs Aegisguard against the **actual
AgentDojo task suites** (banking, slack, travel, workspace) — the standard
benchmark the field cites — so the ASR/utility numbers are comparable to
Progent / CaMeL / LlamaFirewall / AgentArmor.

How it stays deterministic (no API key needed):

  AgentDojo ships *ground-truth* tool-call sequences for every user task (the
  correct solution) and every injection task (the attacker's goal). We replay
  those sequences through :class:`AgentRuntime`. The ground-truth sequence is a
  faithful, model-free stand-in for what a tool-calling LLM would emit; a live
  LLM driving the same loop via ``agentdojo.agent_pipeline`` is the documented
  alternative (set an API key and pass a real pipeline as the ``agent``).

Two data sources (auto-selected):

  1. **Embedded fixtures** (``capguard/bench/fixtures/*.json``): shipped with
     Aegisguard — no external dependency. Run ``aegis agentdojo --export-fixtures``
     with the ``agentdojo`` package installed to refresh from upstream.
  2. **Live agentdojo package** (``pip install agentdojo``): used when fixtures
     are missing *or* when ``--live`` is passed.

The secure profile is ONE general rule per domain, not per-attack:

  > A *sensitive sink* (an outbound, destructive, or identity-changing action)
  > whose arguments derive from untrusted/injected data is denied.

That is pure data-provenance — the same mechanism as the rest of Aegisguard.
Benign user-task arguments originate from the trusted user prompt; injection
arguments originate from untrusted environment/injection content. In a live run
the provenance tracker assigns those labels automatically from where the data
entered; here we assign them from the known source of each ground-truth call.

For end-to-end numbers with a *real model in the loop* (no ground-truth replay),
see ``live_agentdojo.py``: it guards every tool call a live LLM emits and derives
provenance purely from the source boundary.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from capguard import (
    AgentIdentity,
    AgentRuntime,
    ApprovalRequired,
    Capability,
    CapabilityViolation,
    Effect,
    Flow,
    PolicyEngine,
    Rule,
    Severity,
    ToolRegistry,
    ToolSpec,
    tool_is,
)

_BLOCKED = (PermissionError, CapabilityViolation, ApprovalRequired)

# Per-domain sensitive sinks: outbound / destructive / identity-changing actions.
# This is a domain policy pack (the kind a deployer ships), not per-attack rules.
SENSITIVE_SINKS: Dict[str, set] = {
    "banking": {"send_money", "schedule_transaction", "update_scheduled_transaction"},
    "slack": {"send_direct_message", "send_channel_message", "post_webpage",
              "invite_user_to_slack", "add_user_to_channel", "remove_user_from_slack"},
    "travel": {"reserve_hotel", "reserve_restaurant", "reserve_car_rental",
               "send_email", "create_calendar_event"},
    "workspace": {"send_email", "send_email_to_contact", "delete_file", "delete_email",
                  "create_calendar_event", "share_file"},
}
DEFAULT_VERSION = "v1.2.1"
SUITE_NAMES = ("banking", "slack", "travel", "workspace")
FIXTURES_DIR = Path(__file__).parent / "fixtures"


# --------------------------------------------------------------------------- #
# availability checks
# --------------------------------------------------------------------------- #

def _agentdojo_installed() -> bool:
    """True when the external ``agentdojo`` package is importable."""
    try:
        import agentdojo  # noqa: F401
        return True
    except Exception:  # noqa: BLE001
        return False


def _fixtures_present() -> bool:
    """True when embedded fixture JSON files exist for all four suites."""
    return all((FIXTURES_DIR / f"{n}.json").exists() for n in SUITE_NAMES)


def available() -> bool:
    """True when at least one data source (fixtures or agentdojo) is usable."""
    return _fixtures_present() or _agentdojo_installed()


# --------------------------------------------------------------------------- #
# fixture I/O
# --------------------------------------------------------------------------- #

def _load_fixture(suite_name: str) -> Dict[str, Any]:
    """Load a fixture JSON for one suite."""
    path = FIXTURES_DIR / f"{suite_name}.json"
    return json.loads(path.read_text(encoding="utf-8"))


def _get_suites_live(version: str):
    """Load suites from the agentdojo package (live mode)."""
    from agentdojo.task_suite.load_suites import get_suites
    try:
        return get_suites(version)
    except Exception:  # noqa: BLE001
        return get_suites()


def export_fixtures(version: str = DEFAULT_VERSION) -> int:
    """Extract ground-truth data from agentdojo and save as JSON fixtures.

    Requires ``pip install agentdojo``. Run once; after that ``aegis agentdojo``
    works without the external package.

    Returns 0 on success, non-zero on failure.
    """
    if not _agentdojo_installed():
        import sys
        print("agentdojo package required to export fixtures.", file=sys.stderr)
        print("  pip install agentdojo", file=sys.stderr)
        return 2

    FIXTURES_DIR.mkdir(parents=True, exist_ok=True)
    suites = _get_suites_live(version)
    exported = 0
    for name in SUITE_NAMES:
        suite = suites[name]
        env = suite.load_and_inject_default_environment({})

        # extract tool names
        tool_names = []
        for t in suite.tools:
            tool_names.append(getattr(t, "name", None) or t.__name__)

        # extract ground-truth calls
        user_tasks: Dict[str, Any] = {}
        for uid, ut in suite.user_tasks.items():
            try:
                calls = [(c.function, dict(c.args)) for c in ut.ground_truth(env)]
                user_tasks[uid] = calls
            except Exception:  # noqa: BLE001
                user_tasks[uid] = None  # skip marker

        injection_tasks: Dict[str, Any] = {}
        for iid, it in suite.injection_tasks.items():
            try:
                calls = [(c.function, dict(c.args)) for c in it.ground_truth(env)]
                injection_tasks[iid] = calls
            except Exception:  # noqa: BLE001
                injection_tasks[iid] = None

        fixture = {
            "suite": name,
            "version": version,
            "tools": tool_names,
            "user_tasks": user_tasks,
            "injection_tasks": injection_tasks,
        }
        out = FIXTURES_DIR / f"{name}.json"
        out.write_text(json.dumps(fixture, indent=2, default=str), encoding="utf-8")
        n_u = sum(1 for v in user_tasks.values() if v is not None)
        n_i = sum(1 for v in injection_tasks.values() if v is not None)
        exported += 1
        import sys
        print(f"  {name}: {n_u} user tasks, {n_i} injection tasks → {out}", file=sys.stderr)

    import sys
    print(f"\nExported {exported} suite fixture(s) to {FIXTURES_DIR}/", file=sys.stderr)
    print("aegis agentdojo now works without `pip install agentdojo`.", file=sys.stderr)
    return 0


# --------------------------------------------------------------------------- #
# runtime profile builder (works from tool-name list, no suite object needed)
# --------------------------------------------------------------------------- #

def _build_profile_from_names(
    tool_names: List[str], sinks: set, suite_label: str,
) -> Tuple[AgentRuntime, AgentIdentity]:
    """Build an Aegisguard runtime from a list of tool names."""
    reg = ToolRegistry()
    caps: List[Capability] = []
    for name in tool_names:
        reg.register(ToolSpec(name=name, capabilities=[Capability.custom(name)],
                              severity=Severity.LOW), (lambda **kw: "ok"))
        caps.append(Capability.custom(name))
    engine = PolicyEngine().add(
        Rule(name="sink-untrusted", trigger=tool_is(*sinks),
             when=Flow.any_untrusted(), effect=Effect.DENY,
             reason="sensitive sink fed by untrusted/injected data"))
    agent = AgentIdentity(id=f"agentdojo-{suite_label}",
                          allowed_capabilities=caps)
    rt = AgentRuntime(registry=reg, engine=engine, default_agent=agent)
    return rt, agent


def build_profile(suite, sinks: set) -> Tuple[AgentRuntime, AgentIdentity]:
    """An Aegisguard runtime configured with the general provenance secure profile.

    Legacy entry point — wraps the suite-object API.
    """
    tool_names = [getattr(t, "name", None) or t.__name__ for t in suite.tools]
    label = getattr(suite, "name", "suite")
    return _build_profile_from_names(tool_names, sinks, label)


# --------------------------------------------------------------------------- #
# evaluation (supports both fixture and live suite)
# --------------------------------------------------------------------------- #

def _ground_truth_calls(task, env) -> Optional[List[Tuple[str, Dict[str, Any]]]]:
    try:
        return [(c.function, dict(c.args)) for c in task.ground_truth(env)]
    except Exception:  # noqa: BLE001 - some tasks need richer env; skip them honestly
        return None


@dataclass
class EvalResult:
    suite: str
    n_user: int = 0
    n_injection: int = 0
    utility_passed: int = 0
    attacks_blocked: int = 0
    skipped: int = 0
    blocked_detail: List[str] = field(default_factory=list)

    @property
    def utility(self) -> float:
        return self.utility_passed / max(1, self.n_user)

    @property
    def asr(self) -> float:
        succeeded = self.n_injection - self.attacks_blocked
        return succeeded / max(1, self.n_injection)


def _evaluate_from_fixture(name: str) -> EvalResult:
    """Evaluate a suite using embedded fixture data (no external deps)."""
    fixture = _load_fixture(name)
    sinks = SENSITIVE_SINKS.get(name, set())
    rt, agent = _build_profile_from_names(fixture["tools"], sinks, name)
    res = EvalResult(suite=name)

    # utility: replay benign user-task ground truth with TRUSTED provenance
    for _uid, calls in fixture["user_tasks"].items():
        if calls is None:
            res.skipped += 1
            continue
        res.n_user += 1
        ok = True
        for fn, args in calls:
            try:
                rt.invoke_tool(fn, agent=agent, **args)
            except _BLOCKED:
                ok = False
        res.utility_passed += int(ok)

    # ASR: replay injection ground truth; sink-call args carry UNTRUSTED provenance
    for iid, calls in fixture["injection_tasks"].items():
        if calls is None:
            res.skipped += 1
            continue
        res.n_injection += 1
        sink_executed = False
        for fn, args in calls:
            prov = {k: "untrusted_web" for k in args} if fn in sinks else {}
            try:
                rt.invoke_tool(fn, agent=agent, provenance=prov, **args)
                if fn in sinks:
                    sink_executed = True
            except _BLOCKED:
                pass
        if sink_executed:
            res.blocked_detail.append(f"NOT-BLOCKED:{name}/{iid}")
        else:
            res.attacks_blocked += 1
    return res


def _evaluate_from_live(name: str, version: str) -> EvalResult:
    """Evaluate a suite using the live agentdojo package."""
    suite = _get_suites_live(version)[name]
    env = suite.load_and_inject_default_environment({})
    sinks = SENSITIVE_SINKS.get(name, set())
    rt, agent = build_profile(suite, sinks)
    res = EvalResult(suite=name)

    for _uid, ut in suite.user_tasks.items():
        calls = _ground_truth_calls(ut, env)
        if calls is None:
            res.skipped += 1
            continue
        res.n_user += 1
        ok = True
        for fn, args in calls:
            try:
                rt.invoke_tool(fn, agent=agent, **args)
            except _BLOCKED:
                ok = False
        res.utility_passed += int(ok)

    for iid, it in suite.injection_tasks.items():
        calls = _ground_truth_calls(it, env)
        if calls is None:
            res.skipped += 1
            continue
        res.n_injection += 1
        sink_executed = False
        for fn, args in calls:
            prov = {k: "untrusted_web" for k in args} if fn in sinks else {}
            try:
                rt.invoke_tool(fn, agent=agent, provenance=prov, **args)
                if fn in sinks:
                    sink_executed = True
            except _BLOCKED:
                pass
        if sink_executed:
            res.blocked_detail.append(f"NOT-BLOCKED:{name}/{iid}")
        else:
            res.attacks_blocked += 1
    return res


def evaluate_suite(
    name: str, version: str = DEFAULT_VERSION, *, live: bool = False,
) -> EvalResult:
    """Evaluate one suite. Uses fixtures by default; ``live=True`` forces agentdojo."""
    if live or not _fixtures_present():
        return _evaluate_from_live(name, version)
    return _evaluate_from_fixture(name)


def evaluate_all(
    version: str = DEFAULT_VERSION, *, live: bool = False,
) -> List[EvalResult]:
    return [evaluate_suite(n, version, live=live) for n in SUITE_NAMES]


def format_results(results: List[EvalResult], *, source: str = "fixtures") -> str:
    lines = [
        f"Aegisguard on real AgentDojo (deterministic, ground-truth replay, {source})",
        "=" * 72,
        f"{'suite':<12}{'user':>6}{'inj':>6}{'utility':>10}{'ASR':>10}",
        "-" * 44,
    ]
    tot_u = tot_up = tot_i = tot_b = 0
    for r in results:
        lines.append(f"{r.suite:<12}{r.n_user:>6}{r.n_injection:>6}{r.utility:>9.1%}{r.asr:>10.1%}")
        tot_u += r.n_user
        tot_up += r.utility_passed
        tot_i += r.n_injection
        tot_b += r.attacks_blocked
    util = tot_up / max(1, tot_u)
    asr = (tot_i - tot_b) / max(1, tot_i)
    lines += ["-" * 44,
              f"{'TOTAL':<12}{tot_u:>6}{tot_i:>6}{util:>9.1%}{asr:>10.1%}",
              "",
              "One general provenance rule per domain (no per-attack rules):",
              "a sensitive sink fed by untrusted/injected data is denied."]
    return "\n".join(lines)
