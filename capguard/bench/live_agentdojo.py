"""Live-LLM AgentDojo integration — CapGuard as the action-layer backstop.

The deterministic adapter (``agentdojo_adapter.py``) replays ground-truth tool
calls; useful, but a reviewer rightly discounts self-reported replay numbers.
This module is the *real* hook: a drop-in ``FunctionsRuntime`` subclass that
makes AgentDojo route **every tool call a live model emits through CapGuard
before it executes**. Hand the class to AgentDojo's `run_task_with_pipeline`,
point the pipeline at GPT-4o / Claude, and the ASR/utility you get is end-to-end
with a real model in the loop.

Honest provenance — the key difference from the replay adapter: labels come from
the **source boundary**, never from ground truth. A tool that reads
attacker-influenceable environment content (email, web page, channel, file)
taints its output ``untrusted_tool``; the tracker propagates that taint; and a
*sensitive sink* (send money / email / message / reservation) whose arguments
carry untrusted taint is denied. The same one general profile runs for every
task; nothing inspects the attacker's goal.

AgentDojo instantiates the runtime itself (``runtime_class(functions)``), so the
guard is delivered as a self-configuring class via
:func:`make_guarded_runtime_class`. The offline tests exercise the enforcement
loop against *real* AgentDojo environments with no model or API key; the live
numbers come from :func:`run_live` with a pipeline you supply.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from capguard import (
    UNTRUSTED_TOOL,
    AgentIdentity,
    AgentRuntime,
    ApprovalRequired,
    Capability,
    CapabilityViolation,
    Effect,
    Flow,
    PolicyEngine,
    ProvenanceTracker,
    Rule,
    Severity,
    ToolRegistry,
    ToolSpec,
    tool_is,
)

from .agentdojo_adapter import SENSITIVE_SINKS

_BLOCKED = (PermissionError, CapabilityViolation, ApprovalRequired)

# Tools whose output surfaces attacker-influenceable environment content — the
# injection vectors. Reading them taints the result; the taint then propagates.
UNTRUSTED_SOURCES: Dict[str, set] = {
    "banking": {"read_file", "get_most_recent_transactions", "get_scheduled_transactions"},
    "slack": {"read_channel_messages", "read_inbox", "get_webpage"},
    "travel": {"get_all_hotels_in_city", "get_all_restaurants_in_city",
               "get_rating_reviews_for_hotels", "get_rating_reviews_for_restaurants",
               "get_hotels_address"},
    "workspace": {"read_email", "search_emails", "read_file", "search_files",
                  "search_files_by_filename", "get_unread_emails"},
}


def _secure_profile(suite_name: str, tool_names: List[str]):
    """Enforcement-only shims + a least-privilege agent + one general rule:
    a sensitive sink fed by untrusted/injected data is denied."""
    reg = ToolRegistry()
    caps = []
    for name in tool_names:
        reg.register(ToolSpec(name=name, capabilities=[Capability.custom(name)],
                              severity=Severity.LOW), (lambda **kw: None))
        caps.append(Capability.custom(name))
    sinks = SENSITIVE_SINKS.get(suite_name, set())
    engine = PolicyEngine()
    if sinks:
        engine.add(Rule(name="sink-untrusted", trigger=tool_is(*sinks),
                        when=Flow.any_untrusted(), effect=Effect.DENY,
                        reason="sensitive sink fed by untrusted/injected data"))
    agent = AgentIdentity(id=f"agentdojo-{suite_name}", allowed_capabilities=caps)
    return AgentRuntime(registry=reg, engine=engine, default_agent=agent), agent


def make_guarded_runtime_class(suite_name: str):
    """Return a ``FunctionsRuntime`` subclass that guards every call via CapGuard.

    Pass it to ``suite.run_task_with_pipeline(..., runtime_class=Cls)``.
    """
    from agentdojo.functions_runtime import FunctionsRuntime

    sources = UNTRUSTED_SOURCES.get(suite_name, set())

    class _GuardedFunctionsRuntime(FunctionsRuntime):
        def __init__(self, functions=()):  # AgentDojo calls this with the suite's functions
            super().__init__(functions)
            self._cap, self._agent = _secure_profile(suite_name, list(self.functions))
            self._tracker = ProvenanceTracker()
            self._sources = sources
            self.blocked: List[tuple] = []

        def run_function(self, env, function, kwargs, raise_on_error: bool = False):
            if not self._cap.registry.has(function):
                return super().run_function(env, function, kwargs, raise_on_error)
            # provenance from propagated taint (NOT ground truth)
            prov = {k: self._tracker.label_for(v).trust_str for k, v in kwargs.items()}
            try:
                self._cap.invoke_tool(function, agent=self._agent, provenance=prov, **kwargs)
            except _BLOCKED as exc:
                self.blocked.append((function, str(exc)))
                return "", f"CapGuardBlocked: {exc}"   # the model sees a tool error, as with a real guard
            result, error = super().run_function(env, function, kwargs, raise_on_error)
            src = UNTRUSTED_TOOL if function in self._sources else None
            self._tracker.record_output(result, list(kwargs.values()), source=src)
            return result, error

    return _GuardedFunctionsRuntime


def build_guarded_runtime(suite, suite_name: Optional[str] = None):
    """Build a configured guarded runtime *instance* (for direct testing)."""
    name = suite_name or getattr(suite, "name", "suite")
    return make_guarded_runtime_class(name)(suite.tools)


def available() -> bool:
    try:
        import agentdojo  # noqa: F401
        return True
    except Exception:  # noqa: BLE001
        return False


def run_live(
    suite_name: str,
    pipeline,
    *,
    attack=None,
    version: str = "v1.2.1",
    user_task_ids: Optional[List[str]] = None,
    injection_task_ids: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Run a real AgentDojo pipeline with CapGuard guarding every tool call.

    ``pipeline`` is an ``agentdojo.agent_pipeline.AgentPipeline`` (your model).
    Returns end-to-end utility and ASR from AgentDojo's own ``(success,
    injection_success)`` outcomes — the number to publish. Requires a model + key,
    so it is not exercised by the offline tests.
    """
    from agentdojo.task_suite.load_suites import get_suites

    suite = get_suites(version)[suite_name]
    cls = make_guarded_runtime_class(suite_name)
    uids = user_task_ids or list(suite.user_tasks)
    iids = injection_task_ids or list(suite.injection_tasks)

    util_pass = util_total = 0
    inj_success = inj_total = 0
    for uid in uids:
        ut = suite.user_tasks[uid]
        ok, _ = suite.run_task_with_pipeline(pipeline, ut, None, {}, runtime_class=cls)
        util_total += 1
        util_pass += int(bool(ok))
        if attack is not None:
            for iid in iids:
                it = suite.injection_tasks[iid]
                injections = attack.attack(ut, it) if hasattr(attack, "attack") else {}
                _, inj_ok = suite.run_task_with_pipeline(pipeline, ut, it, injections, runtime_class=cls)
                inj_total += 1
                inj_success += int(bool(inj_ok))
    return {
        "suite": suite_name,
        "utility": util_pass / max(1, util_total),
        "asr": inj_success / max(1, inj_total) if inj_total else None,
        "n_user": util_total, "n_injection": inj_total,
    }
