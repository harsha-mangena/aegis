"""Tests for task/intent-scoped capability envelopes (P6)."""

from __future__ import annotations

from datetime import timedelta

import pytest

from capguard import (
    AgentIdentity,
    AgentRuntime,
    ArgConstraint,
    Capability,
    ConstraintOp,
    HMACSigner,
    Policy,
    Severity,
    TaskScope,
    TaskScopeError,
    TaskScopeIssuer,
    ToolRegistry,
    ToolScope,
    ToolSpec,
)


def _runtime(signer=None):
    reg = ToolRegistry()

    def _make(nm):
        return lambda **kw: f"ran {nm}"

    for name, cap in [("transfer", "transfer"), ("send_email", "email"), ("read_balance", "read")]:
        reg.register(ToolSpec(name=name, capabilities=[Capability.custom(cap)],
                              severity=Severity.LOW), _make(name))
    agent = AgentIdentity(id="bot", allowed_capabilities=[
        Capability.custom("transfer"), Capability.custom("email"), Capability.custom("read"),
    ])
    rt = AgentRuntime(registry=reg, policy=Policy(max_auto_allow_severity=Severity.HIGH),
                      default_agent=agent, task_scope_signer=signer)
    return rt, agent


def _scope(agent, **overrides):
    base = dict(
        task_id="t1", agent_id=agent.id,
        tools=[ToolScope("transfer", [
            ArgConstraint("amount", ConstraintOp.LE, 100),
            ArgConstraint("recipient", ConstraintOp.EQ, "Bob"),
        ])],
        capabilities=[Capability.custom("transfer")],
        description="pay Bob up to $100",
    )
    base.update(overrides)
    return TaskScope(**base)


# --------------------------------------------------------------------------- #
# enforcement
# --------------------------------------------------------------------------- #
def test_call_within_task_scope_is_allowed():
    rt, agent = _runtime()
    scope = _scope(agent)
    assert rt.invoke_tool("transfer", amount=100, recipient="Bob", task_scope=scope) == "ran transfer"


def test_argument_constraint_violation_is_denied():
    rt, agent = _runtime()
    scope = _scope(agent)
    with pytest.raises(PermissionError):
        rt.invoke_tool("transfer", amount=101, recipient="Bob", task_scope=scope)   # amount too high
    with pytest.raises(PermissionError):
        rt.invoke_tool("transfer", amount=50, recipient="Mallory", task_scope=scope)  # wrong payee


def test_tool_outside_scope_is_denied_even_if_agent_holds_capability():
    rt, agent = _runtime()
    scope = _scope(agent)
    # the agent *can* send email in general, but this task scope does not include it
    with pytest.raises(PermissionError):
        rt.invoke_tool("send_email", to="x", task_scope=scope)


def test_missing_constrained_argument_is_denied():
    rt, agent = _runtime()
    scope = _scope(agent)
    with pytest.raises(PermissionError):
        rt.invoke_tool("transfer", amount=50, task_scope=scope)  # recipient missing


def test_expired_scope_is_denied():
    rt, agent = _runtime()
    scope = _scope(agent)
    scope.expires_at = scope.issued_at - timedelta(seconds=1)
    with pytest.raises(PermissionError):
        rt.invoke_tool("transfer", amount=50, recipient="Bob", task_scope=scope)


def test_scope_bound_to_other_agent_is_denied():
    rt, agent = _runtime()
    scope = _scope(agent, agent_id="someone-else")
    with pytest.raises(PermissionError):
        rt.invoke_tool("transfer", amount=50, recipient="Bob", task_scope=scope)


def test_calls_without_scope_still_follow_standing_policy():
    """task_scope is opt-in; omitting it leaves normal enforcement intact."""
    rt, agent = _runtime()
    assert rt.invoke_tool("send_email", to="x") == "ran send_email"


# --------------------------------------------------------------------------- #
# capability narrowing within the envelope
# --------------------------------------------------------------------------- #
def test_scope_capability_narrowing_denies_uncovered_tool():
    rt, agent = _runtime()
    # scope lists send_email as an allowed tool but grants only the 'read' capability,
    # which does NOT cover send_email's 'email' capability -> denied.
    scope = TaskScope(task_id="t", agent_id=agent.id,
                      tools=[ToolScope("send_email")],
                      capabilities=[Capability.custom("read")])
    with pytest.raises(PermissionError):
        rt.invoke_tool("send_email", to="x", task_scope=scope)


# --------------------------------------------------------------------------- #
# signing + issuance attenuation
# --------------------------------------------------------------------------- #
def test_signed_scope_verifies_and_tamper_is_rejected():
    signer = HMACSigner(b"k")
    rt, agent = _runtime(signer=signer)
    issuer = TaskScopeIssuer(signer)
    scope = issuer.issue(task_id="t1", agent=agent,
                         tools=[ToolScope("transfer", [ArgConstraint("amount", ConstraintOp.LE, 100)])],
                         capabilities=[Capability.custom("transfer")])
    assert rt.invoke_tool("transfer", amount=50, recipient="anyone", task_scope=scope) == "ran transfer"
    # tamper: widen the constraint after signing
    scope.tools[0].constraints[0].value = 10_000
    with pytest.raises(PermissionError):
        rt.invoke_tool("transfer", amount=5000, recipient="anyone", task_scope=scope)


def test_issuer_cannot_grant_capability_agent_lacks():
    signer = HMACSigner(b"k")
    _, agent = _runtime(signer=signer)
    issuer = TaskScopeIssuer(signer)
    with pytest.raises(TaskScopeError):
        issuer.issue(task_id="t", agent=agent, tools=[ToolScope("danger")],
                     capabilities=[Capability.shell_exec(allowlist=["rm"])])  # agent has no shell cap


def test_dict_roundtrip_preserves_enforcement():
    rt, agent = _runtime()
    scope = _scope(agent)
    restored = TaskScope.from_dict(scope.to_dict())
    assert rt.invoke_tool("transfer", amount=100, recipient="Bob", task_scope=restored) == "ran transfer"
    with pytest.raises(PermissionError):
        rt.invoke_tool("transfer", amount=101, recipient="Bob", task_scope=restored)
