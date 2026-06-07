"""Tests for rogue-agent detection + circuit breaker (ASI10 / ASI08)."""

from __future__ import annotations

import pytest

from capguard import (
    AgentIdentity,
    AgentRuntime,
    AnomalyKind,
    AnomalyPolicy,
    BehaviorMonitor,
    Capability,
    CircuitBreaker,
    Severity,
    ToolRegistry,
    ToolSpec,
)
from capguard.audit import MemorySink


def _runtime_with_monitor(policy: AnomalyPolicy, *, cooldown=0.0):
    reg = ToolRegistry()
    # a permissive set of tools so we can drive sequences of allowed calls
    for name in ("echo", "send_email", "send_message", "delete_repo", "transfer"):
        reg.register(ToolSpec(name=name, capabilities=[Capability.custom(name)],
                              severity=Severity.LOW), (lambda **kw: "ok"))
    agent = AgentIdentity(id="bot", allowed_capabilities=[
        Capability.custom(n) for n in ("echo", "send_email", "send_message", "delete_repo", "transfer")
    ])
    breaker = CircuitBreaker(cooldown_seconds=cooldown)
    downstream = MemorySink()
    monitor = BehaviorMonitor(policy, breaker=breaker, downstream=downstream)
    rt = AgentRuntime(registry=reg, default_agent=agent, audit_sink=monitor,
                      circuit_breaker=breaker)
    return rt, agent, breaker, monitor, downstream


# --------------------------------------------------------------------------- #
# call-rate anomaly
# --------------------------------------------------------------------------- #
def test_call_rate_trips_breaker_and_halts_agent():
    rt, agent, breaker, monitor, _ = _runtime_with_monitor(
        AnomalyPolicy(window_seconds=60, max_calls=3))
    for _ in range(3):
        rt.invoke_tool("echo", text="hi")          # 3 calls: within budget
    assert not breaker.is_open("bot")
    rt.invoke_tool("echo", text="hi")              # 4th call: trips
    assert breaker.is_open("bot")
    assert any(a.kind is AnomalyKind.CALL_RATE for a in monitor.anomalies)
    # subsequent calls fail closed, even valid ones
    with pytest.raises(PermissionError):
        rt.invoke_tool("echo", text="hi")


# --------------------------------------------------------------------------- #
# denial-rate (probing) anomaly
# --------------------------------------------------------------------------- #
def test_denial_rate_detects_probing():
    reg = ToolRegistry()
    reg.register(ToolSpec(name="fetch",
                          capabilities=[Capability.network_http(domains=["a.com"], arg="url")],
                          severity=Severity.LOW), (lambda **kw: "ok"))
    agent = AgentIdentity(id="bot",
                          allowed_capabilities=[Capability.network_http(domains=["a.com"], arg="url")])
    breaker = CircuitBreaker()
    monitor = BehaviorMonitor(AnomalyPolicy(max_denials=2), breaker=breaker)
    rt = AgentRuntime(registry=reg, default_agent=agent, audit_sink=monitor,
                      circuit_breaker=breaker)
    # three denied calls (host not in grant) => probing
    for _ in range(3):
        with pytest.raises(PermissionError):
            rt.invoke_tool("fetch", url="https://evil.com/x")
    assert breaker.is_open("bot")
    assert any(a.kind is AnomalyKind.DENIAL_RATE for a in monitor.anomalies)


def test_circuit_open_denials_do_not_self_reinforce():
    """Denials produced by the breaker must not feed the denial-rate detector."""
    rt, agent, breaker, monitor, _ = _runtime_with_monitor(AnomalyPolicy(max_denials=2))
    breaker.trip("bot", "manual")
    for _ in range(5):
        with pytest.raises(PermissionError):
            rt.invoke_tool("echo", text="x")
    # no DENIAL_RATE anomaly should have been raised from the breaker's own denials
    assert not any(a.kind is AnomalyKind.DENIAL_RATE for a in monitor.anomalies)


# --------------------------------------------------------------------------- #
# blast radius
# --------------------------------------------------------------------------- #
def test_blast_radius_distinct_sinks():
    sinks = frozenset({"send_email", "send_message", "delete_repo", "transfer"})
    rt, agent, breaker, monitor, _ = _runtime_with_monitor(
        AnomalyPolicy(max_distinct_sinks=2, sink_tools=sinks))
    rt.invoke_tool("send_email", to="a", body="b")
    rt.invoke_tool("send_message", channel="c", text="t")
    assert not breaker.is_open("bot")
    rt.invoke_tool("delete_repo", repo="r")        # 3rd distinct sink => trip
    assert breaker.is_open("bot")
    assert any(a.kind is AnomalyKind.BLAST_RADIUS for a in monitor.anomalies)


# --------------------------------------------------------------------------- #
# novel tool
# --------------------------------------------------------------------------- #
def test_novel_tool_outside_baseline():
    rt, agent, breaker, monitor, _ = _runtime_with_monitor(
        AnomalyPolicy(baseline_tools=frozenset({"echo"})))
    rt.invoke_tool("echo", text="hi")              # in baseline: fine
    assert not breaker.is_open("bot")
    rt.invoke_tool("transfer", amount=1, recipient="x")  # novel => anomaly + trip
    assert breaker.is_open("bot")
    assert any(a.kind is AnomalyKind.NOVEL_TOOL for a in monitor.anomalies)


# --------------------------------------------------------------------------- #
# breaker mechanics
# --------------------------------------------------------------------------- #
def test_reset_reenables_agent():
    rt, agent, breaker, monitor, _ = _runtime_with_monitor(AnomalyPolicy(max_calls=1))
    rt.invoke_tool("echo", text="a")
    rt.invoke_tool("echo", text="b")               # trips
    assert breaker.is_open("bot")
    breaker.reset("bot")
    assert rt.invoke_tool("echo", text="c") == "ok"  # allowed again


def test_cooldown_auto_resets():
    breaker = CircuitBreaker(cooldown_seconds=0.01)
    breaker.trip("bot", "x")
    assert breaker.is_open("bot")
    import time
    time.sleep(0.02)
    assert not breaker.is_open("bot")


def test_monitor_forwards_events_downstream():
    rt, agent, breaker, monitor, downstream = _runtime_with_monitor(AnomalyPolicy())
    rt.invoke_tool("echo", text="hi")
    assert len(downstream.events) == 1             # event still reaches the real sink
    assert downstream.events[0].tool_name == "echo"


def test_per_agent_isolation():
    """One rogue agent's trip must not halt a different agent."""
    rt, agent, breaker, monitor, _ = _runtime_with_monitor(AnomalyPolicy(max_calls=1))
    other = AgentIdentity(id="other", allowed_capabilities=[Capability.custom("echo")])
    rt.invoke_tool("echo", agent=agent, text="a")
    rt.invoke_tool("echo", agent=agent, text="b")  # trips "bot"
    assert breaker.is_open("bot")
    assert not breaker.is_open("other")
    assert rt.invoke_tool("echo", agent=other, text="c") == "ok"
