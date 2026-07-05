"""Tests for the live-LLM AgentDojo integration (Phase 1).

These run the CapGuard-guarded FunctionsRuntime against REAL AgentDojo
environments — no model or API key needed. They prove the enforcement loop a
live run depends on: a source read taints its output, and a sensitive sink fed
that tainted value is blocked by propagated provenance (not by peeking at the
attacker's goal).
"""

from __future__ import annotations

import pytest

from capguard import Trust
from capguard.bench import live_agentdojo as live

needs_agentdojo = pytest.mark.skipif(not live.available(), reason="agentdojo not installed")
_BILL = "bill-december-2023.txt"


def test_available_is_bool():
    assert isinstance(live.available(), bool)


def test_sink_sources_pack_is_defined():
    for suite in ("banking", "slack", "travel", "workspace"):
        assert live.UNTRUSTED_SOURCES[suite]


def _banking_rt():
    from agentdojo.task_suite.load_suites import get_suites
    suite = get_suites("v1.2.1")["banking"]
    env = suite.load_and_inject_default_environment({})
    return live.build_guarded_runtime(suite, "banking"), env


@needs_agentdojo
def test_source_read_taints_output_nonsource_does_not():
    grt, env = _banking_rt()
    bal, _ = grt.run_function(env, "get_balance", {})          # not a source
    assert grt._tracker.label_for(bal).trust is Trust.TRUSTED
    content, err = grt.run_function(env, "read_file", {"file_path": _BILL})  # a source
    assert (err is None) or (not str(err).startswith("CapGuardBlocked"))
    assert grt._tracker.label_for(content).trust is not Trust.TRUSTED        # tainted


@needs_agentdojo
def test_laundered_value_into_sink_is_blocked_in_real_env():
    grt, env = _banking_rt()
    content, _ = grt.run_function(env, "read_file", {"file_path": _BILL})    # tainted source
    # the agent is steered to send money with the injected content as the subject
    _, err = grt.run_function(env, "send_money", {
        "recipient": "US133000000121212121212", "amount": 1.0,
        "subject": content, "date": "2024-01-01"})
    assert err and str(err).startswith("AegisguardBlocked")
    assert any(fn == "send_money" for fn, _ in grt.blocked)


@needs_agentdojo
def test_trusted_sink_is_not_blocked():
    grt, env = _banking_rt()
    # first-party args (no tainted data) -> CapGuard must not block it
    _, err = grt.run_function(env, "send_money", {
        "recipient": "DE89370400440532013000", "amount": 10.0,
        "subject": "monthly rent", "date": "2024-01-01"})
    assert (err is None) or (not str(err).startswith("CapGuardBlocked"))
    assert not any(fn == "send_money" for fn, _ in grt.blocked)
