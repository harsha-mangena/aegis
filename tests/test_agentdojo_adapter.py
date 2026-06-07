"""Tests for the real-AgentDojo adapter (P3).

These run only when the optional `agentdojo` package is installed; otherwise they
skip, so the core suite stays dependency-light. When present, they assert the
deterministic ground-truth replay yields ASR 0 at full utility.
"""

from __future__ import annotations

import pytest

from capguard.bench import agentdojo_adapter as ada

needs_agentdojo = pytest.mark.skipif(not ada.available(), reason="agentdojo not installed")


def test_available_returns_bool():
    assert isinstance(ada.available(), bool)


def test_sink_pack_covers_known_suites():
    for suite in ("banking", "slack", "travel", "workspace"):
        assert ada.SENSITIVE_SINKS[suite]


@needs_agentdojo
def test_banking_zero_asr_full_utility():
    r = ada.evaluate_suite("banking")
    assert r.n_user > 0 and r.n_injection > 0
    assert r.utility == 1.0
    assert r.asr == 0.0


@needs_agentdojo
def test_all_suites_zero_asr():
    results = ada.evaluate_all()
    total_inj = sum(r.n_injection for r in results)
    succeeded = sum(r.n_injection - r.attacks_blocked for r in results)
    assert total_inj >= 30          # all four suites loaded with real injection tasks
    assert succeeded == 0           # ASR 0% across the whole benchmark
    # utility should remain high (the secure profile gates on provenance, not action)
    tot_user = sum(r.n_user for r in results)
    tot_pass = sum(r.utility_passed for r in results)
    assert tot_pass / tot_user >= 0.95
