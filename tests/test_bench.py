from __future__ import annotations

from capguard.bench.harness import run
from capguard.bench.suite_agentdojo_like import build


def test_benchmark_blocks_all_attacks_and_preserves_utility():
    scenarios, runtime, executors = build()
    rep = run(scenarios, runtime, executors, timing_iters=20)
    # baseline (no defense) lets everything through
    assert rep.baseline_asr == 1.0
    assert rep.baseline_utility == 1.0
    # CapGuard blocks every attempted malicious call ...
    assert rep.guarded_asr == 0.0, f"attacks leaked: {rep.total_attacks - (rep.total_attacks - rep.attacks_succeeded_guarded)}"
    # ... while preserving every benign call (no over-blocking)
    assert rep.guarded_utility == 1.0
    assert rep.total_attacks >= 13


def test_benchmark_overhead_is_sub_millisecond():
    scenarios, runtime, executors = build()
    rep = run(scenarios, runtime, executors, timing_iters=200)
    assert rep.overhead_ms < 1.0  # deterministic enforcement is cheap
