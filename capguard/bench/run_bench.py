from __future__ import annotations

import json
import sys

from .harness import format_report, run
from .suite_agentdojo_like import build


def main() -> int:
    scenarios, runtime, executors = build()
    rep = run(scenarios, runtime, executors)
    print(format_report(rep))
    print("\nblocked:", ", ".join(rep.blocked_detail))
    results = {
        "baseline_asr": rep.baseline_asr,
        "guarded_asr": rep.guarded_asr,
        "baseline_utility": rep.baseline_utility,
        "guarded_utility": rep.guarded_utility,
        "overhead_ms": rep.overhead_ms,
        "attacks_total": rep.total_attacks,
        "attacks_blocked": rep.total_attacks - rep.attacks_succeeded_guarded,
        "benign_total": rep.total_benign,
    }
    with open("bench_results.json", "w") as f:
        json.dump(results, f, indent=2)
    # exit non-zero if defense regressed (CI gate)
    ok = rep.guarded_asr == 0.0 and rep.guarded_utility == 1.0
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
