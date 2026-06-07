"""Run CapGuard against the real AgentDojo suites and print the results table.

    PYTHONPATH=. python -m capguard.bench.run_agentdojo

Requires the optional `agentdojo` package (pip install agentdojo). No API key is
needed: this replays AgentDojo's ground-truth tool-call sequences through the
CapGuard enforcement runtime. To measure a live LLM instead, drive
agentdojo.agent_pipeline with an API key and route each emitted call through the
same runtime (see agentdojo_adapter.evaluate_suite for the loop).
"""

from __future__ import annotations

import sys

from .agentdojo_adapter import DEFAULT_VERSION, available, evaluate_all, format_results


def main() -> int:
    if not available():
        print("agentdojo is not installed. Run: pip install agentdojo", file=sys.stderr)
        return 2
    results = evaluate_all(DEFAULT_VERSION)
    print(format_results(results))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
