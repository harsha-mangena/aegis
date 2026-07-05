"""Run Aegisguard against the real AgentDojo suites and print the results table.

    aegis agentdojo                    # replay from embedded fixtures (no deps)
    aegis agentdojo --live             # replay from live agentdojo package
    aegis agentdojo --export-fixtures  # extract ground-truth → fixtures/*.json

No API key is needed: this replays AgentDojo's ground-truth tool-call sequences
through the Aegisguard enforcement runtime. To measure a live LLM instead, drive
agentdojo.agent_pipeline with an API key and route each emitted call through the
same runtime (see agentdojo_adapter.evaluate_suite for the loop).
"""

from __future__ import annotations

import sys

from .agentdojo_adapter import (
    DEFAULT_VERSION,
    _agentdojo_installed,
    available,
    evaluate_all,
    export_fixtures,
    format_results,
)


def main(argv: list[str] | None = None) -> int:
    import argparse
    p = argparse.ArgumentParser(
        prog="aegis agentdojo",
        description="Run Aegisguard against real AgentDojo task suites.",
    )
    p.add_argument("--live", action="store_true",
                   help="use the agentdojo package instead of embedded fixtures")
    p.add_argument("--export-fixtures", action="store_true",
                   help="extract ground-truth from agentdojo and save as JSON fixtures")
    p.add_argument("--version", default=DEFAULT_VERSION, dest="dojo_version",
                   help=f"AgentDojo suite version (default: {DEFAULT_VERSION})")
    args = p.parse_args(argv)

    if args.export_fixtures:
        return export_fixtures(args.dojo_version)

    if args.live and not _agentdojo_installed():
        print("--live requires the agentdojo package:", file=sys.stderr)
        print("  pip install agentdojo", file=sys.stderr)
        return 2

    if not available():
        print("No AgentDojo data source found.\n", file=sys.stderr)
        print("Option 1 — export fixtures (one-time, then no dependency):", file=sys.stderr)
        print("  pip install agentdojo", file=sys.stderr)
        print("  aegis agentdojo --export-fixtures", file=sys.stderr)
        print("  pip uninstall agentdojo  # optional", file=sys.stderr)
        print("", file=sys.stderr)
        print("Option 2 — use agentdojo live:", file=sys.stderr)
        print("  pip install agentdojo", file=sys.stderr)
        print("  aegis agentdojo --live", file=sys.stderr)
        print("", file=sys.stderr)
        print("For the self-contained benchmark (no external deps):", file=sys.stderr)
        print("  aegis bench", file=sys.stderr)
        return 2

    source = "live" if args.live else "fixtures"
    results = evaluate_all(args.dojo_version, live=args.live)
    print(format_results(results, source=source))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
