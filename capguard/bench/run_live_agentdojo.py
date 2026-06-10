"""Run the live-LLM AgentDojo benchmark with CapGuard guarding every tool call.

    OPENAI_API_KEY=...  python -m capguard.bench.run_live_agentdojo --suite banking --model gpt-4o-2024-08-06

Requires ``pip install agentdojo`` and a model API key. This drives a *real*
model end-to-end; the offline tests in ``tests/test_live_agentdojo.py`` validate
the enforcement loop against real AgentDojo environments without a key.

If your AgentDojo version constructs pipelines differently, build the pipeline
yourself and call ``capguard.bench.live_agentdojo.run_live(suite, pipeline)`` —
that is the stable entry point.
"""

from __future__ import annotations

import argparse
import os
import sys
from typing import Optional


def main(argv: Optional[list] = None) -> int:
    from .live_agentdojo import available, run_live

    if not available():
        print("agentdojo is not installed. Run: pip install agentdojo", file=sys.stderr)
        return 2

    parser = argparse.ArgumentParser(prog="capguard-live-agentdojo")
    parser.add_argument("--suite", default="banking",
                        choices=["banking", "slack", "travel", "workspace"])
    parser.add_argument("--model", default="gpt-4o-2024-08-06")
    parser.add_argument("--version", default="v1.2.1")
    args = parser.parse_args(argv)

    if not (os.environ.get("OPENAI_API_KEY") or os.environ.get("ANTHROPIC_API_KEY")):
        print("Set OPENAI_API_KEY or ANTHROPIC_API_KEY to drive a live model.", file=sys.stderr)
        return 2

    try:
        from agentdojo.agent_pipeline import AgentPipeline
        pipeline = AgentPipeline.from_config(  # type: ignore[attr-defined]
            type("Cfg", (), {"llm": args.model, "system_message_name": None,
                             "system_message": None, "tool_delimiter": "tool"})()
        )
    except Exception as exc:  # noqa: BLE001
        print(f"Could not auto-build an AgentDojo pipeline for this version: {exc}\n"
              "Build it yourself and call live_agentdojo.run_live(suite, pipeline).",
              file=sys.stderr)
        return 2

    results = run_live(args.suite, pipeline, version=args.version)
    print(results)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
