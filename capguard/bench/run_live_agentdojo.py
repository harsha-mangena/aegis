"""Run the live-LLM AgentDojo benchmark with Aegisguard guarding every tool call.

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

_OPENAI_PREFIXES = ("gpt-", "o1", "o3", "o4", "chatgpt-")
_OPENAI_MODEL_NAME_HINTS = (
    ("gpt-4o", "gpt-4o-2024-05-13"),
    ("gpt-4", "gpt-4-turbo-2024-04-09"),
    ("gpt-3.5", "gpt-3.5-turbo-0125"),
)


def _looks_like_openai_model(model: str) -> bool:
    return model.startswith(_OPENAI_PREFIXES)


def _supported_models() -> list[str]:
    from agentdojo.models import ModelsEnum

    return sorted(member.value for member in ModelsEnum)


def _available_attacks() -> list[str]:
    import agentdojo.attacks  # noqa: F401 - import registers built-in attacks
    from agentdojo.attacks.attack_registry import ATTACKS

    return sorted(ATTACKS)


def _provider_for_known_model(model: str) -> Optional[str]:
    from agentdojo.models import MODEL_PROVIDERS, ModelsEnum

    try:
        return MODEL_PROVIDERS[ModelsEnum(model)]
    except Exception:  # noqa: BLE001 - AgentDojo raises ValueError for unknown enum values
        return None


def _missing_credentials(provider: str) -> list[str]:
    required = {
        "openai": ["OPENAI_API_KEY"],
        "anthropic": ["ANTHROPIC_API_KEY"],
        "cohere": ["COHERE_API_KEY"],
        "together": ["TOGETHER_API_KEY"],
        "together-prompting": ["TOGETHER_API_KEY"],
        # AgentDojo's Google path uses Vertex AI, not the AI Studio API key.
        "google": ["GCP_PROJECT", "GCP_LOCATION"],
    }.get(provider, [])
    return [name for name in required if not os.environ.get(name)]


def _agentdojo_name_hint(model: str) -> str:
    for prefix, known_name in _OPENAI_MODEL_NAME_HINTS:
        if model.startswith(prefix) and known_name not in model:
            return f"{model} agentdojo-name-hint:{known_name}"
    return model


def _build_pipeline(model: str):
    from agentdojo.agent_pipeline import AgentPipeline
    from agentdojo.agent_pipeline.agent_pipeline import PipelineConfig

    provider = _provider_for_known_model(model)
    llm = model
    use_direct_openai_llm = False
    if provider is None:
        if not _looks_like_openai_model(model):
            valid = "\n  ".join(_supported_models())
            raise ValueError(
                f"{model!r} is not a model known to this AgentDojo install.\n"
                "Use one of:\n"
                f"  {valid}\n"
                "Newer OpenAI model IDs are also supported when OPENAI_API_KEY is set."
            )
        provider = "openai"
        use_direct_openai_llm = True

    missing = _missing_credentials(provider)
    if missing:
        raise ValueError(f"model {model!r} uses provider {provider!r}; set {', '.join(missing)}")

    if use_direct_openai_llm:
        from agentdojo.agent_pipeline.llms.openai_llm import OpenAILLM
        from openai import OpenAI

        llm = OpenAILLM(OpenAI(), model)
        llm.name = _agentdojo_name_hint(model)

    config = PipelineConfig(
        llm=llm,
        model_id=None,
        defense=None,
        system_message_name=None,
        system_message=None,
        tool_delimiter="tool",
    )
    return AgentPipeline.from_config(config)


def _build_attack(attack_name: str, suite_name: str, pipeline, version: str):
    import agentdojo.attacks  # noqa: F401 - import registers built-in attacks
    from agentdojo.attacks.attack_registry import ATTACKS, load_attack
    from agentdojo.task_suite.load_suites import get_suites

    if attack_name not in ATTACKS:
        valid = ", ".join(_available_attacks())
        raise ValueError(f"unknown attack {attack_name!r}; choose one of: {valid}")
    suite = get_suites(version)[suite_name]
    return load_attack(attack_name, suite, pipeline)


def main(argv: Optional[list] = None) -> int:
    from .live_agentdojo import available, run_live

    if not available():
        print("agentdojo is not installed. Run: pip install agentdojo", file=sys.stderr)
        return 2

    parser = argparse.ArgumentParser(prog="aegis-live-agentdojo")
    parser.add_argument("--suite", default="banking",
                        choices=["banking", "slack", "travel", "workspace"])
    parser.add_argument("--model", default="gpt-4o-2024-08-06")
    parser.add_argument("--version", default="v1.2.1")
    parser.add_argument("--attack", default=None,
                        help="AgentDojo attack to run; omit for utility-only live run")
    parser.add_argument("--user-task", action="append", default=[],
                        help="run only this AgentDojo user task ID; repeatable")
    parser.add_argument("--injection-task", action="append", default=[],
                        help="run only this AgentDojo injection task ID; repeatable")
    parser.add_argument("--list-models", action="store_true",
                        help="print models accepted by the installed AgentDojo package and exit")
    parser.add_argument("--list-attacks", action="store_true",
                        help="print AgentDojo attacks accepted by the installed package and exit")
    args = parser.parse_args(argv)

    if args.list_models:
        print("Models known to this AgentDojo install:")
        for model in _supported_models():
            print(f"  {model}")
        print("\nNewer OpenAI model IDs are accepted directly when OPENAI_API_KEY is set.")
        return 0

    if args.list_attacks:
        print("Attacks known to this AgentDojo install:")
        for attack in _available_attacks():
            print(f"  {attack}")
        return 0

    try:
        pipeline = _build_pipeline(args.model)
        attack = _build_attack(args.attack, args.suite, pipeline, args.version) if args.attack else None
    except Exception as exc:  # noqa: BLE001
        print(f"Could not auto-build an AgentDojo pipeline for this version: {exc}\n"
              "Build it yourself and call live_agentdojo.run_live(suite, pipeline).",
              file=sys.stderr)
        return 2

    if attack is None:
        print("No --attack supplied; running utility-only live tasks, so ASR will be None.", file=sys.stderr)

    results = run_live(
        args.suite,
        pipeline,
        attack=attack,
        version=args.version,
        user_task_ids=args.user_task or None,
        injection_task_ids=args.injection_task or None,
    )
    print(results)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
