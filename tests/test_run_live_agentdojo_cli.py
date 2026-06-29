"""CLI compatibility tests for the live AgentDojo runner."""

from __future__ import annotations

import importlib.util

import pytest

from capguard.bench import run_live_agentdojo as cli

needs_agentdojo = pytest.mark.skipif(importlib.util.find_spec("agentdojo") is None, reason="agentdojo not installed")


@needs_agentdojo
def test_list_models_exits_successfully(capsys):
    assert cli.main(["--list-models"]) == 0
    out = capsys.readouterr().out
    assert "Models known to this AgentDojo install" in out
    assert "gpt-4o" in out


@needs_agentdojo
def test_list_attacks_exits_successfully(capsys):
    assert cli.main(["--list-attacks"]) == 0
    out = capsys.readouterr().out
    assert "Attacks known to this AgentDojo install" in out
    assert "direct" in out
    assert "important_instructions" in out


@needs_agentdojo
def test_newer_openai_model_ids_require_openai_key(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    with pytest.raises(ValueError, match="OPENAI_API_KEY"):
        cli._build_pipeline("gpt-4o-2024-08-06")


@needs_agentdojo
def test_unknown_non_openai_model_lists_supported_models():
    with pytest.raises(ValueError, match="not a model known"):
        cli._build_pipeline("definitely-not-a-model")


def test_newer_openai_name_hint_keeps_agentdojo_attack_compatibility():
    hinted = cli._agentdojo_name_hint("gpt-4o-2024-08-06")
    assert "gpt-4o-2024-08-06" in hinted
    assert "gpt-4o-2024-05-13" in hinted
