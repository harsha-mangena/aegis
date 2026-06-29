"""Packaging guardrails for the aegisguard PyPI distribution."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _read(relative: str) -> str:
    return (ROOT / relative).read_text()


def _project_field(name: str) -> str:
    pyproject = _read("pyproject.toml")
    match = re.search(rf'^{re.escape(name)} = "([^"]+)"$', pyproject, re.MULTILINE)
    assert match, f"missing project field {name!r}"
    return match.group(1)


def test_distribution_name():
    assert _project_field("name") == "aegisguard"


def test_aegis_cli_entry_point():
    assert 'aegis = "capguard.cli:main"' in _read("pyproject.toml")


def test_packages_include_aegis_and_capguard():
    assert 'include = ["aegis*", "capguard*"]' in _read("pyproject.toml")


def test_aegis_public_api_importable():
    from aegis import Aegis, configure, guard, observe, reset

    assert callable(guard)
    assert callable(configure)
    assert callable(observe)
    assert callable(reset)
    assert Aegis.__name__ == "Aegis"
