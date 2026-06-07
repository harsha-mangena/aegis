"""Tests for the policy-pack compiler."""

from __future__ import annotations

import json

import pytest

from capguard import (
    AgentIdentity,
    AgentRuntime,
    Capability,
    Effect,
    PackError,
    ProvenanceTracker,
    Severity,
    ToolRegistry,
    ToolSpec,
    builtin_pack_names,
    compile_pack,
    load_pack,
    pack_capabilities,
)
from capguard.policy_dsl import CallContext


def _ctx(tool, args=None, provenance=None, labels=None, roles=()):
    return CallContext(agent_id="a", tool_name=tool, args=args or {},
                       roles=roles, provenance=provenance or {},
                       extra={"labels": labels or {}})


# --------------------------------------------------------------------------- #
# predicate compilation
# --------------------------------------------------------------------------- #
def test_arg_predicate_compiles():
    eng = compile_pack({"rules": [
        {"name": "big", "tools": ["transfer"], "when": {"arg": "amount", "op": ">", "value": 1000},
         "effect": "require_approval"}]})
    assert eng.evaluate(_ctx("transfer", {"amount": 5000})).effect is Effect.REQUIRE_APPROVAL
    assert eng.evaluate(_ctx("transfer", {"amount": 10})).effect is Effect.ALLOW


def test_provenance_and_boolean_composition():
    eng = compile_pack({"rules": [
        {"name": "r", "tools": ["send_email"],
         "when": {"all": [{"provenance": "to", "is": "untrusted"},
                          {"arg": "to", "op": "matches", "value": "*@*"}]},
         "effect": "deny"}]})
    d = eng.evaluate(_ctx("send_email", {"to": "x@evil.com"}, provenance={"to": "untrusted_web"}))
    assert d.effect is Effect.DENY
    ok = eng.evaluate(_ctx("send_email", {"to": "x@corp.com"}, provenance={"to": "trusted"}))
    assert ok.effect is Effect.ALLOW


def test_flow_predicate():
    from capguard import SECRET
    eng = compile_pack({"rules": [
        {"name": "exfil", "tools": ["send_*"], "when": {"flow": "any_secret"}, "effect": "deny"}]})
    d = eng.evaluate(_ctx("send_message", {"text": "x"}, labels={"text": SECRET}))
    assert d.effect is Effect.DENY


def test_unknown_op_and_effect_raise():
    with pytest.raises(PackError):
        compile_pack({"rules": [{"name": "x", "when": {"arg": "a", "op": "≈", "value": 1}, "effect": "deny"}]})
    with pytest.raises(PackError):
        compile_pack({"rules": [{"name": "x", "effect": "banish"}]})


# --------------------------------------------------------------------------- #
# builtin packs
# --------------------------------------------------------------------------- #
def test_builtin_packs_exist_and_compile():
    names = builtin_pack_names()
    assert {"owasp-baseline", "finance", "data-exfil"}.issubset(set(names))
    for n in names:
        eng = compile_pack(n)
        assert eng.rules


def test_finance_pack_end_to_end():
    reg = ToolRegistry()
    reg.register(ToolSpec(name="transfer", capabilities=[Capability.custom("transfer")],
                          severity=Severity.LOW), lambda **kw: "moved")
    agent = AgentIdentity(id="bot", allowed_capabilities=[Capability.custom("transfer")])
    rt = AgentRuntime(registry=reg, engine=compile_pack("finance"),
                      default_agent=agent, tracker=ProvenanceTracker())
    # under limit, trusted recipient -> allowed
    assert rt.invoke_tool("transfer", amount=100, recipient="alice") == "moved"
    # over limit -> approval required
    from capguard import ApprovalRequired
    with pytest.raises((ApprovalRequired, PermissionError)):
        rt.invoke_tool("transfer", amount=9999, recipient="alice")
    # untrusted recipient -> denied
    with pytest.raises(PermissionError):
        rt.invoke_tool("transfer", amount=50, recipient="attacker",
                       provenance={"recipient": "untrusted_web"})


# --------------------------------------------------------------------------- #
# capability templates + loading
# --------------------------------------------------------------------------- #
def test_capability_templates_compile():
    pack = {"capabilities": [
        {"type": "network_http", "domains": ["api.corp.com"]},
        {"type": "shell_exec", "allowlist": ["ls", "cat"], "timeout": 30},
        {"type": "custom", "name": "transfer"},
    ], "rules": []}
    caps = pack_capabilities(pack)
    assert len(caps) == 3
    assert caps[0].covers(Capability.network_http(domains=["api.corp.com"]))


def test_load_pack_from_json_file(tmp_path):
    p = tmp_path / "pack.json"
    p.write_text(json.dumps({"name": "t", "rules": [
        {"name": "deny-all-shell", "tools": ["run_shell"], "effect": "deny"}]}))
    eng = compile_pack(str(p))
    assert eng.evaluate(_ctx("run_shell", {"cmd": "ls"})).effect is Effect.DENY


def test_unknown_pack_name_raises():
    with pytest.raises(PackError):
        load_pack("does-not-exist-pack")


@pytest.mark.skipif(__import__("importlib").util.find_spec("yaml") is None,
                    reason="PyYAML not installed")
def test_load_pack_from_yaml_file(tmp_path):
    p = tmp_path / "pack.yaml"
    p.write_text(
        "name: y\n"
        "rules:\n"
        "  - name: big\n"
        "    tools: [transfer]\n"
        "    when: {arg: amount, op: '>', value: 1000}\n"
        "    effect: require_approval\n"
    )
    eng = compile_pack(str(p))
    assert eng.evaluate(_ctx("transfer", {"amount": 5000})).effect is Effect.REQUIRE_APPROVAL
