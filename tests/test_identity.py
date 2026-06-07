"""Tests for verifiable identity + delegation attenuation (P2 / ASI03)."""

from __future__ import annotations

from datetime import timedelta

import pytest

from capguard import (
    AgentIdentity,
    Capability,
    HMACSigner,
    IdentityError,
    IdentityIssuer,
    IdentityVerifier,
    MCPGuard,
    MCPToolDef,
    Severity,
    SignedIdentity,
)
from capguard.mcp_guard import explicit_mapper
from capguard.mcp_proxy import InProcessDownstream, MCPProxy


def _issuer_verifier(tenant="acme"):
    signer = HMACSigner(b"shared-secret")
    return IdentityIssuer(signer), IdentityVerifier(signer, expected_tenant=tenant)


# --------------------------------------------------------------------------- #
# issue / verify
# --------------------------------------------------------------------------- #
def test_issue_and_verify_roundtrip():
    issuer, verifier = _issuer_verifier()
    assertion = issuer.issue(agent_id="bot", principal="alice", tenant="acme",
                             capabilities=[Capability.network_http(domains=["a.com"])],
                             roles=["assistant"])
    agent = verifier.verify(assertion)
    assert isinstance(agent, AgentIdentity)
    assert agent.id == "bot" and agent.roles == ["assistant"]
    assert agent.covers(Capability.network_http(domains=["a.com"]))


def test_tampered_signature_is_rejected():
    issuer, verifier = _issuer_verifier()
    a = issuer.issue(agent_id="bot", principal="alice", tenant="acme",
                     capabilities=[Capability.custom("x")])
    a.signature = "deadbeef"
    with pytest.raises(IdentityError):
        verifier.verify(a)


def test_tampered_capabilities_are_rejected():
    """Escalating caps after signing must break verification."""
    issuer, verifier = _issuer_verifier()
    a = issuer.issue(agent_id="bot", principal="alice", tenant="acme",
                     capabilities=[Capability.custom("read")])
    a.claims.capabilities.append(Capability.shell_exec(allowlist=["*"]))  # smuggle authority
    with pytest.raises(IdentityError):
        verifier.verify(a)


def test_expired_identity_is_rejected():
    issuer, verifier = _issuer_verifier()
    a = issuer.issue(agent_id="bot", principal="alice", tenant="acme",
                     capabilities=[Capability.custom("x")], ttl_seconds=1)
    a.claims.expires_at = a.claims.issued_at - timedelta(seconds=1)  # force-expire
    a.signature = HMACSigner(b"shared-secret").sign(a.claims.canonical())  # re-sign so only expiry fails
    with pytest.raises(IdentityError):
        verifier.verify(a)


def test_wrong_tenant_is_rejected():
    issuer, verifier = _issuer_verifier(tenant="acme")
    a = issuer.issue(agent_id="bot", principal="alice", tenant="evilcorp",
                     capabilities=[Capability.custom("x")])
    with pytest.raises(IdentityError):
        verifier.verify(a)


def test_dict_roundtrip():
    issuer, verifier = _issuer_verifier()
    a = issuer.issue(agent_id="bot", principal="alice", tenant="acme",
                     capabilities=[Capability.network_http(domains=["a.com"]),
                                   Capability.file_read(paths=["/tmp/*"])])
    b = SignedIdentity.from_dict(a.to_dict())
    agent = verifier.verify(b)
    assert agent.covers(Capability.file_read(paths=["/tmp/*"]))


# --------------------------------------------------------------------------- #
# delegation attenuation
# --------------------------------------------------------------------------- #
def test_delegation_can_only_attenuate():
    issuer, verifier = _issuer_verifier()
    parent = issuer.issue(agent_id="orchestrator", principal="alice", tenant="acme",
                          capabilities=[Capability.network_http(domains=["a.com", "b.com"])])
    # OK: a subset of the parent's network authority
    child = issuer.delegate(parent, agent_id="worker",
                            capabilities=[Capability.network_http(domains=["a.com"])])
    assert child.claims.delegator == "orchestrator"
    assert child.claims.depth == 1
    cagent = verifier.verify(child)
    assert cagent.covers(Capability.network_http(domains=["a.com"]))
    assert not cagent.covers(Capability.network_http(domains=["b.com", "c.com"]))


def test_delegation_cannot_expand_authority():
    issuer, _ = _issuer_verifier()
    parent = issuer.issue(agent_id="orchestrator", principal="alice", tenant="acme",
                          capabilities=[Capability.network_http(domains=["a.com"])])
    with pytest.raises(IdentityError):
        issuer.delegate(parent, agent_id="worker",
                        capabilities=[Capability.network_http(domains=["a.com", "evil.com"])])
    with pytest.raises(IdentityError):
        issuer.delegate(parent, agent_id="worker",
                        capabilities=[Capability.shell_exec(allowlist=["rm"])])  # different cap entirely


def test_delegated_child_cannot_outlive_parent():
    issuer, _ = _issuer_verifier()
    parent = issuer.issue(agent_id="p", principal="alice", tenant="acme",
                          capabilities=[Capability.custom("x")], ttl_seconds=10)
    child = issuer.delegate(parent, agent_id="c", capabilities=[Capability.custom("x")],
                            ttl_seconds=10_000)  # ask for much longer
    assert child.claims.expires_at <= parent.claims.expires_at


def test_delegation_depth_is_bounded():
    signer = HMACSigner(b"k")
    issuer = IdentityIssuer(signer, max_delegation_depth=1)
    parent = issuer.issue(agent_id="p", principal="a", tenant="t",
                          capabilities=[Capability.custom("x")])
    child = issuer.delegate(parent, agent_id="c", capabilities=[Capability.custom("x")])
    with pytest.raises(IdentityError):
        issuer.delegate(child, agent_id="gc", capabilities=[Capability.custom("x")])


# --------------------------------------------------------------------------- #
# AgentIdentity.attenuate (JIT / zero standing perms)
# --------------------------------------------------------------------------- #
def test_attenuate_drops_authority_ok():
    agent = AgentIdentity(id="bot", allowed_capabilities=[
        Capability.network_http(domains=["a.com", "b.com"]),
        Capability.file_read(paths=["/tmp/*"]),
    ])
    narrow = agent.attenuate([Capability.network_http(domains=["a.com"])])
    assert narrow.covers(Capability.network_http(domains=["a.com"]))
    assert not narrow.covers(Capability.file_read(paths=["/tmp/*"]))


def test_attenuate_cannot_expand():
    agent = AgentIdentity(id="bot", allowed_capabilities=[Capability.network_http(domains=["a.com"])])
    with pytest.raises(PermissionError):
        agent.attenuate([Capability.network_http(domains=["a.com", "evil.com"])])


# --------------------------------------------------------------------------- #
# proxy boundary enforcement
# --------------------------------------------------------------------------- #
def _proxy_with_identity(require: bool):
    issuer, verifier = _issuer_verifier()
    tools = [MCPToolDef(server_id="s1", name="echo", description="echo a string", input_schema={})]
    ds = InProcessDownstream("s1", tools, {"echo": lambda text="": f"echo:{text}"})
    guard = MCPGuard(capability_mapper=explicit_mapper(
        {"echo": ([Capability.custom("echo")], Severity.LOW)}))
    anon = AgentIdentity(id="anon", allowed_capabilities=[])
    proxy = MCPProxy(guard=guard, agent=anon, downstreams=[ds],
                     identity_verifier=verifier, require_signed_identity=require)
    return issuer, proxy


def _call(proxy, ident_dict=None):
    params = {"name": "s1__echo", "arguments": {"text": "hi"}}
    if ident_dict is not None:
        params["_capguard_identity"] = ident_dict
    return proxy.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": params})


def test_proxy_denies_unsigned_call_when_identity_required():
    _, proxy = _proxy_with_identity(require=True)
    resp = _call(proxy, ident_dict=None)
    assert resp["result"]["isError"] is True
    assert "signed identity" in resp["result"]["content"][0]["text"].lower()


def test_proxy_allows_valid_signed_identity():
    issuer, proxy = _proxy_with_identity(require=True)
    ident = issuer.issue(agent_id="bot", principal="alice", tenant="acme",
                         capabilities=[Capability.custom("echo")])
    resp = _call(proxy, ident_dict=ident.to_dict())
    assert resp["result"]["isError"] is False
    assert "echo:hi" in resp["result"]["content"][0]["text"]


def test_proxy_rejects_tampered_identity():
    issuer, proxy = _proxy_with_identity(require=True)
    ident = issuer.issue(agent_id="bot", principal="alice", tenant="acme",
                         capabilities=[Capability.custom("echo")])
    d = ident.to_dict()
    d["claims"]["capabilities"].append(Capability.shell_exec(allowlist=["*"]).model_dump(mode="json"))
    resp = _call(proxy, ident_dict=d)
    assert resp["result"]["isError"] is True
    assert "identity verification failed" in resp["result"]["content"][0]["text"].lower()
