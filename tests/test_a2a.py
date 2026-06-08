"""Tests for signed inter-agent (A2A) messages (ASI07)."""

from __future__ import annotations

from datetime import timedelta

import pytest

from capguard import (
    A2AChannel,
    A2AError,
    AgentIdentity,
    AgentMessage,
    Capability,
    HMACSigner,
)


def _channel():
    return A2AChannel(HMACSigner(b"a2a-secret"))


def _agent(caps=()):
    return AgentIdentity(id="planner", allowed_capabilities=list(caps))


# --------------------------------------------------------------------------- #
# authenticity + integrity
# --------------------------------------------------------------------------- #
def test_sign_and_verify_roundtrip():
    ch = _channel()
    sender = _agent([Capability.network_http(domains=["api.corp.com"])])
    msg = ch.send(sender=sender, recipient="worker", intent="fetch report",
                  payload={"url": "https://api.corp.com/r"},
                  capabilities=[Capability.network_http(domains=["api.corp.com"])])
    verified = ch.verify(msg, expected_recipient="worker")
    assert verified.sender == "planner" and verified.intent == "fetch report"


def test_tampered_payload_is_rejected():
    ch = _channel()
    msg = ch.send(sender=_agent(), recipient="worker", intent="x", payload={"amount": 10})
    msg.payload["amount"] = 1_000_000  # tamper after signing
    with pytest.raises(A2AError):
        ch.verify(msg)


def test_forged_signature_rejected():
    ch = _channel()
    msg = ch.send(sender=_agent(), recipient="w", intent="x")
    msg.signature = "deadbeef"
    with pytest.raises(A2AError):
        ch.verify(msg)


def test_wrong_signer_rejected():
    sender = _agent()
    msg = A2AChannel(HMACSigner(b"key-A")).send(sender=sender, recipient="w", intent="x")
    with pytest.raises(A2AError):
        A2AChannel(HMACSigner(b"key-B")).verify(msg)   # different secret


# --------------------------------------------------------------------------- #
# expiry, recipient, replay
# --------------------------------------------------------------------------- #
def test_expired_message_rejected():
    ch = _channel()
    msg = ch.send(sender=_agent(), recipient="w", intent="x")
    msg.expires_at = msg.issued_at - timedelta(seconds=1)
    msg.signature = HMACSigner(b"a2a-secret").sign(msg.canonical())  # re-sign so only expiry fails
    with pytest.raises(A2AError):
        ch.verify(msg)


def test_wrong_recipient_rejected():
    ch = _channel()
    msg = ch.send(sender=_agent(), recipient="worker-A", intent="x")
    with pytest.raises(A2AError):
        ch.verify(msg, expected_recipient="worker-B")


def test_replay_is_rejected():
    ch = _channel()
    msg = ch.send(sender=_agent(), recipient="w", intent="x")
    ch.verify(msg)                       # first use ok
    with pytest.raises(A2AError):
        ch.verify(msg)                   # replay -> rejected


# --------------------------------------------------------------------------- #
# capability attenuation across the hop
# --------------------------------------------------------------------------- #
def test_sender_cannot_exercise_capability_it_lacks():
    ch = _channel()
    sender = _agent([Capability.network_http(domains=["api.corp.com"])])
    with pytest.raises(A2AError):
        ch.send(sender=sender, recipient="w", intent="x",
                capabilities=[Capability.shell_exec(allowlist=["rm"])])  # not held


def test_verify_rejects_over_claimed_authority():
    """Even a validly-signed message can't exceed the sender's known authority."""
    ch = _channel()
    # sender legitimately holds broad net access and signs a message exercising it
    broad = _agent([Capability.network_http(domains=["*"])])
    msg = ch.send(sender=broad, recipient="w", intent="x",
                  capabilities=[Capability.network_http(domains=["evil.com"])])
    # but the receiver only recognizes a narrower authority for 'planner'
    narrow_authority = AgentIdentity(id="planner",
                                     allowed_capabilities=[Capability.network_http(domains=["api.corp.com"])])
    with pytest.raises(A2AError):
        ch.verify(msg, sender_authority=narrow_authority)


def test_sender_authority_identity_must_match():
    ch = _channel()
    msg = ch.send(sender=_agent(), recipient="w", intent="x")
    with pytest.raises(A2AError):
        ch.verify(msg, sender_authority=AgentIdentity(id="someone-else"))


# --------------------------------------------------------------------------- #
# provenance + serialization
# --------------------------------------------------------------------------- #
def test_inbound_payload_is_tainted_by_default():
    ch = _channel()
    msg = ch.send(sender=_agent(), recipient="w", intent="x",
                  payload={"text": "do the thing", "url": "https://x"})
    prov = ch.provenance_for(msg)
    assert prov == {"text": "untrusted_tool", "url": "untrusted_tool"}
    trusted = ch.provenance_for(msg, trusted_senders={"planner"})
    assert trusted == {"text": "trusted", "url": "trusted"}


def test_dict_roundtrip_preserves_verification():
    ch = _channel()
    msg = ch.send(sender=_agent([Capability.custom("x")]), recipient="w",
                  intent="do x", payload={"a": 1}, capabilities=[Capability.custom("x")])
    restored = AgentMessage.from_dict(msg.to_dict())
    assert ch.verify(restored, expected_recipient="w").intent == "do x"
