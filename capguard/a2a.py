"""Signed inter-agent (A2A) messages — secure agent-to-agent communication (ASI07).

Google's A2A protocol standardizes agent-to-agent messaging via *AgentCards*, but
(per the 2026 security analyses) it "does not mandate how those cards are verified
for authenticity," delegates credential management to implementers, and — like the
IETF Transaction-Tokens draft — "defines no scope attenuation semantics." The
consequences are impersonation, card/message tampering, replay, and the cross-agent
confused deputy: *an agent with broad permissions leveraged by another agent to do
something it wasn't intended to.*

This module is the missing control layer, reusing CapGuard's identity signer and
capability model:

  * **Authenticity & integrity** — every :class:`AgentMessage` is signed; a tampered
    field or forged sender fails verification.
  * **Anti-replay** — each message carries a single-use nonce + expiry; replaying it
    is rejected.
  * **Capability attenuation across the hop** — a message carries the capabilities
    the sender exercises; ``send`` refuses to claim authority the sender does not
    hold, and ``verify`` re-checks every requested capability against the sender's
    known authority. A sub-agent can never be coerced into exercising more than its
    delegator granted — the scope-attenuation semantics the wire protocols omit.
  * **Provenance** — inbound payloads are tainted ``untrusted_tool`` by default, so
    data arriving from another agent is gated at sinks just like web/tool output.
"""

from __future__ import annotations

import json
import secrets
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Mapping, Optional

from .core import AgentIdentity, Capability
from .identity import Signer


class A2AError(PermissionError):
    """Raised when an inter-agent message is forged, tampered, replayed, expired,
    addressed elsewhere, or over-claims authority."""


@dataclass
class AgentMessage:
    id: str
    sender: str
    recipient: str
    intent: str
    payload: Dict[str, Any] = field(default_factory=dict)
    capabilities: List[Capability] = field(default_factory=list)
    issued_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc) + timedelta(minutes=5))
    signature: str = ""
    alg: str = ""

    def is_expired(self, now: Optional[datetime] = None) -> bool:
        return (now or datetime.now(timezone.utc)) >= self.expires_at

    def canonical(self) -> bytes:
        body = {
            "id": self.id, "sender": self.sender, "recipient": self.recipient,
            "intent": self.intent, "payload": self.payload,
            "capabilities": [c.model_dump(mode="json") for c in self.capabilities],
            "issued_at": self.issued_at.isoformat(), "expires_at": self.expires_at.isoformat(),
        }
        return json.dumps(body, sort_keys=True, separators=(",", ":"), default=str).encode()

    def to_dict(self) -> Dict[str, Any]:
        d = {
            "id": self.id, "sender": self.sender, "recipient": self.recipient,
            "intent": self.intent, "payload": self.payload,
            "capabilities": [c.model_dump(mode="json") for c in self.capabilities],
            "issued_at": self.issued_at.isoformat(), "expires_at": self.expires_at.isoformat(),
            "signature": self.signature, "alg": self.alg,
        }
        return d

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> "AgentMessage":
        return cls(
            id=d["id"], sender=d["sender"], recipient=d["recipient"], intent=d["intent"],
            payload=dict(d.get("payload", {})),
            capabilities=[Capability.model_validate(c) for c in d.get("capabilities", [])],
            issued_at=datetime.fromisoformat(d["issued_at"]),
            expires_at=datetime.fromisoformat(d["expires_at"]),
            signature=d.get("signature", ""), alg=d.get("alg", ""),
        )


class _NonceStore:
    """In-memory single-use nonce store with lazy expiry pruning (anti-replay)."""

    def __init__(self) -> None:
        self._seen: Dict[str, float] = {}
        self._lock = threading.Lock()

    def consume(self, nonce: str, ttl_seconds: float) -> bool:
        now = time.monotonic()
        with self._lock:
            # prune expired
            for k in [k for k, exp in self._seen.items() if exp <= now]:
                self._seen.pop(k, None)
            if nonce in self._seen:
                return False  # replay
            self._seen[nonce] = now + ttl_seconds
            return True


class A2AChannel:
    """Signs outbound and verifies inbound agent-to-agent messages."""

    def __init__(self, signer: Signer, *, ttl_seconds: int = 300,
                 nonce_store: Optional[_NonceStore] = None) -> None:
        self._signer = signer
        self._ttl = ttl_seconds
        self._nonces = nonce_store or _NonceStore()

    # -- send -------------------------------------------------------------- #
    def send(self, *, sender: AgentIdentity, recipient: str, intent: str,
             payload: Optional[Mapping[str, Any]] = None,
             capabilities: Optional[List[Capability]] = None,
             ttl_seconds: Optional[int] = None) -> AgentMessage:
        caps = list(capabilities or [])
        # attenuation at origin: a message cannot exercise authority the sender lacks
        for cap in caps:
            if not sender.covers(cap):
                raise A2AError(
                    f"sender {sender.id!r} cannot exercise capability "
                    f"{cap.type.value!r} it does not hold")
        now = datetime.now(timezone.utc)
        msg = AgentMessage(
            id=secrets.token_urlsafe(16), sender=sender.id, recipient=recipient,
            intent=intent, payload=dict(payload or {}), capabilities=caps,
            issued_at=now, expires_at=now + timedelta(seconds=ttl_seconds or self._ttl),
        )
        msg.signature = self._signer.sign(msg.canonical())
        msg.alg = self._signer.alg
        return msg

    # -- verify ------------------------------------------------------------ #
    def verify(self, msg: AgentMessage, *, expected_recipient: Optional[str] = None,
               sender_authority: Optional[AgentIdentity] = None,
               consume: bool = True) -> AgentMessage:
        if msg.alg != self._signer.alg:
            raise A2AError(f"unexpected signature alg {msg.alg!r}")
        if not msg.signature or not self._signer.verify(msg.canonical(), msg.signature):
            raise A2AError("inter-agent message signature is invalid (forged or tampered)")
        if msg.is_expired():
            raise A2AError("inter-agent message has expired")
        if expected_recipient is not None and msg.recipient != expected_recipient:
            raise A2AError(
                f"message addressed to {msg.recipient!r}, not {expected_recipient!r}")
        # attenuation across the hop: every exercised capability must be covered by
        # the sender's known authority (defeats the cross-agent confused deputy).
        if sender_authority is not None:
            if sender_authority.id != msg.sender:
                raise A2AError("sender_authority identity does not match the message sender")
            for cap in msg.capabilities:
                if not sender_authority.covers(cap):
                    raise A2AError(
                        f"message from {msg.sender!r} over-claims capability "
                        f"{cap.type.value!r} beyond its authority")
        # anti-replay: single-use nonce (do this last, only for otherwise-valid msgs)
        if consume:
            ttl = max(1.0, (msg.expires_at - datetime.now(timezone.utc)).total_seconds())
            if not self._nonces.consume(msg.id, ttl):
                raise A2AError("inter-agent message replay detected (nonce already used)")
        return msg

    # -- provenance helper ------------------------------------------------- #
    def provenance_for(self, msg: AgentMessage, *, trusted_senders=()) -> Dict[str, str]:
        """Default taint for an inbound message's payload args.

        Data from another agent is ``untrusted_tool`` unless the sender is on the
        explicit trusted list, so downstream sinks fed by it are gated by the DSL.
        """
        label = "trusted" if msg.sender in set(trusted_senders) else "untrusted_tool"
        return {k: label for k in msg.payload}
