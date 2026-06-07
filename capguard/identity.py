"""Verifiable agent identity + delegation attenuation (ASI03).

Until now an ``AgentIdentity`` was a *self-asserted* string at the proxy/gateway
boundary — the last "trust me" hole in the runtime. Anyone who could reach the
boundary could claim any agent id and its capabilities. This module closes that:
an identity becomes a **signed assertion** binding an agent to a human
``principal`` and a ``tenant``, carrying its capabilities and a short expiry,
which a verifier checks before the runtime will act on it.

It also models the agentic-2026 reality that agents *delegate* to sub-agents
(A2A). Delegation here is **attenuation by construction**: a child assertion can
only carry capabilities that are already *covered* by the parent's (reusing
``Capability.covers``), the chain depth is recorded, and the whole thing is
re-signed. Authority can only ever narrow down a delegation chain — there is no
code path that lets a sub-agent hold more than its delegator. This aligns with
the SPIFFE/JWT-SVID and AIP (Agent Identity Protocol) direction without taking a
hard crypto dependency.

Signing is pluggable:
  * ``HMACSigner`` (stdlib, symmetric) — zero-dependency default, for a single
    trust domain (issuer == verifier).
  * ``Ed25519Signer`` (optional, needs ``cryptography``) — asymmetric, so a
    verifier holding only the public key can check assertions minted elsewhere.
    This is the cross-trust-domain / SPIFFE-style mode.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Protocol

from .core import AgentIdentity, Capability


class IdentityError(PermissionError):
    """Raised when an identity assertion is missing, invalid, or over-broad."""


# --------------------------------------------------------------------------- #
# Signers / verifiers
# --------------------------------------------------------------------------- #
class Signer(Protocol):
    alg: str
    def sign(self, payload: bytes) -> str: ...
    def verify(self, payload: bytes, signature: str) -> bool: ...


class HMACSigner:
    """Symmetric HMAC-SHA256 signer/verifier. Issuer and verifier share a key."""

    alg = "HMAC-SHA256"

    def __init__(self, secret: Optional[bytes] = None) -> None:
        self._secret = secret or secrets.token_bytes(32)

    def sign(self, payload: bytes) -> str:
        return hmac.new(self._secret, payload, hashlib.sha256).hexdigest()

    def verify(self, payload: bytes, signature: str) -> bool:
        return hmac.compare_digest(signature, self.sign(payload))


class Ed25519Signer:
    """Asymmetric signer (optional ``cryptography`` dependency).

    Construct with a private key to issue+verify; construct a verifier-only
    instance from a public key with :meth:`verifier_from_public`.
    """

    alg = "Ed25519"

    def __init__(self, private_key: Any = None, public_key: Any = None) -> None:
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        except Exception as exc:  # noqa: BLE001
            raise IdentityError("Ed25519Signer requires the 'cryptography' package") from exc
        if private_key is None and public_key is None:
            private_key = Ed25519PrivateKey.generate()
        self._priv = private_key
        self._pub = public_key or (private_key.public_key() if private_key else None)

    def sign(self, payload: bytes) -> str:
        if self._priv is None:
            raise IdentityError("this Ed25519Signer has no private key (verify-only)")
        return base64.b64encode(self._priv.sign(payload)).decode()

    def verify(self, payload: bytes, signature: str) -> bool:
        from cryptography.exceptions import InvalidSignature
        try:
            self._pub.verify(base64.b64decode(signature), payload)
            return True
        except (InvalidSignature, Exception):  # noqa: BLE001
            return False


# --------------------------------------------------------------------------- #
# Assertion data model
# --------------------------------------------------------------------------- #
@dataclass
class IdentityClaims:
    agent_id: str
    principal: str               # the human / owning identity the agent acts for
    tenant: str
    capabilities: List[Capability] = field(default_factory=list)
    roles: List[str] = field(default_factory=list)
    issued_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc) + timedelta(hours=1))
    delegator: Optional[str] = None     # parent agent_id, if this was delegated
    depth: int = 0                      # delegation-chain depth (0 = root)

    def canonical(self) -> bytes:
        body = {
            "agent_id": self.agent_id,
            "principal": self.principal,
            "tenant": self.tenant,
            "capabilities": [c.model_dump(mode="json") for c in self.capabilities],
            "roles": sorted(self.roles),
            "issued_at": self.issued_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "delegator": self.delegator,
            "depth": self.depth,
        }
        return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()


@dataclass
class SignedIdentity:
    claims: IdentityClaims
    signature: str
    alg: str

    def is_expired(self, now: Optional[datetime] = None) -> bool:
        now = now or datetime.now(timezone.utc)
        return now >= self.claims.expires_at

    def to_dict(self) -> Dict[str, Any]:
        c = self.claims
        return {
            "claims": {
                "agent_id": c.agent_id, "principal": c.principal, "tenant": c.tenant,
                "capabilities": [cap.model_dump(mode="json") for cap in c.capabilities],
                "roles": c.roles,
                "issued_at": c.issued_at.isoformat(), "expires_at": c.expires_at.isoformat(),
                "delegator": c.delegator, "depth": c.depth,
            },
            "signature": self.signature, "alg": self.alg,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "SignedIdentity":
        c = d["claims"]
        claims = IdentityClaims(
            agent_id=c["agent_id"], principal=c["principal"], tenant=c["tenant"],
            capabilities=[Capability.model_validate(x) for x in c.get("capabilities", [])],
            roles=list(c.get("roles", [])),
            issued_at=datetime.fromisoformat(c["issued_at"]),
            expires_at=datetime.fromisoformat(c["expires_at"]),
            delegator=c.get("delegator"), depth=int(c.get("depth", 0)),
        )
        return cls(claims=claims, signature=d["signature"], alg=d["alg"])


# --------------------------------------------------------------------------- #
# Issuer + verifier
# --------------------------------------------------------------------------- #
class IdentityIssuer:
    def __init__(self, signer: Signer, default_ttl_seconds: int = 3600,
                 max_delegation_depth: int = 5) -> None:
        self._signer = signer
        self._ttl = default_ttl_seconds
        self._max_depth = max_delegation_depth

    def issue(
        self, *, agent_id: str, principal: str, tenant: str,
        capabilities: List[Capability], roles: Optional[List[str]] = None,
        ttl_seconds: Optional[int] = None,
    ) -> SignedIdentity:
        now = datetime.now(timezone.utc)
        claims = IdentityClaims(
            agent_id=agent_id, principal=principal, tenant=tenant,
            capabilities=list(capabilities), roles=list(roles or []),
            issued_at=now, expires_at=now + timedelta(seconds=ttl_seconds or self._ttl),
        )
        return SignedIdentity(claims=claims, signature=self._signer.sign(claims.canonical()),
                              alg=self._signer.alg)

    def delegate(
        self, parent: SignedIdentity, *, agent_id: str,
        capabilities: List[Capability], roles: Optional[List[str]] = None,
        ttl_seconds: Optional[int] = None,
    ) -> SignedIdentity:
        """Mint a sub-agent identity whose authority is a subset of ``parent``'s.

        Every requested child capability must be *covered* by some parent
        capability, the child cannot outlive the parent, and the chain depth is
        bounded. There is deliberately no path to widen authority here.
        """
        if not self._signer.verify(parent.claims.canonical(), parent.signature):
            raise IdentityError("parent identity signature is invalid")
        if parent.is_expired():
            raise IdentityError("parent identity has expired; cannot delegate")
        if parent.claims.depth + 1 > self._max_depth:
            raise IdentityError(f"delegation depth {parent.claims.depth + 1} exceeds max {self._max_depth}")
        for child_cap in capabilities:
            if not any(p.covers(child_cap) for p in parent.claims.capabilities):
                raise IdentityError(
                    f"delegated capability {child_cap.type.value!r} is not covered by the parent — "
                    "delegation may only attenuate authority"
                )
        now = datetime.now(timezone.utc)
        child_exp = now + timedelta(seconds=ttl_seconds or self._ttl)
        # a child must not outlive its parent
        child_exp = min(child_exp, parent.claims.expires_at)
        claims = IdentityClaims(
            agent_id=agent_id, principal=parent.claims.principal, tenant=parent.claims.tenant,
            capabilities=list(capabilities), roles=list(roles or []),
            issued_at=now, expires_at=child_exp,
            delegator=parent.claims.agent_id, depth=parent.claims.depth + 1,
        )
        return SignedIdentity(claims=claims, signature=self._signer.sign(claims.canonical()),
                              alg=self._signer.alg)


class IdentityVerifier:
    """Verifies a signed assertion and yields a runtime :class:`AgentIdentity`."""

    def __init__(self, signer: Signer, *, expected_tenant: Optional[str] = None) -> None:
        self._signer = signer
        self._tenant = expected_tenant

    def verify(self, assertion: SignedIdentity) -> AgentIdentity:
        if assertion.alg != self._signer.alg:
            raise IdentityError(f"unexpected signature alg {assertion.alg!r}")
        if not self._signer.verify(assertion.claims.canonical(), assertion.signature):
            raise IdentityError("identity signature is invalid (tampered or wrong key)")
        if assertion.is_expired():
            raise IdentityError("identity assertion has expired")
        if self._tenant is not None and assertion.claims.tenant != self._tenant:
            raise IdentityError(
                f"identity tenant {assertion.claims.tenant!r} != expected {self._tenant!r}")
        c = assertion.claims
        return AgentIdentity(id=c.agent_id, roles=list(c.roles),
                             allowed_capabilities=list(c.capabilities))
