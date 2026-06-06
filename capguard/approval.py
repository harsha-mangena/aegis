"""Replay-safe human-approval tokens.

The previous approval queue replayed the original request to the gateway, but
the gateway re-evaluated policy and returned ``approval_required`` again — an
unbreakable loop — and nothing bound the approval to the *exact* arguments that
were reviewed (a classic time-of-check/time-of-use hole: approve a $10 transfer,
replay a $10,000 one).

This module fixes both:

  * An approval is a token bound to ``(agent_id, tool_name, args_digest)`` plus
    an expiry and a single-use nonce. Replaying with a different argument set
    fails because the digest will not match.
  * The token is HMAC-signed for integrity and tracked in a store for
    single-use / anti-replay. A consumed or expired token cannot be reused.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, Mapping, Optional


def args_digest(args: Mapping[str, Any]) -> str:
    canonical = json.dumps(dict(args), sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()


class ApprovalStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    CONSUMED = "consumed"
    EXPIRED = "expired"


@dataclass
class ApprovalToken:
    id: str
    agent_id: str
    tool_name: str
    args_digest: str
    status: ApprovalStatus
    created_at: datetime
    expires_at: datetime
    signature: str = ""
    reason: Optional[str] = None

    def signing_payload(self) -> bytes:
        body = {
            "id": self.id,
            "agent_id": self.agent_id,
            "tool_name": self.tool_name,
            "args_digest": self.args_digest,
            "expires_at": self.expires_at.isoformat(),
        }
        return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()

    def is_expired(self, now: Optional[datetime] = None) -> bool:
        now = now or datetime.now(timezone.utc)
        return now >= self.expires_at


class ApprovalStore:
    """In-memory, thread-safe approval store with HMAC integrity.

    A persistent/distributed backend (the FastAPI approvals service) implements
    the same interface; the SDK logic does not change.
    """

    def __init__(self, secret: Optional[bytes] = None, default_ttl_seconds: int = 900) -> None:
        self._secret = secret or secrets.token_bytes(32)
        self._ttl = default_ttl_seconds
        self._tokens: Dict[str, ApprovalToken] = {}
        self._lock = threading.Lock()

    def _sign(self, token: ApprovalToken) -> str:
        return hmac.new(self._secret, token.signing_payload(), hashlib.sha256).hexdigest()

    def issue(
        self,
        *,
        agent_id: str,
        tool_name: str,
        args: Mapping[str, Any],
        ttl_seconds: Optional[int] = None,
        reason: Optional[str] = None,
    ) -> ApprovalToken:
        now = datetime.now(timezone.utc)
        token = ApprovalToken(
            id=secrets.token_urlsafe(16),
            agent_id=agent_id,
            tool_name=tool_name,
            args_digest=args_digest(args),
            status=ApprovalStatus.PENDING,
            created_at=now,
            expires_at=now + timedelta(seconds=ttl_seconds or self._ttl),
            reason=reason,
        )
        token.signature = self._sign(token)
        with self._lock:
            self._tokens[token.id] = token
        return token

    def approve(self, token_id: str, reason: Optional[str] = None) -> ApprovalToken:
        return self._transition(token_id, ApprovalStatus.APPROVED, reason)

    def reject(self, token_id: str, reason: Optional[str] = None) -> ApprovalToken:
        return self._transition(token_id, ApprovalStatus.REJECTED, reason)

    def _transition(self, token_id: str, status: ApprovalStatus, reason: Optional[str]) -> ApprovalToken:
        with self._lock:
            tok = self._tokens.get(token_id)
            if tok is None:
                raise KeyError(f"approval {token_id!r} not found")
            if tok.status is not ApprovalStatus.PENDING:
                raise ValueError(f"approval {token_id!r} is {tok.status.value}, not pending")
            if tok.is_expired():
                tok.status = ApprovalStatus.EXPIRED
                raise ValueError(f"approval {token_id!r} has expired")
            tok.status = status
            tok.reason = reason
            return tok

    def verify_and_consume(
        self, *, token_id: str, agent_id: str, tool_name: str, args: Mapping[str, Any]
    ) -> bool:
        """Return True iff the token is approved, matches exactly, and is fresh.

        On success the token is single-use consumed (anti-replay).
        """
        with self._lock:
            tok = self._tokens.get(token_id)
            if tok is None:
                return False
            if not hmac.compare_digest(tok.signature, self._sign(tok)):
                return False  # tampered
            if tok.status is not ApprovalStatus.APPROVED:
                return False
            if tok.is_expired():
                tok.status = ApprovalStatus.EXPIRED
                return False
            if tok.agent_id != agent_id or tok.tool_name != tool_name:
                return False
            if tok.args_digest != args_digest(args):
                return False  # arguments differ from what was approved (TOCTOU defense)
            tok.status = ApprovalStatus.CONSUMED
            return True

    def get(self, token_id: str) -> Optional[ApprovalToken]:
        return self._tokens.get(token_id)
