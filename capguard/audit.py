"""Tamper-evident audit log.

Each event is hash-chained to the previous one (``prev_hash`` + canonical
event body -> ``hash``). Any retroactive edit breaks the chain, which
``verify_chain`` detects. Optionally the chain head can be Ed25519-signed for
non-repudiation. This replaces the previous plain-append JSONL, which the
README incorrectly described as "tamper-proof".
"""

from __future__ import annotations

import hashlib
import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from pydantic import BaseModel, Field

from .core import PolicyDecision

GENESIS = "0" * 64


class AuditEvent(BaseModel):
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    agent_id: str
    tool_name: str
    decision: PolicyDecision
    effect: Optional[str] = None          # policy-DSL effect, if any
    params: Dict[str, Any] = Field(default_factory=dict)
    arg_provenance: Dict[str, str] = Field(default_factory=dict)  # arg -> trust label, for flow reconstruction
    result_digest: Optional[str] = None   # sha256 of result repr (no raw payload leak)
    error: Optional[str] = None
    request_id: Optional[str] = None
    prev_hash: str = GENESIS
    hash: Optional[str] = None

    def body_for_hash(self) -> bytes:
        body = self.model_dump(mode="json", exclude={"hash"})
        return json.dumps(body, sort_keys=True, separators=(",", ":"), default=str).encode()

    def seal(self, prev_hash: str) -> "AuditEvent":
        self.prev_hash = prev_hash
        self.hash = hashlib.sha256(self.body_for_hash()).hexdigest()
        return self


def digest(value: Any) -> str:
    return hashlib.sha256(repr(value).encode()).hexdigest()


class HashChainedSink:
    """Thread-safe JSONL sink that maintains a hash chain across events."""

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._head = self._recover_head()

    def _recover_head(self) -> str:
        if not self._path.exists():
            return GENESIS
        last = GENESIS
        for line in self._path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                last = json.loads(line)["hash"]
        return last

    def __call__(self, event: AuditEvent) -> None:
        with self._lock:
            event.seal(self._head)
            self._head = event.hash or GENESIS
            with self._path.open("a", encoding="utf-8") as f:
                f.write(event.model_dump_json() + "\n")

    @property
    def head(self) -> str:
        return self._head


class MemorySink:
    """In-memory hash-chained sink, handy for tests."""

    def __init__(self) -> None:
        self.events: List[AuditEvent] = []
        self._head = GENESIS
        self._lock = threading.Lock()

    def __call__(self, event: AuditEvent) -> None:
        with self._lock:
            event.seal(self._head)
            self._head = event.hash or GENESIS
            self.events.append(event)


class PrintSink:
    def __init__(self) -> None:
        self._head = GENESIS

    def __call__(self, event: AuditEvent) -> None:
        event.seal(self._head)
        self._head = event.hash or GENESIS
        print(f"[AUDIT] {event.model_dump_json()}")


def verify_chain(events: List[AuditEvent]) -> bool:
    """Return True iff the hash chain is intact and well-formed."""
    prev = GENESIS
    for ev in events:
        if ev.prev_hash != prev:
            return False
        recomputed = hashlib.sha256(ev.body_for_hash()).hexdigest()
        if recomputed != ev.hash:
            return False
        prev = ev.hash
    return True


def verify_file(path: str | Path) -> bool:
    events = [
        AuditEvent.model_validate_json(line)
        for line in Path(path).read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    return verify_chain(events)


AuditSink = Callable[[AuditEvent], None]
