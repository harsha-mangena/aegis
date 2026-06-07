"""Task / intent-scoped capability envelopes (P6).

Standing capabilities answer "may this agent ever use this tool?" That is still
too coarse for 2026: an agent authorized to *transfer money* can be hijacked into
transferring the wrong amount to the wrong person — every call is "in scope."
The research direction (PAuth — *Precise Task-Scoped Authorization*; intent-to-
execution integrity) is to authorize only the **concrete operations a specific
task implies**: not "transfer", but "transfer ≤ $100 to Bob, for this task,
expiring in 10 minutes."

A :class:`TaskScope` is that envelope. It names the exact tools allowed for one
task, pins per-argument constraints on each, carries the capabilities the task
needs (which must be a subset of the agent's standing grants — issuing can only
attenuate), and expires. It is signed (reusing the identity signer) so it is
tamper-evident and can travel across a proxy/delegation boundary. The runtime
enforces it *in addition to* the standing capability gate and policy DSL, so it
only ever tightens — least privilege, scoped to intent, just-in-time.
"""

from __future__ import annotations

import fnmatch
import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from .core import AgentIdentity, Capability
from .identity import Signer


class ConstraintOp(str, Enum):
    LE = "<="
    LT = "<"
    GE = ">="
    GT = ">"
    EQ = "=="
    NE = "!="
    IN = "in"
    MATCHES = "matches"     # fnmatch glob on a string


@dataclass
class ArgConstraint:
    """A serializable predicate on one concrete argument value."""

    arg: str
    op: ConstraintOp
    value: Any

    def check(self, actual: Any) -> bool:
        op = self.op
        try:
            if op is ConstraintOp.LE:
                return actual is not None and actual <= self.value
            if op is ConstraintOp.LT:
                return actual is not None and actual < self.value
            if op is ConstraintOp.GE:
                return actual is not None and actual >= self.value
            if op is ConstraintOp.GT:
                return actual is not None and actual > self.value
            if op is ConstraintOp.EQ:
                return actual == self.value
            if op is ConstraintOp.NE:
                return actual != self.value
            if op is ConstraintOp.IN:
                return actual in self.value
            if op is ConstraintOp.MATCHES:
                return isinstance(actual, str) and fnmatch.fnmatch(actual, str(self.value))
        except TypeError:
            return False
        return False

    def to_dict(self) -> Dict[str, Any]:
        return {"arg": self.arg, "op": self.op.value, "value": self.value}

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> "ArgConstraint":
        return cls(arg=d["arg"], op=ConstraintOp(d["op"]), value=d["value"])


@dataclass
class ToolScope:
    """One tool the task may call, plus the constraints every call must satisfy."""

    tool: str                                   # exact name or fnmatch glob
    constraints: List[ArgConstraint] = field(default_factory=list)

    def matches(self, tool_name: str) -> bool:
        return fnmatch.fnmatch(tool_name, self.tool)

    def check(self, kwargs: Mapping[str, Any]) -> Tuple[bool, str]:
        for c in self.constraints:
            if c.arg not in kwargs:
                return False, f"constrained argument {c.arg!r} is missing"
            if not c.check(kwargs[c.arg]):
                return False, f"argument {c.arg!r}={kwargs[c.arg]!r} violates {c.op.value} {c.value!r}"
        return True, ""

    def to_dict(self) -> Dict[str, Any]:
        return {"tool": self.tool, "constraints": [c.to_dict() for c in self.constraints]}

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> "ToolScope":
        return cls(tool=d["tool"],
                   constraints=[ArgConstraint.from_dict(c) for c in d.get("constraints", [])])


class TaskScopeError(PermissionError):
    pass


@dataclass
class TaskScope:
    task_id: str
    agent_id: str
    tools: List[ToolScope] = field(default_factory=list)
    capabilities: List[Capability] = field(default_factory=list)
    description: str = ""                         # the NL task, for audit/explainability
    issued_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc) + timedelta(minutes=10))
    signature: str = ""
    alg: str = ""

    # -- evaluation -------------------------------------------------------- #
    def is_expired(self, now: Optional[datetime] = None) -> bool:
        return (now or datetime.now(timezone.utc)) >= self.expires_at

    def _scope_for(self, tool_name: str) -> Optional[ToolScope]:
        for ts in self.tools:
            if ts.matches(tool_name):
                return ts
        return None

    def covers_capabilities(self, required: Sequence[Capability]) -> bool:
        """Every capability the tool needs must be covered by the task envelope."""
        if not self.capabilities:
            return True  # no capability narrowing declared; tool-list still applies
        return all(any(held.covers(r) for held in self.capabilities) for r in required)

    def check_call(self, tool_name: str, kwargs: Mapping[str, Any],
                   required_caps: Sequence[Capability] = ()) -> Tuple[bool, str]:
        if self.is_expired():
            return False, "task scope expired"
        ts = self._scope_for(tool_name)
        if ts is None:
            return False, f"tool {tool_name!r} is not in the task scope"
        if not self.covers_capabilities(required_caps):
            return False, f"task scope does not grant the capabilities {tool_name!r} requires"
        return ts.check(kwargs)

    # -- signing ----------------------------------------------------------- #
    def canonical(self) -> bytes:
        body = {
            "task_id": self.task_id,
            "agent_id": self.agent_id,
            "tools": [t.to_dict() for t in self.tools],
            "capabilities": [c.model_dump(mode="json") for c in self.capabilities],
            "description": self.description,
            "issued_at": self.issued_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
        }
        return json.dumps(body, sort_keys=True, separators=(",", ":"), default=str).encode()

    def verify(self, signer: Signer) -> bool:
        return bool(self.signature) and signer.verify(self.canonical(), self.signature)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "task_id": self.task_id, "agent_id": self.agent_id,
            "tools": [t.to_dict() for t in self.tools],
            "capabilities": [c.model_dump(mode="json") for c in self.capabilities],
            "description": self.description,
            "issued_at": self.issued_at.isoformat(), "expires_at": self.expires_at.isoformat(),
            "signature": self.signature, "alg": self.alg,
        }

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> "TaskScope":
        return cls(
            task_id=d["task_id"], agent_id=d["agent_id"],
            tools=[ToolScope.from_dict(t) for t in d.get("tools", [])],
            capabilities=[Capability.model_validate(c) for c in d.get("capabilities", [])],
            description=d.get("description", ""),
            issued_at=datetime.fromisoformat(d["issued_at"]),
            expires_at=datetime.fromisoformat(d["expires_at"]),
            signature=d.get("signature", ""), alg=d.get("alg", ""),
        )


class TaskScopeIssuer:
    """Mints signed, attenuated, time-boxed task scopes."""

    def __init__(self, signer: Optional[Signer] = None, default_ttl_seconds: int = 600) -> None:
        self._signer = signer
        self._ttl = default_ttl_seconds

    def issue(
        self,
        *,
        task_id: str,
        agent: AgentIdentity,
        tools: Sequence[ToolScope],
        capabilities: Optional[Sequence[Capability]] = None,
        description: str = "",
        ttl_seconds: Optional[int] = None,
    ) -> TaskScope:
        caps = list(capabilities or [])
        # attenuation: a task can never grant a capability the agent does not hold
        for cap in caps:
            if not agent.covers(cap):
                raise TaskScopeError(
                    f"task scope cannot grant {cap.type.value!r} — the agent does not hold it"
                )
        now = datetime.now(timezone.utc)
        scope = TaskScope(
            task_id=task_id, agent_id=agent.id, tools=list(tools), capabilities=caps,
            description=description, issued_at=now,
            expires_at=now + timedelta(seconds=ttl_seconds or self._ttl),
        )
        if self._signer is not None:
            scope.signature = self._signer.sign(scope.canonical())
            scope.alg = self._signer.alg
        return scope
