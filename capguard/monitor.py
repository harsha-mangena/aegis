"""Rogue-agent detection + circuit breaker (ASI10, with ASI08 blast-radius).

The hash-chained audit stream is not just forensic evidence — it is a live
behavioral signal. A compromised or malfunctioning agent rarely fails on a
single call; it *drifts*: a burst of calls, a run of denials as it probes the
policy, a sudden fan-out across sensitive sinks, or a reach for a tool it has
never used. ASI10 (Rogue Agents) is about catching that pattern and stopping it.

This module does it **deterministically** — sliding-window thresholds over the
audit events, not an ML model — so it stays true to CapGuard's deterministic-
first principle and cannot itself be "talked past." A breach trips a per-agent
:class:`CircuitBreaker` (kill switch); the runtime then fail-closes every
subsequent call from that agent until it is reset or a cooldown elapses. That is
also the ASI08 answer: a tripped breaker caps blast radius and stops a cascading
failure from fanning out.

Wiring: :class:`BehaviorMonitor` is an ``AuditSink`` — drop it in as (or in front
of) your real sink. It observes every decision, detects anomalies, trips the
breaker, and forwards the event downstream unchanged.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Callable, Deque, Dict, FrozenSet, List, Optional, Tuple

from .audit import AuditEvent, AuditSink
from .core import PolicyDecision

# Denials produced *by* the breaker itself carry this error string. The monitor
# ignores them when counting, so a tripped breaker can't self-reinforce by
# generating the very denials that keep it tripped.
CIRCUIT_OPEN_ERROR = "circuit_breaker_open"


class AnomalyKind(str, Enum):
    CALL_RATE = "call_rate"            # too many calls in the window
    DENIAL_RATE = "denial_rate"        # a run of denials => probing / compromise
    BLAST_RADIUS = "blast_radius"      # too many distinct sensitive sinks touched
    NOVEL_TOOL = "novel_tool"          # a tool outside the agent's known baseline


@dataclass
class Anomaly:
    agent_id: str
    kind: AnomalyKind
    detail: str
    at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def __str__(self) -> str:
        return f"[{self.kind.value}] agent={self.agent_id!r}: {self.detail}"


@dataclass
class AnomalyPolicy:
    """Deterministic thresholds over a sliding window. ``0`` / ``None`` = off."""

    window_seconds: float = 60.0
    max_calls: int = 0                              # cap on total calls / window
    max_denials: int = 0                            # cap on DENY decisions / window
    max_distinct_sinks: int = 0                     # cap on distinct sink tools / window
    sink_tools: FrozenSet[str] = frozenset()        # which tools count as sinks
    baseline_tools: Optional[FrozenSet[str]] = None  # if set, any other tool is "novel"


class CircuitBreaker:
    """Per-agent kill switch. Thread-safe; optional auto-reset cooldown."""

    def __init__(self, cooldown_seconds: float = 0.0) -> None:
        self._cooldown = cooldown_seconds
        self._tripped_at: Dict[str, float] = {}
        self._reason: Dict[str, str] = {}
        self._lock = threading.Lock()

    def trip(self, agent_id: str, reason: str = "") -> None:
        with self._lock:
            self._tripped_at[agent_id] = time.monotonic()
            self._reason[agent_id] = reason

    def is_open(self, agent_id: str) -> bool:
        with self._lock:
            t = self._tripped_at.get(agent_id)
            if t is None:
                return False
            if self._cooldown and (time.monotonic() - t) >= self._cooldown:
                self._tripped_at.pop(agent_id, None)
                self._reason.pop(agent_id, None)
                return False
            return True

    def reason(self, agent_id: str) -> Optional[str]:
        with self._lock:
            return self._reason.get(agent_id)

    def reset(self, agent_id: str) -> None:
        with self._lock:
            self._tripped_at.pop(agent_id, None)
            self._reason.pop(agent_id, None)

    def tripped_agents(self) -> List[str]:
        with self._lock:
            return list(self._tripped_at)


class BehaviorMonitor:
    """An ``AuditSink`` that detects rogue behavior and trips a breaker."""

    def __init__(
        self,
        policy: AnomalyPolicy,
        *,
        breaker: Optional[CircuitBreaker] = None,
        downstream: Optional[AuditSink] = None,
        on_anomaly: Optional[Callable[[Anomaly], None]] = None,
    ) -> None:
        self._p = policy
        self._cb = breaker
        self._down = downstream
        self._hook = on_anomaly
        self._win: Dict[str, Deque[Tuple[float, AuditEvent]]] = {}
        self._anomalies: List[Anomaly] = []
        self._lock = threading.Lock()

    # AuditSink interface --------------------------------------------------- #
    def __call__(self, event: AuditEvent) -> None:
        self._observe(event)
        if self._down is not None:
            self._down(event)

    def _observe(self, event: AuditEvent) -> None:
        if event.error == CIRCUIT_OPEN_ERROR:
            return  # don't let the breaker's own denials feed detection
        now = time.monotonic()
        cutoff = now - self._p.window_seconds
        with self._lock:
            dq = self._win.setdefault(event.agent_id, deque())
            dq.append((now, event))
            while dq and dq[0][0] < cutoff:
                dq.popleft()
            found = self._detect(event.agent_id, dq, event)
            self._anomalies.extend(found)
        for a in found:
            if self._cb is not None:
                self._cb.trip(a.agent_id, str(a))
            if self._hook is not None:
                self._hook(a)

    def _detect(self, agent_id: str, dq: Deque[Tuple[float, AuditEvent]],
                latest: AuditEvent) -> List[Anomaly]:
        p = self._p
        out: List[Anomaly] = []
        calls = len(dq)
        if p.max_calls and calls > p.max_calls:
            out.append(Anomaly(agent_id, AnomalyKind.CALL_RATE,
                               f"{calls} calls in {p.window_seconds:g}s (> {p.max_calls})"))
        if p.max_denials:
            denials = sum(1 for _, e in dq if e.decision is PolicyDecision.DENY)
            if denials > p.max_denials:
                out.append(Anomaly(agent_id, AnomalyKind.DENIAL_RATE,
                                   f"{denials} denials in window (> {p.max_denials}) — probing"))
        if p.max_distinct_sinks and p.sink_tools:
            sinks = {e.tool_name for _, e in dq if e.tool_name in p.sink_tools}
            if len(sinks) > p.max_distinct_sinks:
                out.append(Anomaly(agent_id, AnomalyKind.BLAST_RADIUS,
                                   f"{len(sinks)} distinct sinks {sorted(sinks)} (> {p.max_distinct_sinks})"))
        if p.baseline_tools is not None and latest.tool_name not in p.baseline_tools:
            out.append(Anomaly(agent_id, AnomalyKind.NOVEL_TOOL,
                               f"tool {latest.tool_name!r} is outside the agent baseline"))
        return out

    @property
    def anomalies(self) -> List[Anomaly]:
        return list(self._anomalies)
