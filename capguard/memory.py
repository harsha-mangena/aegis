"""Provenance-preserving memory / RAG store (ASI06: Memory & Context Poisoning).

Agent memory is the quietest poisoning vector. A tool reads attacker-controlled
web content, the agent "remembers" it, and days later that text is recalled and
acted on — looking, by then, like trusted first-party context. The danger is not
the write itself but the **laundering**: an untrusted value goes into memory and
comes back out with its taint forgotten.

This module makes memory *provenance-preserving*. Every write records the value's
information-flow label alongside it; every read re-applies that label to the
value in the :class:`~capguard.provenance.ProvenanceTracker`, so taint survives
the round trip and the downstream sink rules (``Taint``/``Flow``) still fire on
recalled content. That turns the laundering hole into a closed loop with no extra
work from the agent. An optional ``deny`` mode refuses to store anything below a
minimum trust at all, for memory stores that must remain first-party only.

It is a library hook over the same tracker as the rest of CapGuard — not a
bespoke vector DB. ``search`` is a deterministic substring match (a stand-in for
an embedding store); the point is the label bookkeeping, which any backend can
adopt.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from .provenance import Label, ProvenanceTracker, Trust


class MemoryPoisoningError(PermissionError):
    """Raised in ``deny`` mode when sub-trust content is written to memory."""


class ProvenanceMemory:
    """Key-value + namespaced memory that preserves information-flow labels.

    Parameters
    ----------
    tracker:
        the shared :class:`ProvenanceTracker` the runtime uses, so labels written
        here are visible to enforcement on later calls.
    mode:
        ``"label"`` (default) stores everything but keeps each item's taint, so
        recalled untrusted content is still blocked at sinks. ``"deny"`` refuses
        to store anything whose trust is below ``min_trust``.
    min_trust:
        the floor used in ``deny`` mode (default: only fully ``TRUSTED`` data).
    """

    def __init__(
        self,
        tracker: ProvenanceTracker,
        *,
        mode: str = "label",
        min_trust: Trust = Trust.TRUSTED,
    ) -> None:
        if mode not in ("label", "deny"):
            raise ValueError("mode must be 'label' or 'deny'")
        self._t = tracker
        self._mode = mode
        self._min = min_trust
        self._kv: Dict[str, Tuple[Any, Label]] = {}
        self._ns: Dict[str, List[Tuple[Any, Label]]] = {}

    # ------------------------------------------------------------------ #
    def _label_for(self, value: Any, label: Optional[Label]) -> Label:
        lbl = label if label is not None else self._t.label_for(value)
        if self._mode == "deny" and lbl.trust < self._min:
            raise MemoryPoisoningError(
                f"refusing to store memory below trust {self._min.label!r} "
                f"(value is {lbl.trust.label!r}) — possible context poisoning"
            )
        return lbl

    # -- key/value --------------------------------------------------------- #
    def write(self, key: str, value: Any, label: Optional[Label] = None) -> Label:
        lbl = self._label_for(value, label)
        self._kv[key] = (value, lbl)
        self._t.observe(value, lbl)   # keep the in-flight value tainted too
        return lbl

    def read(self, key: str) -> Any:
        value, lbl = self._kv[key]
        self._t.observe(value, lbl)   # re-apply taint so it propagates downstream
        return value

    def label_of(self, key: str) -> Label:
        return self._kv[key][1]

    # -- namespaced append / recall / search (RAG-style) ------------------- #
    def append(self, namespace: str, value: Any, label: Optional[Label] = None) -> Label:
        lbl = self._label_for(value, label)
        self._ns.setdefault(namespace, []).append((value, lbl))
        self._t.observe(value, lbl)
        return lbl

    def recall(self, namespace: str) -> List[Any]:
        out: List[Any] = []
        for value, lbl in self._ns.get(namespace, []):
            self._t.observe(value, lbl)
            out.append(value)
        return out

    def search(self, namespace: str, query: str, k: int = 5) -> List[Any]:
        """Deterministic substring retrieval; recalled items keep their taint."""
        q = query.lower()
        hits = [(v, l) for v, l in self._ns.get(namespace, [])
                if isinstance(v, str) and q in v.lower()]
        for value, lbl in hits[:k]:
            self._t.observe(value, lbl)
        return [v for v, _ in hits[:k]]
