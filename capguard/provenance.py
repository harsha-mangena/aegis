"""Provenance propagation engine — deterministic information-flow control.

This is CapGuard's deepest moat and the place the 2026 research frontier lives
(AgentArmor's trace-as-program type system, RTBAS, Ghost-in-the-Agent's
information-flow tracking, NeuroTaint's trace-reconstructed provenance, CaMeL's
capabilities-on-values). The previous provenance support was *per call*: a label
had to be supplied for every argument at the call site. That stops the simplest
exfils but not **laundering** — a value pulled from an untrusted source, passed
through one tool, then used as the argument of a sensitive sink, silently lost
its taint because nothing carried the label forward.

This module carries it forward. It is a **library hook, not a forked
interpreter** (an explicit threat-model choice — see ``docs``): we tag values at
tool boundaries and propagate labels along the data flow the runtime can see.
That is sound for the high-value exfil paths (money / email / messaging / HTTP /
file) which is exactly where the damage is, and it composes with the policy DSL
so a single rule like "a secret may not flow to an untrusted sink" holds across
a whole call chain without the agent having to annotate anything.

Two orthogonal axes form the lattice:

  * **Trust (integrity).**  ``UNTRUSTED_WEB < UNTRUSTED_TOOL < TRUSTED``.
    Combining values takes the **minimum** — a result built from any untrusted
    input is itself untrusted. This is the integrity direction (block tainted
    data from steering a sensitive action).
  * **Confidentiality.**  ``PUBLIC < INTERNAL < SECRET``.
    Combining values takes the **maximum** — a result derived from a secret is
    itself secret. This is the confidentiality direction (block a secret from
    reaching an untrusted sink: the classic data-exfiltration shape).

Both directions are deterministic and microsecond-cheap.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import IntEnum
from functools import reduce
from typing import Any, Dict, FrozenSet, Iterable, Optional


class Trust(IntEnum):
    """Integrity level. Higher = more trustworthy. Combine with ``min``."""

    UNTRUSTED_WEB = 0     # content fetched from the open web / arbitrary URLs
    UNTRUSTED_TOOL = 1    # output of a tool reading attacker-influenceable data
    TRUSTED = 2           # the user's own instructions / first-party config

    @classmethod
    def from_str(cls, s: str) -> "Trust":
        return _STR_TO_TRUST.get(s, cls.TRUSTED)

    @property
    def label(self) -> str:
        return _TRUST_TO_STR[self]


_STR_TO_TRUST = {
    "trusted": Trust.TRUSTED,
    "untrusted_tool": Trust.UNTRUSTED_TOOL,
    "untrusted_web": Trust.UNTRUSTED_WEB,
}
_TRUST_TO_STR = {v: k for k, v in _STR_TO_TRUST.items()}


class Confidentiality(IntEnum):
    """Sensitivity level. Higher = more secret. Combine with ``max``."""

    PUBLIC = 0
    INTERNAL = 1
    SECRET = 2            # secrets + PII; never to an untrusted sink

    @classmethod
    def from_str(cls, s: str) -> "Confidentiality":
        return {"public": cls.PUBLIC, "internal": cls.INTERNAL,
                "secret": cls.SECRET, "pii": cls.SECRET}.get(s, cls.PUBLIC)


@dataclass(frozen=True)
class Label:
    """An information-flow label attached to a value.

    Defaults to the *most permissive* point of the lattice (trusted + public),
    so an untagged first-party value behaves exactly as before this module
    existed — propagation only ever *narrows* from there.
    """

    trust: Trust = Trust.TRUSTED
    confidentiality: Confidentiality = Confidentiality.PUBLIC
    sources: FrozenSet[str] = field(default_factory=frozenset)  # for audit/explainability

    # -- lattice algebra ---------------------------------------------------- #
    def combine(self, other: "Label") -> "Label":
        """The join of two values flowing into one result.

        Integrity takes the minimum (tainted wins); confidentiality takes the
        maximum (secret wins). The operation is commutative, associative and
        idempotent, which the property tests assert.
        """
        return Label(
            trust=Trust(min(self.trust, other.trust)),
            confidentiality=Confidentiality(max(self.confidentiality, other.confidentiality)),
            sources=self.sources | other.sources,
        )

    def downgrade_to(self, source: "Label") -> "Label":
        """Apply a tool's intrinsic source label (e.g. a web fetch is UNTRUSTED_WEB).

        A source can only make the result *less* trusted / *more* secret than
        what flowed in — it cannot launder a tainted input clean.
        """
        return self.combine(source)

    # -- back-compat with the string provenance API ------------------------- #
    @classmethod
    def from_trust_str(cls, s: str) -> "Label":
        return cls(trust=Trust.from_str(s), sources=frozenset({s}) if s else frozenset())

    @property
    def trust_str(self) -> str:
        return self.trust.label

    @property
    def is_secret(self) -> bool:
        return self.confidentiality >= Confidentiality.SECRET

    def at_least(self, trust: Trust) -> bool:
        return self.trust >= trust


# Convenient constants
TRUSTED = Label(Trust.TRUSTED, Confidentiality.PUBLIC)
UNTRUSTED_TOOL = Label(Trust.UNTRUSTED_TOOL, Confidentiality.PUBLIC, frozenset({"untrusted_tool"}))
UNTRUSTED_WEB = Label(Trust.UNTRUSTED_WEB, Confidentiality.PUBLIC, frozenset({"untrusted_web"}))
SECRET = Label(Trust.TRUSTED, Confidentiality.SECRET, frozenset({"secret"}))


def combine_all(labels: Iterable[Label]) -> Label:
    """Join an arbitrary number of labels (TRUSTED/PUBLIC identity element)."""
    return reduce(lambda a, b: a.combine(b), labels, Label())


def _value_key(value: Any) -> str:
    """Stable content key for a value.

    We key the taint map by a canonical content hash rather than ``id()``:
    tool I/O is overwhelmingly immutable scalars/strings, values cross process
    and MCP/JSON boundaries (so identity is not preserved), and if two distinct
    sources ever produce byte-identical content, *merging* their labels (the
    most-restrictive direction) is the safe outcome.
    """
    try:
        canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), default=repr)
    except TypeError:
        canonical = repr(value)
    return hashlib.sha256(canonical.encode("utf-8", "surrogatepass")).hexdigest()


class ProvenanceTracker:
    """Tracks and propagates information-flow labels across tool boundaries.

    Lifecycle, driven by :class:`~capguard.runtime.AgentRuntime` when one is
    attached:

      1. ``observe(value, label)`` records a label for a concrete value
         (e.g. the user's typed instruction is TRUSTED; an env secret is SECRET).
      2. On each tool call the runtime asks ``label_for(arg)`` for every
         argument, so the policy DSL sees propagated provenance with no manual
         tagging at the call site.
      3. After the tool returns, the runtime calls ``record_output`` to label
         the result as the join of its inputs, further downgraded by the tool's
         intrinsic source label — so the taint flows on to the next call.
    """

    def __init__(self, default: Optional[Label] = None) -> None:
        # Unknown values default to TRUSTED/PUBLIC to preserve pre-existing
        # semantics; sources downgrade explicitly. Tighten with default=UNTRUSTED
        # for a fully deny-by-default deployment.
        self._default = default or Label()
        self._labels: Dict[str, Label] = {}

    def observe(self, value: Any, label: Label) -> Label:
        """Record (or merge) a label for ``value``. Returns the effective label."""
        key = _value_key(value)
        existing = self._labels.get(key)
        merged = label if existing is None else existing.combine(label)
        self._labels[key] = merged
        return merged

    def label_for(self, value: Any) -> Label:
        return self._labels.get(_value_key(value), self._default)

    def propagate(self, inputs: Iterable[Any], source: Optional[Label] = None) -> Label:
        """Label of a result derived from ``inputs`` via a tool with ``source``."""
        lbl = combine_all(self.label_for(v) for v in inputs)
        if source is not None:
            lbl = lbl.downgrade_to(source)
        return lbl

    def record_output(self, result: Any, inputs: Iterable[Any], source: Optional[Label] = None) -> Label:
        """Propagate input labels onto ``result`` and store it for downstream calls."""
        lbl = self.propagate(inputs, source)
        # Only store a non-trivial label; storing TRUSTED/PUBLIC for everything
        # would be noise and could mask a later, more-restrictive observation.
        if lbl != Label():
            self.observe(result, lbl)
        return lbl

    def labels_for_args(self, kwargs: Dict[str, Any]) -> Dict[str, Label]:
        return {k: self.label_for(v) for k, v in kwargs.items()}
