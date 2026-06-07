"""CapGuard core types.

The central security primitive is the *capability*. A capability is an
attenuable grant: it describes the maximum authority a holder may exercise.
Authorization is a refinement check ("attenuation"): a tool may run only if
every capability it requires is *covered* by some capability the calling
agent holds. "Covered" means the tool's requested authority is a subset /
refinement of the agent's granted authority — never an expansion.

This module deliberately separates two concerns that the previous version
conflated:

  1. *Gate* — can this agent use this tool at all? (capability attenuation)
  2. *Enforce* — given the actual call arguments, do they stay inside the
     declared capability constraints? (runtime enforcement, defense in depth)

Both are pure/deterministic and microsecond-cheap.
"""

from __future__ import annotations

import fnmatch
import os
import shlex
import unicodedata
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field

from .provenance import Label


class CapabilityType(str, Enum):
    FILE_READ = "file_read"
    FILE_WRITE = "file_write"
    SHELL_EXEC = "shell_exec"
    NETWORK_HTTP = "network_http"
    DB_QUERY = "db_query"
    CUSTOM = "custom"


class Severity(str, Enum):
    """Coarse-grained risk level used for the auto-allow threshold."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return {"low": 0, "medium": 1, "high": 2, "critical": 3}[self.value]


# Characters that turn a single argv into a chained/redirected shell command.
# We refuse to run these through the shell-exec enforcement backend, because an
# allow-list on argv[0] is meaningless if `;`, `|`, `&&`, backticks, `$()`,
# redirects or newlines can smuggle in a second command.
_SHELL_METACHARACTERS = set(";|&<>`$\n\r")


class CapabilityViolation(PermissionError):
    """Raised by Capability.enforce when actual arguments exceed the grant."""


# --------------------------------------------------------------------------- #
# Normalize-before-enforce (P5 hardening).
#
# Every string we enforce on is first NFKC-normalized and screened for smuggling
# characters. Without this, an enforcement check can be talked past with encoding
# tricks the *executor* later collapses: a fullwidth semicolon (`U+FF1B`) that
# folds to `;`, a zero-width space splitting a blocked command, a NUL byte
# truncating a path, or homoglyph/format-control characters hiding intent. We
# canonicalize first so the check sees what the OS/network layer will actually
# act on.
# --------------------------------------------------------------------------- #
def _nfkc(s: str) -> str:
    return unicodedata.normalize("NFKC", s)


def _reject_smuggled(s: str, what: str) -> None:
    if "\x00" in s:
        raise CapabilityViolation(f"{what} contains a NUL byte")
    for ch in s:
        if ch in "\t\n\r":
            continue
        # Cc = control, Cf = format (zero-width joiners, BOM, bidi overrides …)
        if unicodedata.category(ch) in ("Cc", "Cf"):
            raise CapabilityViolation(
                f"{what} contains hidden control/format characters (possible smuggling)"
            )


class Capability(BaseModel):
    """A single attenuable capability.

    ``arg`` optionally binds this capability to the keyword argument whose
    value must be enforced at call time (e.g. the ``cmd`` of a shell tool,
    the ``url`` of an HTTP tool). When unset, a per-type default is used.
    """

    type: CapabilityType
    params: Dict[str, Any] = Field(default_factory=dict)
    arg: Optional[str] = None

    # ------------------------------------------------------------------ #
    # Constructors
    # ------------------------------------------------------------------ #
    @classmethod
    def shell_exec(
        cls,
        timeout: int = 30,
        allowlist: Optional[List[str]] = None,
        arg: str = "cmd",
    ) -> "Capability":
        return cls(
            type=CapabilityType.SHELL_EXEC,
            params={"timeout": int(timeout), "allowlist": sorted(allowlist or [])},
            arg=arg,
        )

    @classmethod
    def file_read(cls, paths: Optional[List[str]] = None, arg: str = "path") -> "Capability":
        return cls(type=CapabilityType.FILE_READ, params={"paths": sorted(paths or [])}, arg=arg)

    @classmethod
    def file_write(cls, paths: Optional[List[str]] = None, arg: str = "path") -> "Capability":
        return cls(type=CapabilityType.FILE_WRITE, params={"paths": sorted(paths or [])}, arg=arg)

    @classmethod
    def network_http(cls, domains: Optional[List[str]] = None, arg: str = "url") -> "Capability":
        return cls(type=CapabilityType.NETWORK_HTTP, params={"domains": sorted(domains or [])}, arg=arg)

    @classmethod
    def db_query(cls, read_only: bool = True, arg: str = "query") -> "Capability":
        return cls(type=CapabilityType.DB_QUERY, params={"read_only": bool(read_only)}, arg=arg)

    @classmethod
    def custom(cls, name: str, **params: Any) -> "Capability":
        p = {"name": name}
        p.update(params)
        return cls(type=CapabilityType.CUSTOM, params=p)

    # ------------------------------------------------------------------ #
    # (1) Attenuation: does THIS (granted) capability cover the requested one?
    # ------------------------------------------------------------------ #
    def covers(self, requested: "Capability") -> bool:
        """True iff ``requested`` is a refinement (subset) of ``self``.

        ``self`` is the authority the agent *holds*; ``requested`` is what the
        tool *needs*. Coverage never expands authority.
        """

        if self.type is not requested.type:
            return False

        t = self.type
        sp, rp = self.params, requested.params

        if t is CapabilityType.SHELL_EXEC:
            # requested commands must be a subset of granted; requested timeout
            # must not exceed the granted maximum.
            granted_cmds = set(sp.get("allowlist", []))
            req_cmds = set(rp.get("allowlist", []))
            if "*" not in granted_cmds and not req_cmds.issubset(granted_cmds):
                return False
            return int(rp.get("timeout", 0)) <= int(sp.get("timeout", 0))

        if t is CapabilityType.NETWORK_HTTP:
            granted = set(sp.get("domains", []))
            req = set(rp.get("domains", []))
            if "*" in granted:
                return True
            return req.issubset(granted)

        if t in (CapabilityType.FILE_READ, CapabilityType.FILE_WRITE):
            granted = sp.get("paths", [])
            req = rp.get("paths", [])
            # every requested path-pattern must be contained by some granted root
            return all(any(_path_covers(g, r) for g in granted) for r in req)

        if t is CapabilityType.DB_QUERY:
            # write authority (read_only=False) covers read+write; read-only
            # authority covers only read-only requests.
            granted_write = not sp.get("read_only", True)
            req_write = not rp.get("read_only", True)
            return granted_write or not req_write

        # CUSTOM: conservative exact match on params.
        return sp == rp

    # ------------------------------------------------------------------ #
    # (2) Runtime enforcement: validate the ACTUAL argument value.
    # ------------------------------------------------------------------ #
    def enforce(self, value: Any) -> None:
        """Raise CapabilityViolation if ``value`` exceeds this capability.

        This is the teeth: it runs on the concrete call argument, independent
        of the attenuation gate, so a registered tool still cannot be driven
        outside its declared bounds.
        """

        t = self.type

        if t is CapabilityType.SHELL_EXEC:
            cmd = _nfkc(str(value))
            _reject_smuggled(cmd, "shell command")
            if any(c in _SHELL_METACHARACTERS for c in cmd):
                raise CapabilityViolation(
                    "shell command contains shell metacharacters; chaining/redirection is not allowed"
                )
            try:
                argv = shlex.split(cmd)
            except ValueError as exc:
                raise CapabilityViolation(f"unparseable shell command: {exc}") from exc
            if not argv:
                raise CapabilityViolation("empty shell command")
            allow = set(self.params.get("allowlist", []))
            prog = os.path.basename(argv[0])
            if "*" not in allow and prog not in allow and argv[0] not in allow:
                raise CapabilityViolation(f"command {prog!r} is not in the allow-list {sorted(allow)}")
            return

        if t is CapabilityType.NETWORK_HTTP:
            from urllib.parse import urlparse

            raw = _nfkc(str(value))
            _reject_smuggled(raw, "url")
            host = (urlparse(raw).hostname or "").lower().rstrip(".")
            domains = set(d.lower() for d in self.params.get("domains", []))
            if "*" in domains:
                return
            if host in domains:
                return
            # allow subdomain match for entries written as ".example.com"
            if any(d.startswith(".") and host.endswith(d) for d in domains):
                return
            raise CapabilityViolation(f"host {host!r} is not in the allowed domains {sorted(domains)}")

        if t in (CapabilityType.FILE_READ, CapabilityType.FILE_WRITE):
            raw = _nfkc(str(value))
            _reject_smuggled(raw, "path")
            target = os.path.realpath(raw)
            roots = self.params.get("paths", [])
            for root in roots:
                if _path_contains(root, target):
                    return
            raise CapabilityViolation(f"path {target!r} is outside the allowed roots {roots}")

        if t is CapabilityType.DB_QUERY:
            if self.params.get("read_only", True):
                q = str(value).lstrip().lower()
                if not (q.startswith("select") or q.startswith("with") or q.startswith("show") or q.startswith("explain")):
                    raise CapabilityViolation("read-only DB capability only permits read queries")
            return

        # CUSTOM: nothing generic to enforce on the value.
        return


def _path_covers(granted_pattern: str, requested_pattern: str) -> bool:
    """Static (pattern-vs-pattern) containment used during attenuation."""
    g = os.path.normpath(granted_pattern)
    r = os.path.normpath(requested_pattern)
    if fnmatch.fnmatch(r, g):
        return True
    # treat a granted dir/glob root as covering anything beneath it
    g_root = g[:-1] if g.endswith("*") else g
    return r == g_root or r.startswith(g_root.rstrip("/") + os.sep)


def _path_contains(root_pattern: str, real_target: str) -> bool:
    """Dynamic (root-vs-realpath) containment used during enforcement."""
    root = root_pattern[:-1] if root_pattern.endswith("*") else root_pattern
    root = os.path.realpath(root.rstrip("/")) if not any(ch in root for ch in "*?[") else root
    if any(ch in root_pattern for ch in "*?["):
        return fnmatch.fnmatch(real_target, os.path.realpath(os.path.dirname(root_pattern.rstrip("*"))) + os.sep + "*")
    return real_target == root or real_target.startswith(root + os.sep)


class ToolSpec(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    name: str
    description: str = ""
    capabilities: List[Capability] = Field(default_factory=list)
    severity: Severity = Severity.MEDIUM
    # Intrinsic information-flow label of this tool's OUTPUT. A source tool that
    # reads attacker-influenceable data (web fetch, inbox, file in a shared dir)
    # declares e.g. ``Label(trust=Trust.UNTRUSTED_WEB)`` so the provenance tracker
    # taints everything derived from its result. ``None`` = pass-through (the
    # output is only as tainted as the inputs it was computed from).
    output_label: Optional[Label] = None


class AgentIdentity(BaseModel):
    """A non-human identity with scoped, attenuable capabilities."""

    id: str
    roles: List[str] = Field(default_factory=list)
    allowed_capabilities: List[Capability] = Field(default_factory=list)

    def covers(self, requested: Capability) -> bool:
        return any(held.covers(requested) for held in self.allowed_capabilities)

    def effective_capability(self, requested: Capability) -> Optional[Capability]:
        """Return the held capability that authorizes ``requested`` (for enforcement)."""
        for held in self.allowed_capabilities:
            if held.covers(requested):
                return held
        return None

    def attenuate(self, capabilities: List[Capability]) -> "AgentIdentity":
        """Return a narrowed copy holding only ``capabilities``.

        Raises ``PermissionError`` if any requested capability is not already
        covered by this identity: attenuation can only *drop* authority, never
        add it. This is the zero-standing-permissions / just-in-time grant
        primitive — hand an agent a broad identity, then attenuate to exactly the
        capabilities a task needs for the duration of that task.
        """
        for cap in capabilities:
            if not self.covers(cap):
                raise PermissionError(
                    f"attenuation would expand authority for {cap.type.value!r} capability"
                )
        return AgentIdentity(id=self.id, roles=list(self.roles),
                             allowed_capabilities=list(capabilities))


class PolicyDecision(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"


class Policy(BaseModel):
    """Baseline capability + severity policy.

    Rules:
      * deny if the agent does not hold capabilities covering the tool's needs;
      * otherwise allow when the tool severity is within the auto-allow ceiling;
      * otherwise require approval.

    Argument-level / use-case constraints live in the policy DSL (see
    ``policy_dsl``), which composes on top of this baseline.
    """

    name: str = "default"
    deny_by_default: bool = True
    max_auto_allow_severity: Severity = Severity.MEDIUM

    def evaluate(self, *, agent: AgentIdentity, tool: ToolSpec) -> PolicyDecision:
        for required in tool.capabilities:
            if not agent.covers(required):
                return PolicyDecision.DENY

        # A tool that declares no capabilities is implicitly capability-free;
        # deny_by_default refuses it unless severity is low.
        if not tool.capabilities and self.deny_by_default and tool.severity.rank > Severity.LOW.rank:
            return PolicyDecision.DENY

        if tool.severity.rank <= self.max_auto_allow_severity.rank:
            return PolicyDecision.ALLOW
        return PolicyDecision.REQUIRE_APPROVAL


class ApprovalRequired(Exception):
    def __init__(
        self,
        *,
        tool: ToolSpec,
        agent: AgentIdentity,
        reason: str | None = None,
        token_id: str | None = None,
    ) -> None:
        self.tool = tool
        self.agent = agent
        self.token_id = token_id
        self.reason = reason or f"Tool {tool.name!r} requires approval for agent {agent.id!r}"
        super().__init__(self.reason)
