"""
Aegis core — the simple API layer.

Wraps capguard's full enforcement engine behind a single decorator.
All complexity is internal; the user sees only ``guard``.
"""

from __future__ import annotations

import functools
import inspect
import threading
from typing import Any, Callable, Dict, List, Optional, Union

from capguard.approval import ApprovalStore
from capguard.audit import AuditSink, HashChainedSink, MemorySink
from capguard.core import (
    AgentIdentity,
    Capability,
    CapabilityType,
    Policy,
    Severity,
    ToolSpec,
)
from capguard.detectors import Detector
from capguard.monitor import AnomalyPolicy, BehaviorMonitor, CircuitBreaker
from capguard.packs import compile_pack, load_pack
from capguard.policy_dsl import PolicyEngine
from capguard.provenance import (
    Confidentiality,
    Label,
    ProvenanceTracker,
    Trust,
)
from capguard.registry import ToolRegistry
from capguard.runtime import AgentRuntime

# ------------------------------------------------------------------ #
# Mapping helpers
# ------------------------------------------------------------------ #

_RISK_MAP: Dict[str, Severity] = {
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}

_SOURCE_MAP: Dict[str, Label] = {
    "trusted": Label(trust=Trust.TRUSTED, confidentiality=Confidentiality.PUBLIC),
    "untrusted": Label(trust=Trust.UNTRUSTED_TOOL, confidentiality=Confidentiality.PUBLIC),
    "web": Label(trust=Trust.UNTRUSTED_WEB, confidentiality=Confidentiality.PUBLIC),
    "secret": Label(trust=Trust.TRUSTED, confidentiality=Confidentiality.SECRET),
}


def _build_capabilities(
    *,
    network: Union[bool, List[str]] = False,
    file_read: Union[bool, str] = False,
    file_write: Union[bool, str] = False,
    shell: Union[bool, List[str]] = False,
    db: bool = False,
    db_write: bool = False,
    custom: Union[None, str, List[str]] = None,
) -> List[Capability]:
    """Convert simple keyword flags into Capability objects."""
    caps: List[Capability] = []

    if network:
        if isinstance(network, list):
            caps.append(Capability.network_http(domains=network))
        else:
            # True = any domain
            caps.append(Capability.network_http(domains=["*"]))

    if file_read:
        if isinstance(file_read, str):
            caps.append(Capability.file_read(paths=[file_read]))
        else:
            # True = unrestricted — no arg binding, so enforcement is skipped
            caps.append(Capability(type=CapabilityType.FILE_READ, params={"paths": []}))

    if file_write:
        if isinstance(file_write, str):
            caps.append(Capability.file_write(paths=[file_write]))
        else:
            caps.append(Capability(type=CapabilityType.FILE_WRITE, params={"paths": []}))

    if shell:
        if isinstance(shell, list):
            caps.append(Capability.shell_exec(allowlist=shell))
        else:
            # True = any command
            caps.append(Capability.shell_exec(allowlist=["*"]))

    if db:
        caps.append(Capability.db_query(read_only=True))

    if db_write:
        caps.append(Capability.db_query(read_only=False))

    if custom is not None:
        if isinstance(custom, str):
            caps.append(Capability.custom(custom))
        else:
            for c in custom:
                caps.append(Capability.custom(c))

    return caps


# ------------------------------------------------------------------ #
# Aegis — the hub
# ------------------------------------------------------------------ #


class Aegis:
    """
    Universal AI Agent Security Hub.

    Create one, guard everything::

        ag = Aegis(pack="owasp-baseline", audit="audit.jsonl")

        @ag.guard(network=True)
        def search(query: str) -> str: ...

    Or use the module-level ``guard`` for zero-config::

        from aegis import guard

        @guard(network=True)
        def search(query: str) -> str: ...
    """

    def __init__(
        self,
        *,
        pack: Union[str, dict, None] = None,
        audit: Union[bool, str] = False,
        agent_id: str = "default",
        roles: Optional[List[str]] = None,
        risk_ceiling: str = "medium",
        monitor: bool = False,
        monitor_policy: Optional[AnomalyPolicy] = None,
        detectors: Optional[List[Detector]] = None,
    ) -> None:
        self._registry = ToolRegistry()
        self._tracker = ProvenanceTracker()
        self._store = ApprovalStore()
        self._breaker = CircuitBreaker()
        self._lock = threading.Lock()
        self._granted_caps: List[Capability] = []

        # Policy engine (from pack or empty)
        if pack:
            pack_data = load_pack(pack)
            self._engine = compile_pack(pack_data)
        else:
            self._engine = PolicyEngine()

        # Audit sink
        if isinstance(audit, str):
            self._sink: AuditSink = HashChainedSink(audit)
        else:
            self._sink = MemorySink()

        # Baseline policy
        ceiling = _RISK_MAP.get(risk_ceiling, Severity.MEDIUM)
        self._policy = Policy(max_auto_allow_severity=ceiling)

        # Agent identity defaults
        self._agent_id = agent_id
        self._roles = roles or ["user"]

        # Monitor (optional)
        effective_sink: AuditSink = self._sink
        if monitor:
            mp = monitor_policy or AnomalyPolicy()
            self._monitor: Optional[BehaviorMonitor] = BehaviorMonitor(
                policy=mp,
                breaker=self._breaker,
                downstream=self._sink,
            )
            effective_sink = self._monitor
        else:
            self._monitor = None

        # Runtime
        self._runtime = AgentRuntime(
            registry=self._registry,
            policy=self._policy,
            engine=self._engine,
            audit_sink=effective_sink,
            approval_store=self._store,
            tracker=self._tracker,
            circuit_breaker=self._breaker,
            detectors=list(detectors or []),
        )

    # -- internal -------------------------------------------------- #

    def _agent(self) -> AgentIdentity:
        """Build an AgentIdentity with all currently granted capabilities."""
        return AgentIdentity(
            id=self._agent_id,
            roles=list(self._roles),
            allowed_capabilities=list(self._granted_caps),
        )

    # -- public API ------------------------------------------------ #

    def guard(
        self,
        _fn: Optional[Callable] = None,
        *,
        # Capabilities (bool = unrestricted, str/list = scoped)
        network: Union[bool, List[str]] = False,
        file_read: Union[bool, str] = False,
        file_write: Union[bool, str] = False,
        shell: Union[bool, List[str]] = False,
        db: bool = False,
        db_write: bool = False,
        custom: Union[None, str, List[str]] = None,
        # Security
        risk: str = "low",
        approval: bool = False,
        # Provenance
        source: Optional[str] = None,
        # Metadata
        name: Optional[str] = None,
        description: Optional[str] = None,
        # Agent-mode hint (tools this agent uses)
        tools: Optional[list] = None,
    ) -> Any:
        """
        Guard any function — tool, agent, RAG pipeline, voice handler.

        Capability flags accept ``True`` (unrestricted) or a scope::

            @ag.guard(network=True)                # any domain
            @ag.guard(network=["api.example.com"]) # only api.example.com
            @ag.guard(file_read="/data")            # only /data/**
            @ag.guard(shell=["ls", "cat"])          # only ls and cat

        Risk levels: ``"low"`` (auto-allow), ``"medium"`` (auto-allow by default),
        ``"high"`` (requires approval), ``"critical"`` (requires approval).

        Source labels for provenance tracking::

            @ag.guard(source="web")       # output tainted as untrusted-web
            @ag.guard(source="untrusted") # output tainted as untrusted-tool
            @ag.guard(source="secret")    # output marked as secret/confidential
        """

        def decorator(fn: Callable) -> Callable:
            tool_name = name or fn.__name__
            tool_desc = description or fn.__doc__ or ""

            # Build capabilities from keyword flags
            caps = _build_capabilities(
                network=network,
                file_read=file_read,
                file_write=file_write,
                shell=shell,
                db=db,
                db_write=db_write,
                custom=custom,
            )

            # Default: custom capability scoped to the tool name
            if not caps:
                caps = [Capability.custom(tool_name)]

            # Severity
            severity = _RISK_MAP.get(risk, Severity.LOW)
            if approval and severity.rank < Severity.HIGH.rank:
                severity = Severity.HIGH

            # Output provenance label
            output_label: Optional[Label] = None
            if source:
                output_label = _SOURCE_MAP.get(source)

            spec = ToolSpec(
                name=tool_name,
                description=tool_desc,
                capabilities=caps,
                severity=severity,
                output_label=output_label,
            )

            with self._lock:
                if self._registry.has(tool_name):
                    self._registry.unregister(tool_name)
                self._registry.register(spec, fn)
                self._granted_caps.extend(caps)

            # Cache the parameter names for positional-to-keyword conversion
            sig = inspect.signature(fn)
            param_names = list(sig.parameters.keys())

            @functools.wraps(fn)
            def wrapper(*args: Any, **kw: Any) -> Any:
                # Convert positional args to kwargs
                call_kwargs: Dict[str, Any] = dict(kw)
                for i, val in enumerate(args):
                    if i < len(param_names):
                        call_kwargs[param_names[i]] = val

                agent = self._agent()
                return self._runtime.invoke_tool(
                    tool_name,
                    agent=agent,
                    **call_kwargs,
                )

            # Metadata for introspection
            wrapper._aegis = True  # type: ignore[attr-defined]
            wrapper._aegis_spec = spec  # type: ignore[attr-defined]
            wrapper._aegis_name = tool_name  # type: ignore[attr-defined]
            wrapper._aegis_fn = fn  # type: ignore[attr-defined]
            return wrapper

        if _fn is not None:
            return decorator(_fn)
        return decorator

    # Aliases for readability
    tool = guard
    agent = guard

    # -- wrap existing agents -------------------------------------- #

    def wrap(self, agent_obj: Any, *, framework: Optional[str] = None) -> Any:
        """
        Wrap an existing agent from any framework::

            safe = ag.wrap(my_langchain_agent)
            safe.invoke("query")

        Auto-detects LangChain, OpenAI Agents, CrewAI, or falls back to
        callable wrapping.
        """
        from capguard.adapters import GuardedAgent, GuardedTool

        guarded_tools = []
        for rt in self._registry.list_tools():
            guarded_tools.append(
                GuardedTool(
                    name=rt.spec.name,
                    description=rt.spec.description,
                    func=rt.func,
                )
            )

        return GuardedAgent(agent=agent_obj, tools=guarded_tools)

    # -- provenance helpers ---------------------------------------- #

    def observe(self, value: Any, label: Union[str, Label] = "untrusted") -> None:
        """Mark a value with a provenance label for taint tracking."""
        lbl = _SOURCE_MAP.get(label) if isinstance(label, str) else label  # type: ignore[arg-type]
        if lbl:
            self._tracker.observe(value, lbl)

    def report_usage(self, *, tokens: int = 0, cost: float = 0.0) -> None:
        """Report LLM token/cost spend for budget enforcement."""
        self._runtime.report_usage(self._agent(), tokens=tokens, cost=cost)

    # -- property accessors (advanced usage) ----------------------- #

    @property
    def runtime(self) -> AgentRuntime:
        return self._runtime

    @property
    def registry(self) -> ToolRegistry:
        return self._registry

    @property
    def tracker(self) -> ProvenanceTracker:
        return self._tracker

    @property
    def sink(self) -> AuditSink:
        return self._sink

    @property
    def events(self) -> list:
        """Return audit events (only works with MemorySink)."""
        if isinstance(self._sink, MemorySink):
            return self._sink.events
        return []


# ------------------------------------------------------------------ #
# Module-level singleton API
# ------------------------------------------------------------------ #

_default: Optional[Aegis] = None
_default_lock = threading.Lock()


def _get_default() -> Aegis:
    """Lazy-init the default Aegis instance."""
    global _default
    if _default is None:
        with _default_lock:
            if _default is None:
                _default = Aegis()
    return _default


def configure(**kwargs: Any) -> Aegis:
    """
    Configure the module-level default Aegis instance.

    Call before any ``@guard`` decorators::

        from aegis import configure, guard

        configure(pack="finance", audit="audit.jsonl")

        @guard(network=True)
        def fetch_price(symbol: str) -> float: ...
    """
    global _default
    with _default_lock:
        _default = Aegis(**kwargs)
    return _default


def reset() -> None:
    """Reset the module-level default (mainly for tests)."""
    global _default
    with _default_lock:
        _default = None


def guard(
    _fn: Optional[Callable] = None,
    **kwargs: Any,
) -> Any:
    """
    Guard any function with the default Aegis instance.

    The simplest possible usage::

        from aegis import guard

        @guard(network=True)
        def search(query: str) -> str:
            return requests.get(f"https://api.example.com?q={query}").text

        @guard(shell=["ls", "cat"])
        def list_files(cmd: str) -> str:
            return subprocess.check_output(cmd, shell=False).decode()

    Works on tools, agents, RAG pipelines, voice handlers —
    anything callable.
    """
    return _get_default().guard(_fn, **kwargs)


def observe(value: Any, label: Union[str, Label] = "untrusted") -> None:
    """Mark a value with a provenance label on the default instance."""
    _get_default().observe(value, label)
