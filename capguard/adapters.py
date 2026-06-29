"""Framework adapters — embed CapGuard under any agent stack in ~one line.

The strategic position (June 2026): we do not compete with the agent frameworks
or with platform suites like Microsoft's Agent Governance Toolkit on breadth — we
are the deterministic enforcement *kernel* that runs **underneath** them. So the
adapter surface is deliberately tiny and framework-agnostic at its core:

  * :class:`CapGuard` — a facade bound to a ``(runtime, agent)`` pair. Decorate a
    plain function with ``@guard.tool(...)`` and it is registered, capability-
    gated, policy-checked, provenance-tracked and audited on every call. That is
    the whole "5-minute adoption" story, and it is framework-independent.

  * ``to_langchain`` / ``to_openai_agents`` / ``to_crewai`` — thin bindings that
    take a guarded tool and hand back the *native* tool object for LangGraph/
    LangChain, the OpenAI Agents SDK, or CrewAI. Each does an optional import so
    CapGuard never hard-depends on a framework; the framework class/decorator can
    also be injected (used by the tests, and handy for unusual setups).

Everything routes through :meth:`AgentRuntime.invoke_tool`, so a guarded tool
behaves identically no matter which framework drives it.
"""

from __future__ import annotations

import functools
from dataclasses import dataclass
from typing import Any, Callable, Iterable, List, Optional, Sequence

from .audit import AuditSink
from .core import AgentIdentity, Capability, Policy, Severity, ToolSpec
from .detectors import Detector
from .packs import compile_pack
from .policy_dsl import PolicyEngine
from .provenance import (
    SECRET,
    TRUSTED,
    UNTRUSTED_TOOL,
    UNTRUSTED_WEB,
    Confidentiality,
    Label,
    ProvenanceTracker,
)
from .registry import ToolRegistry
from .runtime import AgentRuntime


@dataclass
class GuardedTool:
    """A guarded callable plus the metadata frameworks need to expose it."""

    name: str
    description: str
    func: Callable[..., Any]

    def __call__(self, **kwargs: Any) -> Any:
        return self.func(**kwargs)

    def as_langchain(self, *, args_schema: Any = None, structured_tool_cls: Any = None) -> Any:
        """Return this guarded callable as a LangChain/LangGraph StructuredTool."""
        return to_langchain(self, args_schema=args_schema, structured_tool_cls=structured_tool_cls)

    def as_openai_agents(self, *, function_tool: Any = None) -> Any:
        """Return this guarded callable as an OpenAI Agents SDK function tool."""
        return to_openai_agents(self, function_tool=function_tool)

    def as_crewai(self, *, tool_decorator: Any = None) -> Any:
        """Return this guarded callable as a CrewAI tool."""
        return to_crewai(self, tool_decorator=tool_decorator)


@dataclass
class GuardedAgent:
    """A framework-neutral wrapper around an existing agent plus guarded tools.

    The wrapped ``agent`` is deliberately left untouched. Frameworks disagree on
    how tools are attached, so this object gives users the guarded forms they
    need and delegates normal ``invoke`` / ``run`` / call behavior when present.
    """

    agent: Any
    guard: "AgentGuard"
    tools: List[GuardedTool]
    framework: Optional[str] = None

    def tools_for(self, framework: Optional[str] = None) -> List[Any]:
        """Return tools in the requested framework shape.

        ``None`` / ``"raw"`` returns ``GuardedTool`` objects, which are callable
        and work in custom loops. ``"langchain"``, ``"openai"``/``"openai_agents"``,
        and ``"crewai"`` return native framework tool objects.
        """
        fw = (framework or self.framework or "raw").lower().replace("-", "_")
        if fw in ("raw", "python", "custom"):
            return list(self.tools)
        if fw in ("langchain", "langgraph"):
            return [tool.as_langchain() for tool in self.tools]
        if fw in ("openai", "openai_agents"):
            return [tool.as_openai_agents() for tool in self.tools]
        if fw == "crewai":
            return [tool.as_crewai() for tool in self.tools]
        raise ValueError(f"unknown framework {framework!r}")

    def bind(self, framework: Optional[str] = None, **kwargs: Any) -> Any:
        """Bind guarded tools to common framework agents.

        Supports agents exposing ``bind_tools(...)`` or ``with_tools(...)``. For
        other frameworks, call ``tools_for(...)`` and pass the result to that
        framework's normal constructor/binder.
        """
        if self.agent is None:
            raise TypeError("no agent supplied; use tools_for(...) with your framework constructor")
        tools = self.tools_for(framework)
        if hasattr(self.agent, "bind_tools"):
            return self.agent.bind_tools(tools, **kwargs)
        if hasattr(self.agent, "with_tools"):
            return self.agent.with_tools(tools, **kwargs)
        raise TypeError(
            "agent does not expose bind_tools(...) or with_tools(...); "
            "use guarded_agent.tools_for(...) with your framework's tool binding API"
        )

    def invoke(self, *args: Any, **kwargs: Any) -> Any:
        if not hasattr(self.agent, "invoke"):
            raise TypeError("wrapped agent does not expose invoke(...)")
        return self.agent.invoke(*args, **kwargs)

    def run(self, *args: Any, **kwargs: Any) -> Any:
        if not hasattr(self.agent, "run"):
            raise TypeError("wrapped agent does not expose run(...)")
        return self.agent.run(*args, **kwargs)

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        if not callable(self.agent):
            raise TypeError("wrapped agent is not callable")
        return self.agent(*args, **kwargs)

    def __getattr__(self, name: str) -> Any:
        if self.agent is None:
            raise AttributeError(name)
        return getattr(self.agent, name)


class CapGuard:
    """Facade that turns ordinary functions into guarded tools for any framework."""

    def __init__(self, runtime: AgentRuntime, agent: Optional[Any] = None) -> None:
        self._rt = runtime
        # When no agent is passed, calls use the runtime's default agent.
        self._agent = agent if agent is not None else runtime.default_agent

    # -- registration ------------------------------------------------------ #
    def tool(
        self,
        *,
        name: Optional[str] = None,
        capabilities: Optional[List[Capability]] = None,
        severity: Severity = Severity.MEDIUM,
        output_label: Optional[Label] = None,
        description: str = "",
        provenance: Optional[dict] = None,
    ) -> Callable[[Callable[..., Any]], GuardedTool]:
        """Decorator: register ``fn`` in the runtime and return a guarded tool."""

        def decorator(fn: Callable[..., Any]) -> GuardedTool:
            tool_name = name or fn.__name__
            self._rt.registry.register(
                ToolSpec(
                    name=tool_name,
                    description=description or (fn.__doc__ or "").strip(),
                    capabilities=capabilities or [],
                    severity=severity,
                    output_label=output_label,
                ),
                fn,
            )
            return self.wrap(tool_name, description=description or (fn.__doc__ or "").strip(),
                             provenance=provenance, reference=fn)

        return decorator

    def wrap(
        self,
        name: str,
        *,
        description: str = "",
        provenance: Optional[dict] = None,
        reference: Optional[Callable[..., Any]] = None,
    ) -> GuardedTool:
        """Return a guarded callable for an already-registered tool ``name``."""
        agent = self._agent
        rt = self._rt

        def guarded(**kwargs: Any) -> Any:
            return rt.invoke_tool(name, agent=agent, provenance=provenance, **kwargs)

        if reference is not None:
            functools.update_wrapper(guarded, reference)
        guarded.__name__ = name  # frameworks key on the function name
        if not description and reference is not None:
            description = (reference.__doc__ or "").strip()
        return GuardedTool(name=name, description=description, func=guarded)


class AgentGuard:
    """High-level secure-by-default facade for any agent or framework.

    ``AgentGuard`` owns the runtime, identity, registry, provenance tracker, and
    a default policy pack. Users decorate or wrap the tools they already pass to
    LangChain, OpenAI Agents, CrewAI, AutoGen, a RAG pipeline, a voice agent, or
    a custom loop. The model/provider stays outside the API; every dangerous
    action still crosses this deterministic boundary.
    """

    def __init__(
        self,
        agent_id: str = "agent",
        *,
        profile: str | None = "owasp-baseline",
        roles: Optional[Sequence[str]] = None,
        capabilities: Optional[Sequence[Capability]] = None,
        policy: Optional[Policy] = None,
        engine: Optional[PolicyEngine] = None,
        audit_sink: Optional[AuditSink] = None,
        tracker: Optional[ProvenanceTracker] = None,
        detectors: Optional[Sequence[Detector]] = None,
        runtime: Optional[AgentRuntime] = None,
        agent: Optional[AgentIdentity] = None,
        auto_grant: bool = True,
    ) -> None:
        self._auto_grant = auto_grant
        self._guarded: dict[str, GuardedTool] = {}

        if runtime is not None:
            self._rt = runtime
            self._agent = agent or runtime.default_agent or AgentIdentity(
                id=agent_id,
                roles=list(roles or []),
                allowed_capabilities=list(capabilities or []),
            )
            self._tracker = tracker or getattr(runtime, "_tracker", None)
            if tracker is not None:
                self._rt._tracker = tracker
        else:
            self._tracker = tracker or ProvenanceTracker()
            self._agent = agent or AgentIdentity(
                id=agent_id,
                roles=list(roles or []),
                allowed_capabilities=list(capabilities or []),
            )
            self._rt = AgentRuntime(
                registry=ToolRegistry(),
                policy=policy or Policy(),
                engine=engine or (compile_pack(profile) if profile else PolicyEngine()),
                audit_sink=audit_sink,
                default_agent=self._agent,
                tracker=self._tracker,
                detectors=list(detectors or []),
            )
        self._facade = CapGuard(self._rt, self._agent)

    @classmethod
    def from_runtime(
        cls,
        runtime: AgentRuntime,
        *,
        agent: Optional[AgentIdentity] = None,
        auto_grant: bool = False,
    ) -> "AgentGuard":
        """Wrap an existing advanced runtime with the simple AgentGuard surface."""
        return cls(runtime=runtime, agent=agent, auto_grant=auto_grant)

    @property
    def runtime(self) -> AgentRuntime:
        return self._rt

    @property
    def agent(self) -> AgentIdentity:
        return self._agent

    @property
    def registry(self) -> ToolRegistry:
        return self._rt.registry

    def tool(
        self,
        fn: Optional[Callable[..., Any]] = None,
        *,
        name: Optional[str] = None,
        capability: str | Capability | Sequence[str | Capability] | None = None,
        capabilities: Optional[Sequence[Capability]] = None,
        network: str | Sequence[str] | None = None,
        shell: str | Sequence[str] | None = None,
        file_read: str | Sequence[str] | None = None,
        file_write: str | Sequence[str] | None = None,
        db_read: bool = False,
        db_write: bool = False,
        risk: str | Severity = Severity.LOW,
        source: str | Label | None = None,
        output_label: Optional[Label] = None,
        description: str = "",
        provenance: Optional[dict] = None,
    ) -> Callable[[Callable[..., Any]], GuardedTool] | GuardedTool:
        """Register and guard a tool.

        Can be used as ``@guard.tool(...)`` or ``guard.tool(fn, ...)``. If no
        capability is supplied, a scoped custom capability named after the tool
        is created and granted to this guard's agent.
        """

        def decorator(func: Callable[..., Any]) -> GuardedTool:
            tool_name = name or func.__name__
            caps = _build_capabilities(
                tool_name,
                capability=capability,
                capabilities=capabilities,
                network=network,
                shell=shell,
                file_read=file_read,
                file_write=file_write,
                db_read=db_read,
                db_write=db_write,
            )
            if self._auto_grant:
                self._grant(caps)
            guarded = self._facade.tool(
                name=tool_name,
                capabilities=list(caps),
                severity=_severity(risk),
                output_label=output_label or _label_from_source(source),
                description=description,
                provenance=provenance,
            )(func)
            self._guarded[tool_name] = guarded
            return guarded

        return decorator(fn) if fn is not None else decorator

    def guard(self, fn: Optional[Callable[..., Any]] = None, **kwargs: Any):
        """Alias for :meth:`tool`; reads naturally in quickstarts."""
        return self.tool(fn, **kwargs)

    def wrap(self, name: str, *, description: str = "", provenance: Optional[dict] = None) -> GuardedTool:
        """Return a guarded handle for a tool already in this runtime."""
        guarded = self._facade.wrap(name, description=description, provenance=provenance)
        self._guarded[name] = guarded
        return guarded

    def invoke(self, name: str, /, **kwargs: Any) -> Any:
        """Invoke a registered tool through the guard."""
        return self._rt.invoke_tool(name, agent=self._agent, **kwargs)

    def observe(self, value: Any, label: Label | str) -> Any:
        """Attach a provenance label to a value and return the same value."""
        if self._tracker is None:
            self._tracker = ProvenanceTracker()
            self._rt._tracker = self._tracker
        self._tracker.observe(value, _label_from_source(label) or TRUSTED)
        return value

    def untrusted(self, value: Any, *, source: str = "tool") -> Any:
        """Mark RAG/search/email/browser/voice-derived data as untrusted."""
        return self.observe(value, "web" if source == "web" else "tool")

    def secret(self, value: Any) -> Any:
        """Mark a value as secret/PII so sink policies can block exfiltration."""
        return self.observe(value, SECRET)

    def tools(self) -> List[GuardedTool]:
        """Return registered guarded tools for custom agent loops."""
        return list(self._guarded.values())

    def langchain_tools(self, *, args_schema: Any = None, structured_tool_cls: Any = None) -> List[Any]:
        return [t.as_langchain(args_schema=args_schema, structured_tool_cls=structured_tool_cls) for t in self.tools()]

    def openai_tools(self, *, function_tool: Any = None) -> List[Any]:
        return [t.as_openai_agents(function_tool=function_tool) for t in self.tools()]

    def crewai_tools(self, *, tool_decorator: Any = None) -> List[Any]:
        return [t.as_crewai(tool_decorator=tool_decorator) for t in self.tools()]

    def protect(
        self,
        agent: Any = None,
        *,
        tools: Optional[Sequence[Callable[..., Any] | GuardedTool]] = None,
        framework: Optional[str] = None,
    ) -> GuardedAgent:
        """Return a framework-neutral guarded-agent wrapper.

        Raw callables in ``tools`` are registered with a default scoped custom
        capability. For stronger argument enforcement, decorate tools with
        ``@guard.tool(network=..., shell=..., file_read=...)`` first and pass the
        resulting ``GuardedTool`` objects.
        """
        guarded_tools: List[GuardedTool] = []
        for item in tools or self.tools():
            if isinstance(item, GuardedTool):
                guarded = item
                self._guarded.setdefault(item.name, item)
            elif callable(item):
                guarded = self.tool(item)
            else:
                raise TypeError(f"unsupported tool object {item!r}")
            guarded_tools.append(guarded)
        return GuardedAgent(agent=agent, guard=self, tools=guarded_tools, framework=framework)

    def _grant(self, capabilities: Iterable[Capability]) -> None:
        for cap in capabilities:
            if not any(held.covers(cap) for held in self._agent.allowed_capabilities):
                self._agent.allowed_capabilities.append(cap)


def _as_list(value: str | Sequence[str] | None) -> List[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    return list(value)


def _severity(value: str | Severity) -> Severity:
    if isinstance(value, Severity):
        return value
    return Severity(str(value).lower())


def _label_from_source(source: str | Label | None) -> Optional[Label]:
    if source is None:
        return None
    if isinstance(source, Label):
        return source
    s = source.lower().replace("-", "_")
    if s in ("trusted", "user", "first_party"):
        return TRUSTED
    if s in ("web", "browser", "internet", "untrusted", "untrusted_web"):
        return UNTRUSTED_WEB
    if s in ("tool", "rag", "retrieval", "memory", "email", "document", "voice", "untrusted_tool"):
        return UNTRUSTED_TOOL
    if s in ("secret", "pii", "phi"):
        return SECRET
    if s == "internal":
        return Label(confidentiality=Confidentiality.INTERNAL)
    return Label.from_trust_str(s)


def _capability_items(value: str | Capability | Sequence[str | Capability] | None) -> List[str | Capability]:
    if value is None:
        return []
    if isinstance(value, (str, Capability)):
        return [value]
    return list(value)


def _build_capabilities(
    tool_name: str,
    *,
    capability: str | Capability | Sequence[str | Capability] | None = None,
    capabilities: Optional[Sequence[Capability]] = None,
    network: str | Sequence[str] | None = None,
    shell: str | Sequence[str] | None = None,
    file_read: str | Sequence[str] | None = None,
    file_write: str | Sequence[str] | None = None,
    db_read: bool = False,
    db_write: bool = False,
) -> List[Capability]:
    caps = list(capabilities or [])
    for item in _capability_items(capability):
        caps.append(item if isinstance(item, Capability) else Capability.custom(item))
    if network:
        caps.append(Capability.network_http(domains=_as_list(network)))
    if shell:
        caps.append(Capability.shell_exec(allowlist=_as_list(shell)))
    if file_read:
        caps.append(Capability.file_read(paths=_as_list(file_read)))
    if file_write:
        caps.append(Capability.file_write(paths=_as_list(file_write)))
    if db_read:
        caps.append(Capability.db_query(read_only=True))
    if db_write:
        caps.append(Capability.db_query(read_only=False))
    return caps or [Capability.custom(tool_name)]


def guard_agent(
    agent: Any = None,
    *,
    tools: Optional[Sequence[Callable[..., Any] | GuardedTool]] = None,
    framework: Optional[str] = None,
    agent_id: str = "agent",
    profile: str | None = "owasp-baseline",
    **kwargs: Any,
) -> GuardedAgent:
    """One-shot helper: create an ``AgentGuard`` and protect an agent/tool list."""
    guard = AgentGuard(agent_id=agent_id, profile=profile, **kwargs)
    return guard.protect(agent, tools=tools, framework=framework)


# --------------------------------------------------------------------------- #
# Native-framework bindings (optional imports; class/decorator injectable)
# --------------------------------------------------------------------------- #
def to_langchain(guarded: GuardedTool, *, args_schema: Any = None,
                 structured_tool_cls: Any = None) -> Any:
    """Wrap a guarded tool as a LangChain/LangGraph ``StructuredTool``."""
    if structured_tool_cls is None:
        try:
            from langchain_core.tools import StructuredTool as structured_tool_cls  # type: ignore
        except Exception as exc:  # noqa: BLE001
            raise ImportError(
                "to_langchain requires langchain-core (pip install langchain-core)"
            ) from exc
    return structured_tool_cls.from_function(
        func=guarded.func, name=guarded.name, description=guarded.description,
        args_schema=args_schema,
    )


def to_openai_agents(guarded: GuardedTool, *, function_tool: Any = None) -> Any:
    """Wrap a guarded tool as an OpenAI Agents SDK function tool."""
    if function_tool is None:
        try:
            from agents import function_tool  # type: ignore
        except Exception as exc:  # noqa: BLE001
            raise ImportError(
                "to_openai_agents requires the openai-agents SDK (pip install openai-agents)"
            ) from exc
    fn = guarded.func
    fn.__name__ = guarded.name
    fn.__doc__ = guarded.description or fn.__doc__
    return function_tool(fn)


def to_crewai(guarded: GuardedTool, *, tool_decorator: Any = None) -> Any:
    """Wrap a guarded tool as a CrewAI tool."""
    if tool_decorator is None:
        try:
            from crewai.tools import tool as tool_decorator  # type: ignore
        except Exception as exc:  # noqa: BLE001
            raise ImportError(
                "to_crewai requires crewai (pip install crewai)"
            ) from exc
    fn = guarded.func
    fn.__name__ = guarded.name
    fn.__doc__ = guarded.description or fn.__doc__
    return tool_decorator(guarded.name)(fn)
