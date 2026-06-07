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
from typing import Any, Callable, List, Optional

from .core import Capability, Severity, ToolSpec
from .provenance import Label
from .runtime import AgentRuntime


@dataclass
class GuardedTool:
    """A guarded callable plus the metadata frameworks need to expose it."""

    name: str
    description: str
    func: Callable[..., Any]

    def __call__(self, **kwargs: Any) -> Any:
        return self.func(**kwargs)


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
