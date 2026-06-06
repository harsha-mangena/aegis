from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional

from .core import Capability, Severity, ToolSpec


class RegisteredTool:
    def __init__(self, spec: ToolSpec, func: Callable[..., Any]) -> None:
        self.spec = spec
        self.func = func


class ToolRegistry:
    """Process-local registry; decorator-based registration."""

    def __init__(self) -> None:
        self._tools: Dict[str, RegisteredTool] = {}

    def tool(
        self,
        *,
        name: Optional[str] = None,
        capabilities: Optional[List[Capability]] = None,
        description: str = "",
        severity: Severity = Severity.MEDIUM,
    ) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
            tool_name = name or func.__name__
            if tool_name in self._tools:
                raise ValueError(f"Tool {tool_name!r} already registered")
            spec = ToolSpec(
                name=tool_name,
                description=description or (func.__doc__ or "").strip(),
                capabilities=capabilities or [],
                severity=severity,
            )
            self._tools[tool_name] = RegisteredTool(spec, func)
            return func

        return decorator

    def register(self, spec: ToolSpec, func: Callable[..., Any]) -> None:
        if spec.name in self._tools:
            raise ValueError(f"Tool {spec.name!r} already registered")
        self._tools[spec.name] = RegisteredTool(spec, func)

    def get(self, name: str) -> RegisteredTool:
        try:
            return self._tools[name]
        except KeyError as exc:
            raise KeyError(f"Tool {name!r} not found") from exc

    def list_tools(self) -> List[ToolSpec]:
        return [rt.spec for rt in self._tools.values()]

    def unregister(self, name: str) -> None:
        self._tools.pop(name, None)

    def has(self, name: str) -> bool:
        return name in self._tools
