"""AgentRuntime — the inline enforcement point for every tool call.

Pipeline (deterministic, defense in depth):

  1. Baseline capability gate   (Policy.evaluate: attenuation + severity)
  2. Programmable policy DSL     (argument/use-case/rate/provenance rules)
  3. Capability ARGUMENT enforcement on the concrete call values  ← the teeth
  4. Dispatch
  5. Hash-chained audit at every exit

The runtime holds NO mutable per-call identity. Identity flows through an
immutable CallContext, so concurrent calls cannot bleed permissions into each
other (the previous version mutated ``self._agent`` under a try/finally, which
was unsafe under FastAPI's threadpool).
"""

from __future__ import annotations

from typing import Any, Callable, Dict, Optional

from .audit import AuditEvent, AuditSink, digest
from .core import (
    AgentIdentity,
    ApprovalRequired,
    Capability,
    CapabilityViolation,
    Policy,
    PolicyDecision,
    ToolSpec,
)
from .policy_dsl import CallContext, Decision, Effect, PolicyEngine
from .registry import ToolRegistry

ApprovalHandler = Callable[[AuditEvent, ToolSpec], bool]


class AgentRuntime:
    def __init__(
        self,
        *,
        registry: ToolRegistry,
        policy: Optional[Policy] = None,
        engine: Optional[PolicyEngine] = None,
        audit_sink: Optional[AuditSink] = None,
        approval_handler: Optional[ApprovalHandler] = None,
        approval_store: Optional[Any] = None,
        default_agent: Optional[AgentIdentity] = None,
    ) -> None:
        self._registry = registry
        self._policy = policy or Policy()
        self._engine = engine or PolicyEngine()
        self._audit_sink = audit_sink
        self._approval_handler = approval_handler
        self._approval_store = approval_store
        self._default_agent = default_agent

    # ------------------------------------------------------------------ #
    def _emit(self, event: AuditEvent) -> None:
        if self._audit_sink is not None:
            self._audit_sink(event)

    def _enforce_arguments(
        self, agent: AgentIdentity, tool: ToolSpec, kwargs: Dict[str, Any]
    ) -> None:
        """Validate each concrete argument against the effective capability.

        Uses the agent's *granted* capability (the one that covers the tool's
        requirement), so the enforced bound is the agent's, not merely the
        tool's declaration. Raises CapabilityViolation on the first breach.
        """
        for required in tool.capabilities:
            granted = agent.effective_capability(required)
            enforcer: Capability = granted or required
            arg_name = required.arg
            if not arg_name or arg_name not in kwargs:
                continue
            enforcer.enforce(kwargs[arg_name])

    # ------------------------------------------------------------------ #
    def invoke_tool(
        self,
        name: str,
        /,
        *,
        agent: Optional[AgentIdentity] = None,
        request_id: Optional[str] = None,
        provenance: Optional[Dict[str, str]] = None,
        approval_token: Optional[str] = None,
        **kwargs: Any,
    ) -> Any:
        agent = agent or self._default_agent
        if agent is None:
            raise ValueError("no agent identity supplied (pass agent= or set default_agent)")

        registered = self._registry.get(name)
        tool: ToolSpec = registered.spec

        ctx = CallContext(
            agent_id=agent.id,
            tool_name=tool.name,
            args=dict(kwargs),
            roles=tuple(agent.roles),
            request_id=request_id,
            provenance=provenance or {},
        )

        event = AuditEvent(
            agent_id=agent.id,
            tool_name=tool.name,
            decision=PolicyDecision.DENY,
            params={k: digest(v) for k, v in kwargs.items()},  # store digests, not raw payloads
            request_id=request_id,
        )

        # 1. baseline capability gate
        base = self._policy.evaluate(agent=agent, tool=tool)
        if base is PolicyDecision.DENY:
            event.decision = PolicyDecision.DENY
            event.error = "denied_by_capability_policy"
            self._emit(event)
            raise PermissionError(
                f"agent {agent.id!r} lacks capabilities for tool {name!r}"
            )

        # 2. programmable DSL (deny-overrides). It can only tighten.
        dsl: Decision = self._engine.evaluate(ctx)
        event.effect = dsl.effect.value

        effective = base
        if dsl.effect is Effect.DENY:
            effective = PolicyDecision.DENY
        elif dsl.effect is Effect.REQUIRE_APPROVAL and base is PolicyDecision.ALLOW:
            effective = PolicyDecision.REQUIRE_APPROVAL

        if effective is PolicyDecision.DENY:
            event.decision = PolicyDecision.DENY
            event.error = f"denied_by_policy_dsl: {dsl.reason}"
            self._emit(event)
            raise PermissionError(f"denied by policy ({dsl.reason}) for tool {name!r}")

        if effective is PolicyDecision.REQUIRE_APPROVAL:
            event.decision = PolicyDecision.REQUIRE_APPROVAL

            # (a) replay path: a valid, approved, args-matching token.
            if approval_token is not None and self._approval_store is not None:
                ok = self._approval_store.verify_and_consume(
                    token_id=approval_token, agent_id=agent.id, tool_name=tool.name, args=kwargs
                )
                if not ok:
                    event.error = "invalid_or_mismatched_approval_token"
                    self._emit(event)
                    raise PermissionError(
                        f"approval token invalid/expired/mismatched for tool {name!r}"
                    )
                event.decision = PolicyDecision.ALLOW

            # (b) inline synchronous human approval.
            elif self._approval_handler is not None:
                if not self._approval_handler(event, tool):
                    event.error = "denied_by_approval_handler"
                    self._emit(event)
                    raise PermissionError(f"approval denied for tool {name!r}")
                event.decision = PolicyDecision.ALLOW

            # (c) pause: issue a pending token bound to these exact args.
            else:
                token_id = None
                if self._approval_store is not None:
                    tok = self._approval_store.issue(
                        agent_id=agent.id, tool_name=tool.name, args=kwargs, reason=dsl.reason
                    )
                    token_id = tok.id
                event.error = "require_approval_pending"
                self._emit(event)
                raise ApprovalRequired(tool=tool, agent=agent, reason=dsl.reason, token_id=token_id)

        # 3. ARGUMENT enforcement (the teeth) — independent of the gate above.
        try:
            self._enforce_arguments(agent, tool, kwargs)
        except CapabilityViolation as exc:
            event.decision = PolicyDecision.DENY
            event.error = f"capability_violation: {exc}"
            self._emit(event)
            raise

        # 4. dispatch + 5. audit
        try:
            result = registered.func(**kwargs)
            event.result_digest = digest(result)
            self._emit(event)
            return result
        except Exception as exc:  # noqa: BLE001
            event.error = f"{type(exc).__name__}: {exc}"
            self._emit(event)
            raise
