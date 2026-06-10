"""In-memory, tenant-isolated store for ingested audit events.

MVP/demo backend: a per-tenant list of hash-chained :class:`AuditEvent`s. It
verifies the chain server-side and derives the dashboard views (decisions feed,
stats, reconstructed flow graph). A persistent backend (Postgres) implements the
same surface later without changing the API.
"""

from __future__ import annotations

import threading
from collections import Counter
from typing import Any, Dict, List

from capguard.audit import AuditEvent, verify_chain
from capguard.audit_graph import _DEFAULT_SINKS, build_flow_graph, tainted_sink_calls


class CloudStore:
    def __init__(self) -> None:
        self._events: Dict[str, List[AuditEvent]] = {}
        self._lock = threading.Lock()

    def ingest(self, tenant: str, event: AuditEvent) -> int:
        with self._lock:
            self._events.setdefault(tenant, []).append(event)
            return len(self._events[tenant])

    def _events_for(self, tenant: str) -> List[AuditEvent]:
        return list(self._events.get(tenant, []))

    def chain_ok(self, tenant: str) -> bool:
        return verify_chain(self._events_for(tenant))

    def decisions(self, tenant: str, limit: int = 50) -> List[Dict[str, Any]]:
        evs = self._events_for(tenant)[-limit:]
        return [{
            "timestamp": e.timestamp.isoformat(),
            "agent": e.agent_id,
            "tool": e.tool_name,
            "decision": e.decision.value,
            "effect": e.effect,
            "error": e.error,
        } for e in reversed(evs)]

    def stats(self, tenant: str) -> Dict[str, Any]:
        evs = self._events_for(tenant)
        by_decision = Counter(e.decision.value for e in evs)
        return {
            "total": len(evs),
            "by_decision": dict(by_decision),
            "blocked": sum(1 for e in evs if e.decision.value == "deny"),
            "approvals": sum(1 for e in evs if e.decision.value == "require_approval"),
            "agents": sorted({e.agent_id for e in evs}),
            "tools": sorted({e.tool_name for e in evs}),
            "chain_ok": self.chain_ok(tenant),
        }

    def flows(self, tenant: str) -> Dict[str, Any]:
        graph = build_flow_graph(self._events_for(tenant))
        flagged = tainted_sink_calls(graph, _DEFAULT_SINKS)
        return {
            "nodes": len(graph.nodes),
            "edges": len(graph.edges),
            "tainted_sinks": [
                {"index": n.index, "tool": n.tool, "agent": n.agent} for n in flagged
            ],
        }
