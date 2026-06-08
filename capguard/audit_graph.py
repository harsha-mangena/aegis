"""Forensic provenance reconstruction from the audit chain.

The hash-chained audit log already records, per call, a digest of every argument,
a digest of the result, and each argument's trust label. That is enough to
reconstruct *data flow* after the fact — the offline, trace-based provenance
recovery the 2026 literature (NeuroTaint, "Ghost in the Agent") argues for, here
for free off a tamper-evident log and with **no raw payloads** stored.

The key insight: digests are content-identity. If call *A* returned a value with
digest ``D`` and a later call *B* was invoked with an argument whose digest is
also ``D``, then *A*'s output flowed into *B* — an edge ``A → B.arg``. Chaining
those edges reconstructs how data moved through the agent, and the per-argument
trust labels let us answer the incident-response question that matters:

    *which untrusted source reached which sensitive sink, through which hops?*

This is advisory forensics (digest collisions on trivial values are possible), not
an enforcement gate — enforcement already happened inline. It turns the audit log
into a triage tool.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Sequence

from .audit import AuditEvent


@dataclass
class FlowNode:
    index: int
    tool: str
    agent: str
    decision: str


@dataclass
class FlowEdge:
    src: int          # producing event index, or -1 for an external (untrusted) source
    dst: int          # consuming event index
    arg: str          # which argument of dst received the value
    digest: str
    label: str        # trust label of that argument at dst


@dataclass
class FlowGraph:
    nodes: List[FlowNode] = field(default_factory=list)
    edges: List[FlowEdge] = field(default_factory=list)

    def incoming(self, idx: int) -> List[FlowEdge]:
        return [e for e in self.edges if e.dst == idx]


def build_flow_graph(events: Sequence[AuditEvent]) -> FlowGraph:
    """Reconstruct a value-flow graph from a sequence of audit events."""
    nodes = [FlowNode(i, e.tool_name, e.agent_id, getattr(e.decision, "value", str(e.decision)))
             for i, e in enumerate(events)]
    edges: List[FlowEdge] = []
    producers: Dict[str, List[int]] = {}     # result digest -> producing event indices

    for i, e in enumerate(events):
        for arg, dig in (e.params or {}).items():
            label = (e.arg_provenance or {}).get(arg, "trusted")
            prior = [j for j in producers.get(dig, []) if j < i]
            if prior:
                edges.append(FlowEdge(src=prior[-1], dst=i, arg=arg, digest=dig, label=label))
            elif label != "trusted":
                # no in-trace producer, but the value is tainted => external source
                edges.append(FlowEdge(src=-1, dst=i, arg=arg, digest=dig, label=label))
        if e.result_digest:
            producers.setdefault(e.result_digest, []).append(i)
    return FlowGraph(nodes, edges)


def tainted_nodes(graph: FlowGraph, *, trusted_label: str = "trusted") -> set:
    """Indices of calls that consumed untrusted data (directly or transitively)."""
    tainted: set = set()
    by_dst: Dict[int, List[FlowEdge]] = {}
    for e in graph.edges:
        by_dst.setdefault(e.dst, []).append(e)
    for node in graph.nodes:                  # node.index is ascending; edges are causal (src < dst)
        for e in by_dst.get(node.index, []):
            if e.label != trusted_label or e.src in tainted:
                tainted.add(node.index)
                break
    return tainted


def tainted_sink_calls(graph: FlowGraph, sink_tools: Sequence[str]) -> List[FlowNode]:
    """Sink calls (tool name matches a glob in ``sink_tools``) that received taint."""
    tainted = tainted_nodes(graph)
    return [graph.nodes[i] for i in sorted(tainted)
            if any(fnmatch.fnmatch(graph.nodes[i].tool, pat) for pat in sink_tools)]


def upstream_chain(graph: FlowGraph, idx: int) -> List[int]:
    """The ordered list of ancestor event indices feeding ``idx`` (external = -1)."""
    seen: List[int] = []
    stack = [idx]
    visited = set()
    while stack:
        cur = stack.pop()
        for e in graph.incoming(cur):
            if e.src not in visited:
                visited.add(e.src)
                seen.append(e.src)
                if e.src >= 0:
                    stack.append(e.src)
    return sorted(set(seen))


def flow_graph_from_file(path: str | Path) -> FlowGraph:
    events = [
        AuditEvent.model_validate_json(line)
        for line in Path(path).read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    return build_flow_graph(events)


_DEFAULT_SINKS = ["send_*", "post_*", "transfer", "send_money", "delete_*", "share_*", "reserve_*"]


def format_flows(graph: FlowGraph, sink_tools: Sequence[str] = ()) -> str:
    sinks = list(sink_tools) or _DEFAULT_SINKS
    flagged = tainted_sink_calls(graph, sinks)
    lines = [f"flow graph: {len(graph.nodes)} calls, {len(graph.edges)} edges",
             f"tainted sink calls: {len(flagged)}"]
    for node in flagged:
        chain = [c for c in upstream_chain(graph, node.index) if c >= 0]
        src = "external/untrusted" if -1 in [e.src for e in graph.incoming(node.index)] else ""
        via = " <- ".join(f"#{c}:{graph.nodes[c].tool}" for c in reversed(chain)) or src
        lines.append(f"  #{node.index} {node.tool} (agent={node.agent}) <= {via or 'untrusted input'}")
    return "\n".join(lines)
