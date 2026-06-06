#!/usr/bin/env python3
"""Launch a CapGuard MCP proxy over stdio in front of a downstream server.

A client (e.g. Claude Desktop) is pointed at THIS process; the proxy spawns and
guards the downstream server. Example client config entry:

    {
      "mcpServers": {
        "guarded-echo": {
          "command": "python",
          "args": ["examples/run_proxy.py"]
        }
      }
    }

This wiring is intentionally explicit (one scoped agent identity, an explicit
capability map). In production you would load these from config per tenant.
"""
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from capguard import AgentIdentity, Capability, PolicyEngine, Severity  # noqa: E402
from capguard.approval import ApprovalStore  # noqa: E402
from capguard.audit import HashChainedSink  # noqa: E402
from capguard.mcp_guard import MCPGuard, explicit_mapper  # noqa: E402
from capguard.mcp_proxy import MCPProxy, StdioDownstream, StdioServer  # noqa: E402


def build() -> MCPProxy:
    here = os.path.dirname(os.path.abspath(__file__))
    downstream = StdioDownstream("echo", [sys.executable, os.path.join(here, "echo_mcp_server.py")])

    guard = MCPGuard(
        engine=PolicyEngine(),
        audit_sink=HashChainedSink(os.path.join(here, "proxy_audit.jsonl")),
        approval_store=ApprovalStore(),
        capability_mapper=explicit_mapper({
            "echo": ([Capability.custom("echo")], Severity.LOW),
        }),
    )
    agent = AgentIdentity(
        id="desktop-agent",
        roles=["assistant"],
        allowed_capabilities=[Capability.custom("echo")],
    )
    return MCPProxy(guard=guard, agent=agent, downstreams=[downstream])


if __name__ == "__main__":
    StdioServer(build()).serve()
