"""Tests for the FastAPI control-plane service (Phase 2, slice 2).

Run in-process with Starlette's TestClient — no real server, DB, or network.
Skipped if FastAPI isn't installed (the `cloud` extra).
"""

from __future__ import annotations

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from capguard import (  # noqa: E402
    UNTRUSTED_WEB,
    AgentIdentity,
    AgentRuntime,
    Capability,
    ProvenanceTracker,
    Severity,
    ToolRegistry,
    ToolSpec,
)
from capguard.audit import GENESIS, AuditEvent, MemorySink  # noqa: E402
from capguard.core import PolicyDecision  # noqa: E402
from capguard_cloud import create_app  # noqa: E402

KEYS = {"kA": "tenantA", "kB": "tenantB"}


def _client():
    return TestClient(create_app(api_keys=dict(KEYS)))


def _post(client, key, event):
    return client.post("/v1/audit", headers={"Authorization": f"Bearer {key}",
                                             "Content-Type": "application/json"},
                       content=event.model_dump_json())


def _sealed(n, agent="bot", head=GENESIS):
    evs = []
    for i in range(n):
        e = AuditEvent(agent_id=agent, tool_name=f"t{i}", decision=PolicyDecision.ALLOW)
        e.seal(head)
        head = e.hash
        evs.append(e)
    return evs


# --------------------------------------------------------------------------- #
# auth + ingest
# --------------------------------------------------------------------------- #
def test_auth_required():
    c = _client()
    assert c.get("/v1/decisions").status_code == 401
    assert c.get("/v1/decisions", headers={"Authorization": "Bearer nope"}).status_code == 401
    assert _post(c, "nope", _sealed(1)[0]).status_code == 401


def test_ingest_and_chain_ok():
    c = _client()
    for e in _sealed(3):
        r = _post(c, "kA", e)
        assert r.status_code == 200
    body = c.get("/v1/stats", headers={"Authorization": "Bearer kA"}).json()
    assert body["total"] == 3 and body["chain_ok"] is True


def test_tenant_isolation():
    c = _client()
    for e in _sealed(2):
        _post(c, "kA", e)
    other = c.get("/v1/stats", headers={"Authorization": "Bearer kB"}).json()
    assert other["total"] == 0


def test_server_side_tamper_detection():
    c = _client()
    e0, = _sealed(1)
    _post(c, "kA", e0)
    # a second event whose prev_hash does NOT chain from e0 -> server flags chain broken
    bad = AuditEvent(agent_id="bot", tool_name="t1", decision=PolicyDecision.ALLOW)
    bad.seal("0" * 64)  # wrong predecessor
    _post(c, "kA", bad)
    assert c.get("/v1/stats", headers={"Authorization": "Bearer kA"}).json()["chain_ok"] is False


# --------------------------------------------------------------------------- #
# flows + coverage + dashboard
# --------------------------------------------------------------------------- #
def _laundering_events():
    tracker = ProvenanceTracker()
    sink = MemorySink()
    reg = ToolRegistry()
    reg.register(ToolSpec(name="web_fetch", capabilities=[Capability.custom("web")],
                          severity=Severity.LOW, output_label=UNTRUSTED_WEB), lambda **k: "ATTACKER")
    reg.register(ToolSpec(name="send_message", capabilities=[Capability.custom("slack")],
                          severity=Severity.LOW), lambda **k: "ok")
    agent = AgentIdentity(id="bot", allowed_capabilities=[Capability.custom("web"), Capability.custom("slack")])
    rt = AgentRuntime(registry=reg, default_agent=agent, audit_sink=sink, tracker=tracker)
    poisoned = rt.invoke_tool("web_fetch", url="https://evil.com")
    rt.invoke_tool("send_message", channel="#x", text=poisoned)
    return sink.events


def test_flows_surface_tainted_sink():
    c = _client()
    for e in _laundering_events():
        _post(c, "kA", e)
    flows = c.get("/v1/flows", headers={"Authorization": "Bearer kA"}).json()
    assert any(t["tool"] == "send_message" for t in flows["tainted_sinks"])


def test_coverage_and_dashboard():
    c = _client()
    cov = c.get("/v1/coverage").json()["owasp_asi_2026"]
    assert len(cov) == 10 and all(r["status"] == "covered" for r in cov)
    html = c.get("/")
    assert html.status_code == 200 and "CapGuard Control Plane" in html.text
    assert c.get("/healthz").json() == {"ok": True}
