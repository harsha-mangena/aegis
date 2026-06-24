"""FastAPI control-plane service: ingest + dashboard (observe-only).

Tenants stream their hash-chained audit trail to ``POST /v1/audit`` (via
``capguard.audit.HttpSink``); the service verifies the chain server-side and
serves a live dashboard. It never participates in enforcement — purely
observe + (future) policy push. Bearer API keys isolate tenants.
"""

from __future__ import annotations

import os
from typing import Dict, Optional

from capguard.audit import AuditEvent
from capguard.mcp_auth import extract_bearer

from .store import CloudStore

# OWASP ASI-2026 coverage board (mirrors README / docs/security-model.md).
ASI_COVERAGE = [
    {"risk": "ASI01 Goal/behavior hijack", "status": "covered", "mechanism": "propagated provenance + advisory detectors"},
    {"risk": "ASI02 Tool misuse", "status": "covered", "mechanism": "attenuation + argument DSL + normalize + task scopes"},
    {"risk": "ASI03 Identity & privilege abuse", "status": "covered", "mechanism": "signed identity, delegation only attenuates"},
    {"risk": "ASI04 Agentic supply chain", "status": "covered", "mechanism": "MCP pinning + poisoning/rug-pull/shadow scan"},
    {"risk": "ASI05 Unexpected code execution", "status": "covered", "mechanism": "sandbox backends"},
    {"risk": "ASI06 Memory/context poisoning", "status": "covered", "mechanism": "provenance-preserving memory"},
    {"risk": "ASI07 Insecure inter-agent comms", "status": "covered", "mechanism": "signed A2A + per-message attenuation"},
    {"risk": "ASI08 Cascading failures", "status": "covered", "mechanism": "budgets + circuit-breaker kill switch"},
    {"risk": "ASI09 Human-agent trust", "status": "covered", "mechanism": "replay-safe approval tokens"},
    {"risk": "ASI10 Rogue agents", "status": "covered", "mechanism": "audit-stream anomaly detection"},
]


def create_app(store: Optional[CloudStore] = None,
               api_keys: Optional[Dict[str, str]] = None,
               title: str = "CapGuard Control Plane",
               policy_signer=None):
    """Build the FastAPI app. ``api_keys`` maps bearer token -> tenant id.

    ``policy_signer`` (a ``capguard.identity.Signer``) enables signed policy push:
    guards pull ``GET /v1/policy`` and verify the signature locally before applying.
    """
    from fastapi import Body, Depends, FastAPI, Header, HTTPException
    from fastapi.responses import HTMLResponse

    store = store or CloudStore()
    api_keys = dict(api_keys or {})
    app = FastAPI(title=title, version="0.1.0")
    app.state.store = store
    app.state.api_keys = api_keys

    def tenant(authorization: Optional[str] = Header(default=None)) -> str:
        token = extract_bearer(authorization)
        tid = api_keys.get(token) if token else None
        if tid is None:
            raise HTTPException(status_code=401, detail="missing or invalid API key",
                                headers={"WWW-Authenticate": "Bearer"})
        return tid

    @app.post("/v1/audit")
    def ingest(event: AuditEvent, tenant_id: str = Depends(tenant)):
        n = store.ingest(tenant_id, event)
        return {"accepted": 1, "tenant_events": n, "chain_ok": store.chain_ok(tenant_id)}

    @app.get("/v1/decisions")
    def decisions(limit: int = 50, tenant_id: str = Depends(tenant)):
        return {"decisions": store.decisions(tenant_id, limit)}

    @app.get("/v1/stats")
    def stats(tenant_id: str = Depends(tenant)):
        return store.stats(tenant_id)

    @app.get("/v1/flows")
    def flows(tenant_id: str = Depends(tenant)):
        return store.flows(tenant_id)

    @app.put("/v1/policy")
    def set_policy(pack: dict = Body(...), tenant_id: str = Depends(tenant)):
        if policy_signer is None:
            raise HTTPException(status_code=501, detail="policy signing not configured")
        sp = store.set_policy(tenant_id, pack, policy_signer)
        return {"version": sp.version, "alg": sp.alg}

    @app.get("/v1/policy")
    def get_policy(tenant_id: str = Depends(tenant)):
        sp = store.get_policy(tenant_id)
        if sp is None:
            raise HTTPException(status_code=404, detail="no policy set for this tenant")
        return sp.to_dict()

    @app.get("/v1/coverage")
    def coverage():
        return {"owasp_asi_2026": ASI_COVERAGE}

    @app.get("/healthz")
    def healthz():
        return {"ok": True}

    @app.get("/", response_class=HTMLResponse)
    def dashboard():
        return _DASHBOARD_HTML

    return app


def main() -> int:  # console-script entry: `capguard-cloud`
    import uvicorn
    key = os.environ.get("CAPGUARD_CLOUD_KEY", "demo-key")
    tenant = os.environ.get("CAPGUARD_CLOUD_TENANT", "demo")
    app = create_app(api_keys={key: tenant})
    host = os.environ.get("CAPGUARD_CLOUD_HOST", "127.0.0.1")
    port = int(os.environ.get("CAPGUARD_CLOUD_PORT", "8088"))
    print(f"CapGuard control plane on http://{host}:{port}  (tenant {tenant!r}, key {key!r})")
    uvicorn.run(app, host=host, port=port)
    return 0


# A self-contained dashboard: paste your tenant API key, it polls /v1/* and renders
# stats, the blocked-attack feed, tainted flow paths, and the ASI coverage board.
_DASHBOARD_HTML = """<!doctype html><html><head><meta charset="utf-8">
<title>CapGuard Control Plane</title>
<style>
 body{font:14px/1.5 system-ui,sans-serif;margin:0;background:#0b0f17;color:#e6edf3}
 header{padding:16px 24px;background:#111827;border-bottom:1px solid #1f2937;display:flex;gap:12px;align-items:center}
 h1{font-size:18px;margin:0;font-weight:700}
 main{padding:24px;display:grid;gap:20px;grid-template-columns:repeat(auto-fit,minmax(320px,1fr))}
 .card{background:#111827;border:1px solid #1f2937;border-radius:10px;padding:16px}
 .card h2{font-size:13px;text-transform:uppercase;letter-spacing:.05em;color:#9ca3af;margin:0 0 10px}
 input{background:#0b0f17;border:1px solid #374151;color:#e6edf3;border-radius:6px;padding:6px 10px}
 table{width:100%;border-collapse:collapse;font-size:13px}
 td,th{text-align:left;padding:4px 6px;border-bottom:1px solid #1f2937}
 .deny{color:#f87171;font-weight:600}.allow{color:#34d399}.require_approval{color:#fbbf24}
 .ok{color:#34d399}.bad{color:#f87171}
 .big{font-size:28px;font-weight:700}
</style></head><body>
<header><h1>🛡 CapGuard Control Plane</h1>
 <input id="key" placeholder="tenant API key" />
 <button onclick="refresh()">Connect</button>
 <span id="chain"></span></header>
<main>
 <div class="card"><h2>Stats</h2><div id="stats">—</div></div>
 <div class="card"><h2>Blocked / decisions feed</h2><div id="decisions">—</div></div>
 <div class="card"><h2>Untrusted → sink flows</h2><div id="flows">—</div></div>
 <div class="card"><h2>OWASP ASI 2026 coverage</h2><div id="coverage">—</div></div>
</main>
<script>
async function get(p){const k=document.getElementById('key').value;
 const r=await fetch(p,{headers:{Authorization:'Bearer '+k}});return r.ok?r.json():null;}
async function refresh(){
 const s=await get('/v1/stats'); const d=await get('/v1/decisions'); const f=await get('/v1/flows');
 const c=await get('/v1/coverage');
 if(!s){document.getElementById('chain').textContent='⚠ invalid key';return;}
 document.getElementById('chain').innerHTML = s.chain_ok?'<span class=ok>● audit chain verified</span>':'<span class=bad>● CHAIN BROKEN</span>';
 document.getElementById('stats').innerHTML =
   `<div class=big>${s.total}</div>calls · <span class=deny>${s.blocked} blocked</span> · ${s.approvals} approvals<br>agents: ${s.agents.join(', ')||'—'}`;
 document.getElementById('decisions').innerHTML = '<table><tr><th>tool</th><th>agent</th><th>decision</th></tr>'+
   (d.decisions||[]).map(x=>`<tr><td>${x.tool}</td><td>${x.agent}</td><td class=${x.decision}>${x.decision}</td></tr>`).join('')+'</table>';
 document.getElementById('flows').innerHTML = f.tainted_sinks.length
   ? f.tainted_sinks.map(t=>`<div class=deny>⚠ #${t.index} ${t.tool} (agent ${t.agent}) ← untrusted</div>`).join('')
   : `<span class=ok>no untrusted→sink paths (${f.nodes} calls, ${f.edges} edges)</span>`;
 document.getElementById('coverage').innerHTML = '<table>'+
   c.owasp_asi_2026.map(r=>`<tr><td>${r.risk}</td><td class=ok>✓</td></tr>`).join('')+'</table>';
}
</script></body></html>"""
