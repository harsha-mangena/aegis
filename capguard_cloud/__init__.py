"""CapGuard control plane (commercial wedge).

The OSS core (``capguard``, Apache-2.0) is the enforcement runtime that ships
inside the agent. This package is the **hosted control plane**: it *observes*
fleets of guards and *pushes* policy — it never participates in the enforcement
decision, so if the control plane is down, every local guard keeps enforcing,
fail-closed. (Licensing for this package may differ from the Apache-2.0 core.)

Slice 1 (in core): ``capguard.audit.HttpSink`` streams the hash-chained audit
trail here, fail-open.

This slice: a FastAPI service that ingests those events per tenant, verifies the
hash chain server-side, and serves a live dashboard — recent decisions, the
blocked-attack feed, reconstructed untrusted→sink flow graphs, and the OWASP ASI
coverage board. In-memory store for the MVP/demo (swap for Postgres later);
tenant isolation via bearer API keys.
"""

from .app import ASI_COVERAGE, create_app
from .store import CloudStore

__all__ = ["CloudStore", "create_app", "ASI_COVERAGE"]
