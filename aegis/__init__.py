"""
Aegis -- Universal AI Agent Security.

One decorator. Any framework. Full protection.

    from aegis import guard

    @guard(network=True)
    def search(query: str) -> str:
        return requests.get(f"https://api.example.com?q={query}").text

    @guard(tools=[search])
    def my_agent(query: str) -> str:
        return llm.chat(query, context=search(query))

Or configure once, guard everything:

    from aegis import Aegis

    ag = Aegis(pack="owasp-baseline", audit="audit.jsonl")

    @ag.guard(network=True, risk="high")
    def fetch(url: str) -> str: ...
"""

__version__ = "0.1.0"

from .core import Aegis, configure, guard, observe, reset

__all__ = [
    "Aegis",
    "guard",
    "configure",
    "observe",
    "reset",
]
