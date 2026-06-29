# Quickstart

```bash
pip install capguard-runtime
```

The distribution is named `capguard-runtime` on PyPI; the Python package and CLI
remain `capguard`. The `agentguard` import alias is available for the simplified
`AgentGuard` facade.

## 60 seconds: guard any agent's tools

```python
from agentguard import AgentGuard

guard = AgentGuard("support-agent")

@guard.tool(network=["api.example.com"])
def search(url: str) -> str:
    return http_get(url)

search(url="https://api.example.com/docs")      # allowed
search(url="https://evil.example/steal")        # denied
```

`AgentGuard` creates the runtime, identity, provenance tracker, and default OWASP
policy for you. Pass the guarded callables to whatever agent framework you use.

```python
agent = create_agent(model="gpt-4o", tools=guard.langchain_tools())
```

Or wrap an existing agent object:

```python
from agentguard import guard_agent

secured = guard_agent(existing_agent, tools=[search], framework="langchain")
agent = secured.bind()       # uses bind_tools(...) when the framework exposes it
```

See the live demo:

```bash
python -m capguard.cli version
python examples/simple_agentguard.py    # guard tools for any agent/framework
python examples/demo_poison_strip.py     # poisoned MCP tool stripped + guarded transfer
```

## Embed under your framework

```python
from agentguard import AgentGuard

guard = AgentGuard("research-agent")

@guard.tool(network=["api.corp.com"])
def search(url: str) -> str:
    ...

lc_tool = search.as_langchain()      # native LangChain StructuredTool, still guarded
```

`search.as_openai_agents()` and `search.as_crewai()` work the same way. CapGuard
runs **underneath** your framework; the LLM provider can be OpenAI, Anthropic,
Gemini, local models, or anything else because the action boundary is the same.

## Adopt a strong default in one line

```python
from capguard import compile_pack
engine = compile_pack("owasp-baseline")   # or "finance", "data-exfil"
```

## Stop a laundered injection with propagated provenance

```python
from agentguard import AgentGuard

guard = AgentGuard("rag-agent")

@guard.tool(name="send_message", capability="send_message")
def send_message(channel: str, text: str) -> str:
    return "sent"

poisoned = guard.untrusted(retriever.invoke("invoice instructions"), source="rag")
guard.invoke("send_message", channel="#x", text=poisoned)        # DENIED by default sink policy
```
