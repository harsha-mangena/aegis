# Quickstart

```bash
pip install aegisguard
```

## 30 seconds: guard any tool

```python
from aegis import guard

@guard(network=["api.example.com"])
def search(url: str) -> str:
    return http_get(url)

search(url="https://api.example.com/docs")      # allowed
search(url="https://evil.example/steal")         # BLOCKED
```

## Configured instance with policy pack

```python
from aegis import Aegis

ag = Aegis(
    pack="owasp-baseline",
    agent_id="support-agent",
    audit="audit.jsonl",
)

@ag.guard(network=["api.example.com"])
def search(url: str) -> str: ...

@ag.guard(shell=["ls", "cat", "grep"])
def run_cmd(cmd: str) -> str: ...

@ag.guard(custom="send_email", risk="high")
def send_email(to: str, body: str) -> str: ...
```

## Run the demos

```bash
python examples/demo_local_no_api.py     # 40 enforcement tests, no API key
python examples/demo_with_aegis.py       # OpenAI agent with aegisguard (needs OPENAI_API_KEY)
python examples/demo_comparison.py       # side-by-side: unprotected vs protected
```

## Adopt a strong default in one line

```python
from aegis import Aegis
ag = Aegis(pack="owasp-baseline")   # or "finance", "data-exfil", "healthcare"
```

## CLI

```bash
aegis bench                          # security benchmark gate
aegis audit verify audit.jsonl       # check tamper-evident hash chain
aegis packs list                     # list builtin policy packs
```
