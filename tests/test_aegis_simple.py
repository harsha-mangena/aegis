"""Tests for the aegis simplified API."""

from __future__ import annotations

import pytest

# Reset module-level singleton before each test
import aegis
from aegis import Aegis, configure, guard, observe, reset


@pytest.fixture(autouse=True)
def _clean():
    reset()
    yield
    reset()


# ------------------------------------------------------------------ #
# Basic guard decorator
# ------------------------------------------------------------------ #


class TestGuardDecorator:
    """The @guard decorator should work on any function."""

    def test_guard_simple_function(self):
        ag = Aegis()

        @ag.guard()
        def greet(name: str) -> str:
            return f"hello {name}"

        assert greet("world") == "hello world"

    def test_guard_with_network(self):
        ag = Aegis()

        @ag.guard(network=True)
        def fetch(url: str) -> str:
            return f"fetched {url}"

        result = fetch("https://example.com")
        assert result == "fetched https://example.com"

    def test_guard_with_scoped_network(self):
        ag = Aegis()

        @ag.guard(network=["api.example.com"])
        def fetch(url: str) -> str:
            return f"fetched {url}"

        result = fetch("https://api.example.com/data")
        assert result == "fetched https://api.example.com/data"

    def test_guard_network_blocks_wrong_domain(self):
        ag = Aegis()

        @ag.guard(network=["api.example.com"])
        def fetch(url: str) -> str:
            return f"fetched {url}"

        with pytest.raises(Exception):
            fetch("https://evil.com/steal")

    def test_guard_with_file_read(self):
        ag = Aegis()

        @ag.guard(file_read=True)
        def read(path: str) -> str:
            return f"read {path}"

        assert read("/tmp/test.txt") == "read /tmp/test.txt"

    def test_guard_with_shell(self):
        ag = Aegis()

        @ag.guard(shell=["ls", "cat"])
        def run(cmd: str) -> str:
            return f"ran {cmd}"

        assert run("ls -la") == "ran ls -la"

    def test_guard_shell_blocks_unlisted_command(self):
        ag = Aegis()

        @ag.guard(shell=["ls", "cat"])
        def run(cmd: str) -> str:
            return f"ran {cmd}"

        with pytest.raises(Exception):
            run("rm -rf /")

    def test_guard_shell_blocks_metacharacters(self):
        ag = Aegis()

        @ag.guard(shell=["ls"])
        def run(cmd: str) -> str:
            return f"ran {cmd}"

        with pytest.raises(Exception):
            run("ls; rm -rf /")

    def test_guard_with_db(self):
        ag = Aegis()

        @ag.guard(db=True)
        def query(query: str) -> str:
            return f"result of {query}"

        assert query("SELECT * FROM users") == "result of SELECT * FROM users"

    def test_guard_with_custom(self):
        ag = Aegis()

        @ag.guard(custom="send_email")
        def send(to: str, body: str) -> str:
            return f"sent to {to}"

        assert send("alice@example.com", "hello") == "sent to alice@example.com"


# ------------------------------------------------------------------ #
# Module-level guard (zero-config)
# ------------------------------------------------------------------ #


class TestModuleLevelGuard:
    """Module-level ``guard`` should work without explicit Aegis instance."""

    def test_module_guard(self):
        @guard()
        def ping() -> str:
            return "pong"

        assert ping() == "pong"

    def test_module_guard_with_kwargs(self):
        @guard(network=True)
        def fetch(url: str) -> str:
            return f"fetched {url}"

        assert fetch("https://example.com") == "fetched https://example.com"


# ------------------------------------------------------------------ #
# Configure
# ------------------------------------------------------------------ #


class TestConfigure:
    """``configure`` should set up the default instance."""

    def test_configure_with_pack(self):
        ag = configure(pack="owasp-baseline")
        assert ag is not None

    def test_configure_with_audit_file(self, tmp_path):
        log = str(tmp_path / "audit.jsonl")
        ag = configure(audit=log)

        @ag.guard()
        def noop() -> str:
            return "ok"

        noop()
        assert (tmp_path / "audit.jsonl").exists()


# ------------------------------------------------------------------ #
# Provenance tracking
# ------------------------------------------------------------------ #


class TestProvenance:
    """Provenance observation and taint tracking."""

    def test_observe_marks_value(self):
        ag = Aegis()
        ag.observe("user input from web", "web")
        label = ag.tracker.label_for("user input from web")
        assert label is not None
        assert label.trust.value == 0  # UNTRUSTED_WEB

    def test_source_label_on_tool(self):
        ag = Aegis()

        @ag.guard(network=True, source="web")
        def fetch(url: str) -> str:
            return "data from internet"

        result = fetch("https://example.com")
        label = ag.tracker.label_for(result)
        assert label is not None
        assert label.trust.value == 0  # UNTRUSTED_WEB


# ------------------------------------------------------------------ #
# Risk levels and severity
# ------------------------------------------------------------------ #


class TestRiskLevels:
    """Risk parameter maps to severity correctly."""

    def test_low_risk_auto_allows(self):
        ag = Aegis()

        @ag.guard(risk="low")
        def safe_tool() -> str:
            return "ok"

        assert safe_tool() == "ok"

    def test_high_risk_requires_approval(self):
        ag = Aegis()

        @ag.guard(risk="high")
        def dangerous() -> str:
            return "boom"

        with pytest.raises(Exception):
            dangerous()

    def test_approval_flag_escalates_severity(self):
        ag = Aegis()

        @ag.guard(approval=True)
        def needs_ok() -> str:
            return "ok"

        with pytest.raises(Exception):
            needs_ok()


# ------------------------------------------------------------------ #
# Audit trail
# ------------------------------------------------------------------ #


class TestAudit:
    """Every guarded call produces an audit event."""

    def test_audit_events_recorded(self):
        ag = Aegis()

        @ag.guard()
        def greet(name: str) -> str:
            return f"hi {name}"

        greet("world")
        assert len(ag.events) >= 1
        assert ag.events[-1].tool_name == "greet"

    def test_audit_records_denial(self):
        ag = Aegis()

        @ag.guard(shell=["ls"])
        def run(cmd: str) -> str:
            return cmd

        try:
            run("rm -rf /")
        except Exception:
            pass

        denied = [e for e in ag.events if e.decision == "deny"]
        assert len(denied) >= 1


# ------------------------------------------------------------------ #
# Policy packs
# ------------------------------------------------------------------ #


class TestPolicyPacks:
    """Built-in packs should load and enforce."""

    def test_owasp_baseline_loads(self):
        ag = Aegis(pack="owasp-baseline")
        assert ag.runtime is not None

    def test_finance_pack_loads(self):
        ag = Aegis(pack="finance")
        assert ag.runtime is not None


# ------------------------------------------------------------------ #
# Metadata and introspection
# ------------------------------------------------------------------ #


class TestMetadata:
    """Guarded functions retain metadata for introspection."""

    def test_aegis_marker(self):
        ag = Aegis()

        @ag.guard(network=True)
        def fetch(url: str) -> str:
            return url

        assert fetch._aegis is True
        assert fetch._aegis_name == "fetch"

    def test_functools_wraps_preserved(self):
        ag = Aegis()

        @ag.guard()
        def my_func():
            """My docstring."""
            pass

        assert my_func.__name__ == "my_func"
        assert my_func.__doc__ == "My docstring."

    def test_custom_name_override(self):
        ag = Aegis()

        @ag.guard(name="custom_name")
        def original():
            return "ok"

        assert original._aegis_name == "custom_name"


# ------------------------------------------------------------------ #
# Positional args conversion
# ------------------------------------------------------------------ #


class TestPositionalArgs:
    """Positional args should be converted to kwargs transparently."""

    def test_positional_and_keyword_mixed(self):
        ag = Aegis()

        @ag.guard()
        def add(a: int, b: int) -> int:
            return a + b

        assert add(2, 3) == 5
        assert add(a=2, b=3) == 5
        assert add(2, b=3) == 5


# ------------------------------------------------------------------ #
# Multiple tools on same instance
# ------------------------------------------------------------------ #


class TestMultipleTools:
    """Multiple tools can be registered on the same Aegis instance."""

    def test_two_tools(self):
        ag = Aegis()

        @ag.guard(network=True)
        def search(url: str) -> str:
            return f"searched {url}"

        @ag.guard(file_read=True)
        def read(path: str) -> str:
            return f"read {path}"

        assert search("https://example.com") == "searched https://example.com"
        assert read("/tmp/test") == "read /tmp/test"

    def test_tools_share_provenance(self):
        ag = Aegis()

        @ag.guard(network=True, source="web")
        def fetch(url: str) -> str:
            return "untrusted data"

        @ag.guard()
        def process(data: str) -> str:
            return f"processed: {data}"

        raw = fetch("https://example.com")
        result = process(raw)
        assert result == "processed: untrusted data"


# ------------------------------------------------------------------ #
# Monitor integration
# ------------------------------------------------------------------ #


class TestMonitor:
    """Monitor flag enables behavior monitoring."""

    def test_monitor_enabled(self):
        ag = Aegis(monitor=True)
        assert ag._monitor is not None

    def test_monitor_disabled_by_default(self):
        ag = Aegis()
        assert ag._monitor is None
