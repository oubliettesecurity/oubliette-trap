"""Security-review regression tests (2026-07-02).

Covers:
  1. [CRITICAL] webhook forges licenses without verification
     (the webhook moved to oubliette-commerce with product-scoped licensing;
     its regression tests live there now)
  2. [VERIFY]   license fails OPEN when no signing key configured
  3. [HIGH]     source_ip hardcoded "unknown" in the real MCP path
  4. [MEDIUM]   unbounded sessions/profiles dicts
  5. [MEDIUM]   unbounded per-session call/probe history lists
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json

import pytest

from oubliette_trap.license import LicenseManager

# ---------------------------------------------------------------------------
# 2. [VERIFY] license must fail CLOSED when no signing key is configured
# ---------------------------------------------------------------------------


def test_no_signing_key_forces_free_tier(monkeypatch):
    """A legacy HMAC-signed license must not grant Pro, even when the old
    signing-key variable is set: schema v2 has no HMAC path at all."""
    body = {"tier": "pro", "org": "Acme", "features": []}
    payload = json.dumps(body, sort_keys=True, separators=(",", ":"))
    sig = hmac.new(b"secret", payload.encode(), hashlib.sha256).hexdigest()
    key = base64.b64encode(json.dumps({**body, "sig": sig}).encode()).decode()
    monkeypatch.setenv("OUBLIETTE_LICENSE_SIGNING_KEY", "secret")
    mgr = LicenseManager()
    mgr._load_license(key)
    assert mgr.license.tier == "free", "unsigned/unverifiable license must not grant Pro"


# ---------------------------------------------------------------------------
# 3. [HIGH] real source IP must be extracted, not hardcoded "unknown"
# ---------------------------------------------------------------------------


class _FakeClient:
    def __init__(self, host: str):
        self.host = host


class _FakeRequest:
    def __init__(self, host: str, headers: dict | None = None):
        self.client = _FakeClient(host)
        self.headers = headers or {}


def test_extract_source_ip_direct_peer():
    from oubliette_trap.server import _extract_source_ip

    req = _FakeRequest("203.0.113.9")
    assert _extract_source_ip(req, trust_proxy=False) == "203.0.113.9"


def test_extract_source_ip_ignores_xff_when_untrusted():
    from oubliette_trap.server import _extract_source_ip

    req = _FakeRequest("10.0.0.1", {"x-forwarded-for": "198.51.100.7, 10.0.0.1"})
    assert _extract_source_ip(req, trust_proxy=False) == "10.0.0.1"


def test_extract_source_ip_honors_xff_behind_trusted_proxy():
    from oubliette_trap.server import _extract_source_ip

    req = _FakeRequest("10.0.0.1", {"x-forwarded-for": "198.51.100.7, 10.0.0.1"})
    assert _extract_source_ip(req, trust_proxy=True) == "198.51.100.7"


def test_extract_source_ip_stdio_has_none():
    from oubliette_trap.server import _extract_source_ip

    assert _extract_source_ip(None, trust_proxy=False) == "unknown"


def test_derive_session_identity_populates_ip_from_request():
    from oubliette_trap.server import _derive_session_identity

    class _RC:
        request = _FakeRequest("203.0.113.55")

    class _Ctx:
        client_id = "client-42"
        request_context = _RC()

    session_id, source_ip = _derive_session_identity(_Ctx())
    assert session_id == "client-42"
    assert source_ip == "203.0.113.55"


# ---------------------------------------------------------------------------
# 4. [MEDIUM] sessions/profiles dicts must be bounded
# ---------------------------------------------------------------------------


def test_sessions_and_profiles_bounded(tmp_path, monkeypatch):
    monkeypatch.setenv("OUBLIETTE_MAX_SESSIONS", "3")
    from oubliette_trap.server import OublietteTrap

    trap = OublietteTrap(storage_dir=str(tmp_path))
    for i in range(12):
        trap.handle_tool_call("whoami", {}, session_id=f"s{i}", source_ip="1.1.1.1")
    assert len(trap.sessions) <= 3
    assert len(trap.profiles) <= 3


# ---------------------------------------------------------------------------
# 5. [MEDIUM] per-session call/probe history must be bounded
# ---------------------------------------------------------------------------


def test_call_and_probe_history_bounded(monkeypatch):
    monkeypatch.setenv("OUBLIETTE_MAX_CALL_HISTORY", "5")
    from oubliette_trap.deception.session import DeceptionSession

    s = DeceptionSession(session_id="x", source_ip="1.1.1.1")
    for _ in range(50):
        s.record_tool_call("whoami", {})
    assert len(s.tools_called) <= 5
    assert len(s.call_timestamps) <= 5
    assert len(s.inter_call_timings_ms) <= 5

    for i in range(50):
        s.record_probe_sent(f"p{i}")
    assert len(s.probes_sent) <= 5
