"""Security-review regression tests (2026-07-02).

Covers:
  1. [CRITICAL] webhook forges licenses without verification
  2. [VERIFY]   license fails OPEN when no signing key configured
  3. [HIGH]     source_ip hardcoded "unknown" in the real MCP path
  4. [MEDIUM]   unbounded sessions/profiles dicts
  5. [MEDIUM]   unbounded per-session call/probe history lists
"""

from __future__ import annotations

import hashlib
import hmac
import time

import pytest

from oubliette_trap.license import LicenseManager
from oubliette_trap.license_issuer import issue_license
from oubliette_trap.license_webhook import license_for_sale

_PMAP = {"oubliette-trap-pro": {"tier": "pro"}}


# ---------------------------------------------------------------------------
# 1. [CRITICAL] webhook must verify before issuing a signed license
# ---------------------------------------------------------------------------


def test_webhook_rejects_unverified_gumroad():
    """No token at all -> reject. Anyone POSTing a permalink must NOT get a key."""
    with pytest.raises(PermissionError):
        license_for_sale(
            {"product_permalink": "oubliette-trap-pro", "email": "a@b.com"},
            _PMAP,
            "sign",
            webhook_secret="shared",
        )


def test_webhook_rejects_wrong_token():
    with pytest.raises(PermissionError):
        license_for_sale(
            {
                "product_permalink": "oubliette-trap-pro",
                "email": "a@b.com",
                "webhook_token": "not-the-secret",
            },
            _PMAP,
            "sign",
            webhook_secret="shared",
        )


def test_webhook_issues_with_valid_token():
    res = license_for_sale(
        {
            "product_permalink": "oubliette-trap-pro",
            "email": "a@b.com",
            "full_name": "Acme",
            "webhook_token": "shared",
        },
        _PMAP,
        "sign",
        webhook_secret="shared",
    )
    assert res is not None and res["tier"] == "pro"
    mgr = LicenseManager(signing_key="sign")
    mgr._load_license(res["license_key"])
    assert mgr.license.tier == "pro"


def test_webhook_requires_configured_secret():
    """An empty shared secret must fail closed, not skip verification."""
    with pytest.raises(ValueError):
        license_for_sale(
            {"product_permalink": "oubliette-trap-pro", "webhook_token": "x"},
            _PMAP,
            "sign",
            webhook_secret="",
        )


def test_webhook_paddle_signature_accepted():
    from oubliette_trap.license_webhook import verify_paddle_signature

    secret = "paddle-sec"
    raw = b"whatever=1"
    ts = str(int(time.time()))
    h1 = hmac.new(secret.encode(), f"{ts}:".encode() + raw, hashlib.sha256).hexdigest()
    headers = {"Paddle-Signature": f"ts={ts};h1={h1}"}
    assert verify_paddle_signature(raw, headers, secret) is True


def test_webhook_paddle_signature_rejected():
    from oubliette_trap.license_webhook import verify_paddle_signature

    headers = {"Paddle-Signature": "ts=123;h1=deadbeef"}
    assert verify_paddle_signature(b"x", headers, "paddle-sec") is False


# ---------------------------------------------------------------------------
# 2. [VERIFY] license must fail CLOSED when no signing key is configured
# ---------------------------------------------------------------------------


def test_no_signing_key_forces_free_tier():
    key = issue_license(org="Acme", tier="pro", signing_key="secret")
    mgr = LicenseManager(signing_key="")  # server misconfigured / no key
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
