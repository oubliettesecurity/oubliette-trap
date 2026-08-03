"""Issued licenses must be verifiable by a standard install.

`LicenseManager` verifies an HMAC-signed license only when a signing key is
configured locally, and correctly refuses otherwise -- verifying a symmetric
signature on the client would mean shipping the secret that mints licenses.
A normal customer install therefore has no signing key, so an HMAC-signed
license falls back to the free tier.

That makes HMAC minting a silent-downgrade path: the sale succeeds, the key is
delivered, and the customer sits on free tier with nothing in the flow
reporting a problem. The issuer must refuse to mint asymmetric-unverifiable
licenses unless the caller explicitly opts in for a client that already holds
the key.

Mirrors the same contract in oubliette-shield.
"""

from __future__ import annotations

import base64
import json

import pytest

from oubliette_trap.license import LicenseManager
from oubliette_trap.license_issuer import generate_keypair, issue_license


@pytest.fixture(autouse=True)
def no_ambient_keys(monkeypatch):
    """The defect only shows with no key in the environment.

    Without this, a developer's own configured key makes every mint succeed and
    the test passes for a reason unrelated to the code.
    """
    monkeypatch.delenv("OUBLIETTE_LICENSE_PRIVATE_KEY", raising=False)
    monkeypatch.delenv("OUBLIETTE_LICENSE_SIGNING_KEY", raising=False)
    monkeypatch.delenv("OUBLIETTE_LICENSE_KEY", raising=False)


def _tier_of(key: str, **manager_kwargs) -> str:
    manager = LicenseManager(**manager_kwargs)
    manager._load_license(key)
    return manager.license.tier


def test_minting_with_only_a_symmetric_key_is_refused():
    with pytest.raises(ValueError, match="Ed25519"):
        issue_license(org="Acme", tier="pro", signing_key="s3cret")


def test_the_refusal_explains_what_to_do():
    with pytest.raises(ValueError) as ei:
        issue_license(org="Acme", tier="pro", signing_key="s3cret")
    message = str(ei.value)
    assert "OUBLIETTE_LICENSE_PRIVATE_KEY" in message
    assert "allow_hmac" in message


def test_an_ed25519_license_verifies_on_a_standard_install():
    priv, pub = generate_keypair()
    key = issue_license(org="Acme", tier="pro", private_key=priv)
    assert _tier_of(key, public_key=pub) == "pro"


def test_explicit_opt_in_still_allows_the_legacy_scheme():
    """Kept deliberately: licences issued before the asymmetric switch."""
    key = issue_license(org="Acme", tier="pro", signing_key="s3cret", allow_hmac=True)
    assert json.loads(base64.b64decode(key))["sig_alg"] == "hmac"
    assert _tier_of(key, signing_key="s3cret") == "pro"


def test_a_legacy_license_still_downgrades_on_a_normal_install():
    """Pins the behaviour that makes the refusal necessary.

    If this ever stops being true the guard can be revisited -- but while it
    holds, minting without opt-in sells a paid tier and delivers free.
    """
    key = issue_license(org="Acme", tier="pro", signing_key="s3cret", allow_hmac=True)
    assert _tier_of(key) == "free"


def test_an_ed25519_key_in_the_environment_is_enough(monkeypatch):
    priv, pub = generate_keypair()
    monkeypatch.setenv("OUBLIETTE_LICENSE_PRIVATE_KEY", priv)
    key = issue_license(org="Acme", tier="enterprise")
    assert _tier_of(key, public_key=pub) == "enterprise"


def test_the_sale_path_refuses_rather_than_issuing_an_unverifiable_key():
    """The webhook is where a downgrade would actually reach a customer."""
    from oubliette_trap.license_webhook import license_for_sale

    shared = "wh-shared"
    # Sender verification runs before minting, so the ping must authenticate --
    # otherwise this would pass on a PermissionError and prove nothing.
    payload = {
        "permalink": "trap-pro",
        "email": "a@b.c",
        "full_name": "Acme",
        "token": shared,
    }
    with pytest.raises(ValueError, match="Ed25519"):
        license_for_sale(
            payload,
            {"trap-pro": {"tier": "pro"}},
            "s3cret",
            webhook_secret=shared,
        )
