"""Ed25519 asymmetric license signing/verification (ported from commerce)."""

from __future__ import annotations

import base64
import json

import pytest

from oubliette_trap.license import LicenseManager, generate_keypair
from oubliette_trap.license_issuer import issue_license


def test_generate_keypair_returns_distinct_b64_keys():
    priv, pub = generate_keypair()
    assert priv and pub and priv != pub
    assert len(base64.b64decode(priv)) == 32
    assert len(base64.b64decode(pub)) == 32
    # Two calls produce different keys.
    assert generate_keypair()[0] != priv


def test_ed25519_issued_license_validates_with_public_key():
    priv, pub = generate_keypair()
    key = issue_license(org="Acme", tier="enterprise", private_key=priv)
    # sig_alg is stamped ed25519
    assert json.loads(base64.b64decode(key))["sig_alg"] == "ed25519"
    mgr = LicenseManager(public_key=pub)
    mgr._load_license(key)
    assert mgr.license.tier == "enterprise"
    assert mgr.license.org == "Acme"


def test_ed25519_tampered_payload_fails_closed():
    priv, pub = generate_keypair()
    key = issue_license(org="Acme", tier="pro", private_key=priv)
    blob = json.loads(base64.b64decode(key))
    blob["tier"] = "enterprise"  # tamper after signing
    forged = base64.b64encode(json.dumps(blob).encode()).decode()
    mgr = LicenseManager(public_key=pub)
    mgr._load_license(forged)
    assert mgr.license.tier == "free"


def test_ed25519_wrong_public_key_fails_closed():
    priv, _pub = generate_keypair()
    _priv2, pub2 = generate_keypair()
    key = issue_license(org="Acme", tier="enterprise", private_key=priv)
    mgr = LicenseManager(public_key=pub2)  # mismatched key
    mgr._load_license(key)
    assert mgr.license.tier == "free"


def test_ed25519_without_public_key_fails_closed():
    priv, _pub = generate_keypair()
    key = issue_license(org="Acme", tier="enterprise", private_key=priv)
    mgr = LicenseManager()  # no public key configured
    mgr._load_license(key)
    assert mgr.license.tier == "free"


def test_forged_unsigned_enterprise_blob_still_rejected():
    """The original bug: an unsigned blob must never grant a paid tier."""
    forged = base64.b64encode(
        json.dumps({"tier": "enterprise", "org": "attacker"}).encode()
    ).decode()
    _priv, pub = generate_keypair()
    mgr = LicenseManager(public_key=pub)
    mgr._load_license(forged)
    assert mgr.license.tier == "free"


def test_legacy_hmac_still_supported():
    key = issue_license(org="Acme", tier="pro", signing_key="s3cret")
    assert json.loads(base64.b64decode(key))["sig_alg"] == "hmac"
    mgr = LicenseManager(signing_key="s3cret")
    mgr._load_license(key)
    assert mgr.license.tier == "pro"


def test_issue_requires_some_key():
    with pytest.raises(ValueError):
        issue_license(org="Acme", tier="pro")
