"""Trap's license SDK: Trap-specific Pro features and a signed round trip.

Issuing (and the Gumroad/Paddle sale webhook) lives only in
oubliette-commerce; these tests sign schema-v2 keys locally with a throwaway
Ed25519 key.
"""

from __future__ import annotations

import base64
import datetime
import json

import pytest

pytest.importorskip("cryptography")

from oubliette_trap._license_core import canonical_payload, generate_keypair
from oubliette_trap.license import PRO_FEATURES, LicenseManager

FAR_FUTURE = (datetime.date.today() + datetime.timedelta(days=365)).isoformat()


def _issue(priv: str, **overrides: object) -> str:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    claims: dict[str, object] = {
        "v": 2, "kid": "test", "lid": "l1", "products": ["trap"], "tier": "pro",
        "org": "Acme Corp", "issued": "2026-01-01", "expires": FAR_FUTURE, "quota": 0,
        "features": ["active_probes"], "sig_alg": "ed25519",
    }  # fmt: skip
    claims.update(overrides)
    signer = Ed25519PrivateKey.from_private_bytes(base64.b64decode(priv))
    claims["sig"] = base64.b64encode(signer.sign(canonical_payload(claims))).decode()
    return base64.b64encode(json.dumps(claims).encode()).decode()


def test_issued_pro_key_validates():
    priv, pub = generate_keypair()
    mgr = LicenseManager(keyring={"test": pub})
    mgr._load_license(_issue(priv))
    assert mgr.license.tier == "pro"
    assert mgr.license.org == "Acme Corp"
    assert mgr.check_feature("active_probes") is True
    assert mgr.check_feature("intel_dashboard") is False


def test_pro_features_are_trap_specific():
    assert "active_probes" in PRO_FEATURES
    assert "intel_dashboard" in PRO_FEATURES
    assert "scan_output" not in PRO_FEATURES  # Shield's, not Trap's


def test_wrong_key_falls_back_to_free():
    priv, _ = generate_keypair()
    _, other_pub = generate_keypair()
    mgr = LicenseManager(keyring={"test": other_pub})
    mgr._load_license(_issue(priv))
    assert mgr.license.tier == "free"


def test_shield_key_falls_back_to_free():
    priv, pub = generate_keypair()
    mgr = LicenseManager(keyring={"test": pub})
    mgr._load_license(_issue(priv, products=["shield"], tier="enterprise"))
    assert mgr.license.tier == "free"
