"""Verify the ported revenue SDK works in Trap (issuer -> validator round-trip)."""

from oubliette_trap.license import LicenseManager, PRO_FEATURES
from oubliette_trap.license_issuer import generate_keypair, issue_license
from oubliette_trap.license_webhook import license_for_sale


def test_issued_pro_key_validates():
    # Legacy symmetric scheme, opted into explicitly: this client holds the
    # signing key, which is the only situation where such a licence verifies.
    key = issue_license(
        org="Acme Corp", tier="pro", signing_key="trap-secret", allow_hmac=True
    )
    mgr = LicenseManager(signing_key="trap-secret")
    mgr._load_license(key)
    assert mgr.license.tier == "pro"
    assert mgr.license.org == "Acme Corp"


def test_pro_features_are_trap_specific():
    assert "active_probes" in PRO_FEATURES
    assert "intel_dashboard" in PRO_FEATURES
    assert "scan_output" not in PRO_FEATURES  # Shield's, not Trap's


def test_wrong_key_falls_back_to_free():
    key = issue_license(org="Acme", tier="pro", signing_key="right", allow_hmac=True)
    mgr = LicenseManager(signing_key="wrong")
    mgr._load_license(key)
    assert mgr.license.tier == "free"


def test_webhook_issues_validating_key(monkeypatch):
    """The sale path must issue a licence a standard install can verify.

    Configured with Ed25519 rather than a symmetric key: the customer receiving
    this key has only the public half, so an HMAC-signed licence would load as
    free tier and the sale would silently deliver nothing.
    """
    priv, pub = generate_keypair()
    monkeypatch.setenv("OUBLIETTE_LICENSE_PRIVATE_KEY", priv)
    res = license_for_sale(
        {
            "product_permalink": "oubliette-trap-pro",
            "email": "a@b.com",
            "full_name": "Acme",
            "webhook_token": "hook-secret",
        },
        {"oubliette-trap-pro": {"tier": "pro"}},
        "trap-secret",
        webhook_secret="hook-secret",
    )
    assert res is not None and res["tier"] == "pro"
    mgr = LicenseManager(public_key=pub)  # what a customer actually has
    mgr._load_license(res["license_key"])
    assert mgr.license.tier == "pro"
