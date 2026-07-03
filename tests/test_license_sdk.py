"""Verify the ported revenue SDK works in Trap (issuer -> validator round-trip)."""

from oubliette_trap.license import LicenseManager, PRO_FEATURES
from oubliette_trap.license_issuer import issue_license
from oubliette_trap.license_webhook import license_for_sale


def test_issued_pro_key_validates():
    key = issue_license(org="Acme Corp", tier="pro", signing_key="trap-secret")
    mgr = LicenseManager(signing_key="trap-secret")
    mgr._load_license(key)
    assert mgr.license.tier == "pro"
    assert mgr.license.org == "Acme Corp"


def test_pro_features_are_trap_specific():
    assert "active_probes" in PRO_FEATURES
    assert "intel_dashboard" in PRO_FEATURES
    assert "scan_output" not in PRO_FEATURES  # Shield's, not Trap's


def test_wrong_key_falls_back_to_free():
    key = issue_license(org="Acme", tier="pro", signing_key="right")
    mgr = LicenseManager(signing_key="wrong")
    mgr._load_license(key)
    assert mgr.license.tier == "free"


def test_webhook_issues_validating_key():
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
    mgr = LicenseManager(signing_key="trap-secret")
    mgr._load_license(res["license_key"])
    assert mgr.license.tier == "pro"
