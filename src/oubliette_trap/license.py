"""
Oubliette Trap - License & Metering Layer
=============================================
Soft enforcement of feature gating and usage metering.

Tiers:
- **free**: analyze(), scan_input(), basic session tracking, pre-filter + ML.
- **pro**: Unlocks scan_output, drift_monitor, webhooks, stix_export,
  agent_policy, mcp_guard, tenant_manager, rbac.
- **enterprise**: Everything, no warnings.

Licenses are product-scoped schema v2 tokens signed with Ed25519 (see
:mod:`oubliette_trap._license_core`, vendored byte-identical from
``oubliette-commerce``, which is the only issuer). Trap accepts a key only
if its signed ``products`` list contains ``"trap"``; a Shield- or Dungeon-only
key gives the free tier here. Every validation failure gives the free tier.
Client-side HMAC verification has been removed.
"""

from __future__ import annotations

import os
from collections.abc import Iterable, Mapping
from typing import Any

from . import _license_core
from ._license_core import (
    DEFAULT_MONTHLY_QUOTA,
    FREE_LICENSE,
    KNOWN_PRODUCTS,
    PRODUCTION_KEYRING,
    SCHEMA_VERSION,
    LicenseError,
    LicenseInfo,
    canonical_payload,
    verify_license_token,
)

#: This product's registry name in the signed ``products`` claim.
PRODUCT = "trap"

# Features that require Pro tier (Trap deception platform)
PRO_FEATURES = frozenset(
    {
        "active_probes",  # active fingerprinting probes (canary, instruction trap)
        "custom_profiles",  # author/import custom deception profiles
        "network_transport",  # SSE/network-accessible honeypot (vs local stdio)
        "stix_export",  # STIX 2.1 intel export
        "cef_export",  # CEF/SIEM intel export
        "intel_dashboard",  # captured-agent intel dashboard + aggregation
        "webhooks",  # capture-event webhook alerts
        "rbac",  # role-based access control
        "tenant_manager",  # multi-tenant isolation
    }
)

__all__ = [
    "DEFAULT_MONTHLY_QUOTA",
    "FREE_LICENSE",
    "KNOWN_PRODUCTS",
    "PRODUCT",
    "PRODUCTION_KEYRING",
    "PRO_FEATURES",
    "SCHEMA_VERSION",
    "FeatureGate",
    "LicenseError",
    "LicenseInfo",
    "LicenseManager",
    "canonical_payload",
    "verify_license_token",
]


class LicenseManager(_license_core.LicenseManager):
    """Trap's license manager: validation, feature gating, usage metering.

    Verifies ``OUBLIETTE_LICENSE_KEY`` for product ``"trap"`` against the
    embedded public keyring. Thread-safe.

    Args:
        storage_backend: Optional storage backend for persisting usage data.
        keyring: ``kid -> public key`` override for tests and rotation drills.
            Defaults to the embedded production keyring. There is no
            environment-variable override.
    """

    def __init__(
        self,
        *,
        storage_backend: Any = None,
        keyring: Mapping[str, str] | None = None,
    ) -> None:
        super().__init__(
            product=PRODUCT,
            pro_features=PRO_FEATURES,
            storage_backend=storage_backend,
            keyring=keyring,
        )


class FeatureGate(_license_core.FeatureGate):
    """Controls access to Pro features based on license key.

    Provides a simple boolean check for whether a feature is available
    under the current license tier.  Integrates with :class:`Shield` via
    the ``feature_gate`` constructor parameter.

    Tiers:
        - **community**: ``analyze``, ``health``, ``basic_session``
        - **pro**: Everything in community plus ``multi_tenant``,
          ``siem_export``, ``webhooks``, ``openc2``, ``rbac``,
          ``advanced_session``, ``threat_intel``

    Usage::

        gate = FeatureGate(license_manager=LicenseManager())
        gate.validate()
        if gate.is_allowed("openc2"):
            # enable OpenC2 adapter
            ...

    Args:
        license_key: A license key string.  Defaults to the
            ``OUBLIETTE_LICENSE_KEY`` environment variable.
        license_manager: Optional :class:`LicenseManager` to
            delegate validation to.  When provided, the gate uses
            the manager's (Trap-scoped) tier after validation.  This is
            the only path that verifies the license signature.
        insecure_simple_mode: DEV/TEST ONLY.  Without a manager the key
            cannot be verified, so the gate stays at ``community``.  Set
            this (or ``OUBLIETTE_INSECURE_DEV_FEATURE_GATE=true``) to
            restore the old behaviour of treating any non-empty key as
            Pro.  Default off.
    """

    COMMUNITY_FEATURES: frozenset[str] = frozenset(
        {
            "analyze",
            "health",
            "basic_session",
        }
    )

    PRO_FEATURES: frozenset[str] = frozenset(
        {
            "multi_tenant",
            "siem_export",
            "webhooks",
            "openc2",
            "rbac",
            "advanced_session",
            "threat_intel",
        }
    )

    ALL_FEATURES: frozenset[str] = COMMUNITY_FEATURES | PRO_FEATURES

    def __init__(
        self,
        license_key: str | None = None,
        license_manager: _license_core.LicenseManager | None = None,
        *,
        insecure_simple_mode: bool | None = None,
        community_features: Iterable[str] | None = None,
        pro_features: Iterable[str] | None = None,
    ) -> None:
        if insecure_simple_mode is None:
            insecure_simple_mode = os.getenv(
                "OUBLIETTE_INSECURE_DEV_FEATURE_GATE", ""
            ).strip().lower() in ("1", "true", "yes")
        super().__init__(
            license_key,
            license_manager,
            community_features=community_features,
            pro_features=pro_features,
            insecure_simple_mode=insecure_simple_mode,
        )
