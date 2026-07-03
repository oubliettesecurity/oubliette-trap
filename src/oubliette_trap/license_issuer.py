"""
Oubliette Trap - License Issuer (server-side)

Mints signed license keys that ``license.LicenseManager`` accepts. This is the
counterpart to the client-side validator in ``license.py``: it signs the same
JSON payload with the shared HMAC signing key and base64-encodes it.

Keep the signing key (``OUBLIETTE_LICENSE_SIGNING_KEY``) SERVER-SIDE ONLY — it
is the secret that authorizes Pro/Enterprise tiers. The same module powers the
Gumroad/Paddle webhook handler (``license_webhook.py``).

Usage:
    from oubliette_trap.license_issuer import issue_license
    key = issue_license(org="Acme", tier="pro", features=[...], signing_key=SECRET)
"""

import base64
import datetime
import hashlib
import hmac
import json
import os
from collections.abc import Sequence

from .license import PRO_FEATURES, _canonical_payload, generate_keypair


def issue_license(
    org: str,
    tier: str = "pro",
    *,
    expires: str = "",
    features: Sequence[str] | None = None,
    quota: int = 0,
    issued: str | None = None,
    signing_key: str | None = None,
    private_key: str | None = None,
) -> str:
    """Mint a base64 license key validated by ``LicenseManager``.

    Args:
        org: Customer / organization name (appears in the license).
        tier: "free", "pro", or "enterprise".
        expires: ISO date "YYYY-MM-DD" or "" for perpetual.
        features: Pro feature names to grant. Defaults to all PRO_FEATURES for
            the "pro" tier; ignored for "enterprise" (which unlocks everything).
        quota: Monthly quota override (0 = tier default).
        issued: ISO issue date; defaults to today.
        signing_key: HMAC signing secret; falls back to
            ``OUBLIETTE_LICENSE_SIGNING_KEY``. Legacy symmetric scheme.
        private_key: Ed25519 private key (base64); falls back to
            ``OUBLIETTE_LICENSE_PRIVATE_KEY``. Preferred asymmetric scheme.
            Either a private_key or a signing_key is required.

    Returns:
        A base64-encoded, signed license key string.
    """
    if not private_key:
        private_key = os.getenv("OUBLIETTE_LICENSE_PRIVATE_KEY", "")
    if not signing_key:
        signing_key = os.getenv("OUBLIETTE_LICENSE_SIGNING_KEY", "")
    if not private_key and not signing_key:
        raise ValueError(
            "an Ed25519 private_key (preferred) or an HMAC signing_key is "
            "required to issue a license"
        )

    if features is None:
        features = sorted(PRO_FEATURES) if tier == "pro" else []

    data = {
        "tier": tier,
        "org": org,
        "issued": issued or datetime.date.today().isoformat(),
        "expires": expires,
        "quota": quota,
        "features": list(features),
    }

    # Sign the EXACT serialization the validator reconstructs (sorted + compact,
    # excluding the signature envelope fields).
    payload = _canonical_payload(data)

    full = dict(data)
    if private_key:
        # Preferred: asymmetric Ed25519. The client verifies with the public key.
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        priv = Ed25519PrivateKey.from_private_bytes(base64.b64decode(private_key))
        sig = base64.b64encode(priv.sign(payload.encode("utf-8"))).decode("ascii")
        full["sig_alg"] = "ed25519"
    else:
        # Legacy: symmetric HMAC-SHA256.
        sig = hmac.new(
            signing_key.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256
        ).hexdigest()
        full["sig_alg"] = "hmac"

    full["sig"] = sig
    return base64.b64encode(json.dumps(full).encode("utf-8")).decode("ascii")


if __name__ == "__main__":  # pragma: no cover - CLI convenience
    import argparse
    import sys

    if len(sys.argv) > 1 and sys.argv[1] == "keygen":
        priv, pub = generate_keypair()
        print("# Ed25519 license keypair. Keep the PRIVATE key secret (server-side only).")
        print(f"OUBLIETTE_LICENSE_PRIVATE_KEY={priv}")
        print("# Public key: paste into license.py (_BUNDLED_PUBLIC_KEY) before")
        print("# publishing, or set OUBLIETTE_LICENSE_PUBLIC_KEY on clients.")
        print(f"OUBLIETTE_LICENSE_PUBLIC_KEY={pub}")
        sys.exit(0)

    ap = argparse.ArgumentParser(description="Mint an Oubliette Trap license key (or run 'keygen')")
    ap.add_argument("--org", required=True)
    ap.add_argument("--tier", default="pro", choices=["free", "pro", "enterprise"])
    ap.add_argument("--expires", default="", help="YYYY-MM-DD or empty for perpetual")
    ap.add_argument("--quota", type=int, default=0)
    ap.add_argument("--features", nargs="*", default=None)
    args = ap.parse_args()
    print(
        issue_license(
            org=args.org,
            tier=args.tier,
            expires=args.expires,
            quota=args.quota,
            features=args.features,
        )
    )
