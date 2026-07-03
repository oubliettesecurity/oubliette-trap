"""
Oubliette Trap - Gumroad/Paddle sale -> license-key webhook.

On a sale, the merchant-of-record (Gumroad/Paddle) POSTs a "ping" to our
endpoint. We map the purchased product to a tier, mint a signed Oubliette
license key (``license_issuer.issue_license``), and return it for delivery
(email / receipt). Subscriptions re-ping on renewal, refreshing the key's
expiry.

SECURITY (SEC-review 2026-07-02): the webhook endpoint MUST authenticate the
sender before minting a paid license. Previously verification hinged on an
optional public ``seller_id`` field that defaulted to ``None`` and was skipped,
so anyone who knew a product permalink could POST it and receive a valid,
signed Pro/Enterprise key without ever paying. Verification is now MANDATORY:

  * Gumroad pings carry no cryptographic signature, so we require a mandatory
    shared-secret token (configured in the Gumroad ping URL / a custom field,
    or an ``X-Oubliette-Webhook-Token`` header) compared in constant time.
  * Paddle Billing signs the raw request body -- we verify the
    ``Paddle-Signature`` HMAC-SHA256 against the configured secret.

Unverified requests are rejected (``PermissionError``). A missing/empty shared
secret is a misconfiguration and fails closed (``ValueError``).

The signing key (``OUBLIETTE_LICENSE_SIGNING_KEY``) and product map live
server-side. Deploy ``create_license_webhook_blueprint`` behind the existing
Flask app or a tiny standalone service.
"""

import hashlib
import hmac
from collections.abc import Mapping
from typing import Any

from .license_issuer import issue_license

_TRUTHY = {"true", "1", "yes", True}


def _is_true(v: Any) -> bool:
    return v in _TRUTHY or (isinstance(v, str) and v.strip().lower() == "true")


def _header(headers: Mapping[str, str] | None, name: str) -> str | None:
    """Case-insensitive header lookup that tolerates plain dicts and Starlette
    ``Headers`` alike."""
    if not headers:
        return None
    # Starlette Headers / Werkzeug EnvironHeaders are already case-insensitive.
    try:
        val = headers.get(name)
        if val is not None:
            return val
    except Exception:
        pass
    lowered = name.lower()
    for k, v in dict(headers).items():
        if str(k).lower() == lowered:
            return v
    return None


def verify_gumroad_token(
    payload: Mapping[str, Any],
    headers: Mapping[str, str] | None,
    secret: str,
) -> bool:
    """Constant-time compare a Gumroad shared-secret token.

    Gumroad pings are unsigned, so we require a caller-provided token that only
    the merchant configuration and this server know. Accepts the token from an
    ``X-Oubliette-Webhook-Token`` header or a ``webhook_token`` / ``token``
    payload field.
    """
    if not secret:
        return False
    provided = (
        _header(headers, "X-Oubliette-Webhook-Token")
        or payload.get("webhook_token")
        or payload.get("token")
    )
    if not provided:
        return False
    return hmac.compare_digest(str(provided), str(secret))


def verify_paddle_signature(
    raw_body: bytes | None,
    headers: Mapping[str, str] | None,
    secret: str,
) -> bool:
    """Verify a Paddle Billing ``Paddle-Signature`` header.

    Header form: ``ts=<unix_ts>;h1=<hex_hmac_sha256>`` where the signed payload
    is ``f"{ts}:" + raw_body``.
    """
    if not secret or raw_body is None:
        return False
    sig_header = _header(headers, "Paddle-Signature")
    if not sig_header:
        return False
    parts = {}
    for chunk in sig_header.split(";"):
        if "=" in chunk:
            k, _, v = chunk.partition("=")
            parts[k.strip()] = v.strip()
    ts = parts.get("ts")
    h1 = parts.get("h1")
    if not ts or not h1:
        return False
    signed = f"{ts}:".encode() + raw_body
    expected = hmac.new(secret.encode("utf-8"), signed, hashlib.sha256).hexdigest()
    return hmac.compare_digest(h1, expected)


def license_for_sale(
    payload: Mapping[str, Any],
    product_map: Mapping[str, Mapping[str, Any]],
    signing_key: str,
    *,
    webhook_secret: str,
    provider: str = "gumroad",
    headers: Mapping[str, str] | None = None,
    raw_body: bytes | None = None,
    seller_id: str | None = None,
) -> dict[str, Any] | None:
    """Turn a verified Gumroad/Paddle sale payload into an issued license, or None.

    Verification is MANDATORY and happens before any license is minted:
        * ``provider="gumroad"`` -> shared-secret token (see verify_gumroad_token)
        * ``provider="paddle"``  -> HMAC signature (see verify_paddle_signature)

    Args:
        webhook_secret: The shared secret / Paddle signing secret. Required; an
            empty value fails closed (misconfiguration).
        headers/raw_body: Request metadata used for verification.
        seller_id: Optional *additional* check on the payload's seller_id. It is
            NOT a substitute for webhook verification.

    Returns None for ignorable events (unknown product, refund/dispute/cancel).

    Raises:
        ValueError: ``webhook_secret`` is empty (server misconfigured).
        PermissionError: the request could not be authenticated, or the optional
            ``seller_id`` does not match.
    """
    if not webhook_secret:
        raise ValueError(
            "webhook_secret is required -- refusing to issue licenses on an unauthenticated webhook"
        )

    if provider == "paddle":
        verified = verify_paddle_signature(raw_body, headers, webhook_secret)
    else:
        verified = verify_gumroad_token(payload, headers, webhook_secret)
    if not verified:
        raise PermissionError("webhook verification failed")

    if seller_id and payload.get("seller_id") != seller_id:
        raise PermissionError("seller_id mismatch")

    # Ignore reversals / cancellations.
    if any(_is_true(payload.get(k)) for k in ("refunded", "disputed", "cancelled", "chargedback")):
        return None

    permalink = (
        payload.get("product_permalink")
        or payload.get("permalink")
        or payload.get("short_product_id")
        or payload.get("product_id")
        or ""
    )
    cfg = product_map.get(permalink)
    if not cfg:
        return None

    email = str(payload.get("email", ""))
    org = str(payload.get("full_name") or payload.get("organization") or email)

    key = issue_license(
        org=org,
        tier=cfg["tier"],
        features=cfg.get("features"),
        quota=int(cfg.get("quota", 0)),
        expires=str(cfg.get("expires", "")),
        signing_key=signing_key,
    )
    return {"email": email, "org": org, "tier": cfg["tier"], "license_key": key}


def create_license_webhook_blueprint(
    product_map: Mapping[str, Mapping[str, Any]],
    signing_key: str,
    webhook_secret: str,
    provider: str = "gumroad",
    seller_id: str | None = None,
    deliver: Any = None,
) -> Any:  # pragma: no cover - thin Flask glue; logic is tested via license_for_sale
    """Flask blueprint exposing POST /webhooks/gumroad.

    ``webhook_secret`` is mandatory -- it authenticates the merchant ping. For
    Gumroad it is the shared token; for Paddle it is the signing secret.

    ``deliver(result)`` is an optional callback to email/store the key; if omitted
    the key is only logged (wire an email sender in production).
    """
    from flask import Blueprint, jsonify, request

    if not webhook_secret:
        raise ValueError("webhook_secret is required to mount the license webhook")

    bp = Blueprint("license_webhook", __name__)

    @bp.route("/webhooks/gumroad", methods=["POST"])
    def gumroad() -> Any:
        payload = request.form.to_dict() or (request.get_json(silent=True) or {})
        try:
            result = license_for_sale(
                payload,
                product_map,
                signing_key,
                webhook_secret=webhook_secret,
                provider=provider,
                headers=request.headers,
                raw_body=request.get_data(),
                seller_id=seller_id,
            )
        except PermissionError:
            return jsonify({"error": "unauthorized"}), 403
        if result is None:
            return jsonify({"status": "ignored"}), 200
        if deliver is not None:
            deliver(result)
        return jsonify({"status": "issued", "email": result["email"], "tier": result["tier"]}), 200

    return bp
