# Changelog

All notable changes to `oubliette-trap` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

Entries are reconstructed from the git history. Release dates are the PyPI
upload dates (UTC). There was no 0.1.0 release on PyPI; 0.2.0 was the first.

## [Unreleased]

## [0.4.0] - 2026-09-27

0.3.2 was never released; its changes ship in this release. Licensing moves to
product-scoped Ed25519 keys (schema v2), which is a breaking change: see
*Changed* and *Removed*.

### Security
- **License expiry fails closed.** A signed license whose `expires` value
  cannot be parsed as an ISO date (or is not a string) now falls back to the
  free tier. Previously the parse error was swallowed and the license was
  treated as never expiring (#10).
- **`FeatureGate` without a `LicenseManager` fails closed.** It cannot verify a
  key, so any non-empty `OUBLIETTE_LICENSE_KEY` no longer grants Pro; the gate
  stays at `community`. The old behaviour is available for local development
  and tests only via `FeatureGate(..., insecure_simple_mode=True)` or
  `OUBLIETTE_INSECURE_DEV_FEATURE_GATE=true` (default off) (#10).

### Added
- `.github/workflows/publish.yml`: publishes `vX.Y.Z` tags to PyPI via Trusted
  Publishing (OIDC), after checking the tag matches the pyproject version and
  running a packaging-boundary gate on the built sdist and wheel (#9).
- `tests/test_packaging_boundary.py` and `tests/test_version_sync.py` (#9).

### Changed
- **Breaking: product-scoped license keys (schema v2).** A key carries a
  signed `products` list, and Trap accepts it only if `"trap"` is in that
  list. A Shield- or Dungeon-only key gives the free tier here. Keys also
  carry signed `v`, `lid` (license id) and `kid` (signing-key id).
  Verification runs in `oubliette_trap/_license_core.py`, vendored
  byte-identical from `oubliette-commerce`, which is now the only issuer
  (#12).
- **Breaking: HMAC licenses removed.** `LicenseManager(signing_key=...)` and
  `LicenseManager(public_key=...)` are gone. So are the
  `OUBLIETTE_LICENSE_SIGNING_KEY` and `OUBLIETTE_LICENSE_PUBLIC_KEY`
  variables. Keys verify only against the Ed25519 public keys embedded by
  `kid`. The signature is now `LicenseManager(*, storage_backend=None,
  keyring=None)` (#12).
- **Breaking: no perpetual keys.** `expires` is required, so an empty or
  missing `expires` gives the free tier. Pre-v2 keys also give the free tier.
  No licenses had been issued, so this is a clean cutover. The `FeatureGate`
  dev opt-in is unchanged (#12).
- The sdist no longer includes `tests/` (`MANIFEST.in`) (#9).
- GitHub Actions updated to their Node 24 majors (#9).

### Removed
- `oubliette_trap.license_issuer` and `oubliette_trap.license_webhook`.
  Issuing, the key-generation CLI and the Gumroad/Paddle sale webhook now
  live only in `oubliette-commerce` (#12).

### Fixed
- `oubliette_trap.__version__` now matches the package version. The published
  0.3.1 reports `0.3.0`, and 0.2.0 reports `0.1.0` (#9).
- CEF export: the header's Device Version field now carries the package
  version instead of a hardcoded `0.1.0` (#9).

## [0.3.1] - 2026-08-05

### Fixed
- The MCP server can be built on Python 3.14 (#8).
- `mcp` is capped below 2.0, which removed `mcp.server.fastmcp` (#7).
- Metering holds one lock across the quota check and the counter update (#6).
- Metering rejects invalid quantities before any counter update (#4).

### Changed
- Issuing a license requires an Ed25519 private key; the legacy HMAC scheme
  needs an explicit `allow_hmac=True` (#5).

### Security
- `cryptography` minimum raised to 48.0.1 (#3).

## [0.3.0] - 2026-07-04

### Added
- Ed25519 license signing and verification, with a `licensing` extra and an
  embedded production public key (#2).

### Security
- Fixes from the 2026-07-02 review (#1): webhook verification before license
  issue, license verification fails closed without a signing key, real client
  source IP on the MCP tool path, and bounded session state and history.

## [0.2.0] - 2026-06-06

First release on PyPI.

### Added
- Deception profiles and sessions, passive fingerprinting, active probes,
  a rule-based agent classifier, SQLite event storage, STIX 2.1 / CEF / JSON
  export, the FastMCP honeypot server and the `oubliette-trap` CLI.
- Commercial layer: licensing, metering, auth, license issuer and webhook.

### Security
- Session identity and shared environment state, argument handling, probe
  rotation, resource bounds, SSE bind address, CEF escaping, STIX references
  and export path scope hardened before the first release.

[Unreleased]: https://github.com/oubliettesecurity/oubliette-trap/compare/v0.4.0...HEAD
[0.4.0]: https://pypi.org/project/oubliette-trap/0.4.0/
[0.3.1]: https://pypi.org/project/oubliette-trap/0.3.1/
[0.3.0]: https://pypi.org/project/oubliette-trap/0.3.0/
[0.2.0]: https://pypi.org/project/oubliette-trap/0.2.0/
