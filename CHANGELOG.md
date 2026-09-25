# Changelog

All notable changes to `oubliette-trap` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

Entries are reconstructed from the git history. Release dates are the PyPI
upload dates (UTC). There was no 0.1.0 release on PyPI; 0.2.0 was the first.

## [Unreleased]

### Added
- `.github/workflows/publish.yml`: publishes `vX.Y.Z` tags to PyPI via Trusted
  Publishing (OIDC), after checking the tag matches the pyproject version and
  running a packaging-boundary gate on the built sdist and wheel.
- `tests/test_packaging_boundary.py` and `tests/test_version_sync.py`.

### Changed
- The sdist no longer includes `tests/` (`MANIFEST.in`).
- GitHub Actions updated to their Node 24 majors.

### Fixed
- `oubliette_trap.__version__` now matches the package version (0.3.1). The
  published 0.3.1 reports `0.3.0`, and 0.2.0 reports `0.1.0`.

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

[Unreleased]: https://github.com/oubliettesecurity/oubliette-trap/compare/651e3dd...HEAD
[0.3.1]: https://pypi.org/project/oubliette-trap/0.3.1/
[0.3.0]: https://pypi.org/project/oubliette-trap/0.3.0/
[0.2.0]: https://pypi.org/project/oubliette-trap/0.2.0/
