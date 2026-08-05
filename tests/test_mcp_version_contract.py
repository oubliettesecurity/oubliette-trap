"""The declared `mcp` constraint must match the API this code actually uses.

mcp 2.0.0 removed ``mcp.server.fastmcp``, which ``server.create_mcp_server``
imports. That function builds the honeypot's MCP server -- its primary entry
point -- so an uncapped ``mcp>=1.20.0`` advertises support that does not exist:
a fresh install resolves 2.x and the server cannot start.

This pins the cap so removing it requires deliberately porting the server
first, rather than shipping a release whose main feature raises
ModuleNotFoundError.

Mirrors the same contract in oubliette-shield.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PYPROJECT = REPO_ROOT / "pyproject.toml"


def _mcp_requirements() -> list[str]:
    """Every declared `mcp` requirement, across all dependency groups."""
    with PYPROJECT.open("rb") as fh:
        cfg = tomllib.load(fh)
    project = cfg["project"]
    groups: list[str] = list(project.get("dependencies", []))
    for extra in project.get("optional-dependencies", {}).values():
        groups.extend(extra)
    return [
        req
        for req in groups
        # The `mcp` distribution itself, not names merely containing it.
        if req.split(">")[0].split("<")[0].split("=")[0].split("[")[0].strip() == "mcp"
    ]


def test_mcp_is_declared_at_all():
    assert _mcp_requirements(), "mcp is a hard dependency of the honeypot server"


def test_every_mcp_requirement_excludes_2_x():
    """2.x removes the module server.py imports, so it must not resolve."""
    for req in _mcp_requirements():
        assert "<2" in req.replace(" ", ""), (
            f"{req!r} permits mcp 2.x, where mcp.server.fastmcp does not exist "
            f"and create_mcp_server raises ModuleNotFoundError"
        )


def test_the_import_the_cap_protects_still_exists():
    """Guards against capping for a reason that has silently stopped applying.

    If this fails on an mcp the cap allows, the constraint is wrong rather than
    the code.
    """
    from mcp.server.fastmcp import FastMCP

    assert FastMCP is not None


def test_the_server_entry_point_can_actually_be_built():
    """The end a customer cares about: the honeypot server constructs.

    Covers more than the version cap. `create_mcp_server` also broke on Python
    3.14 with a permitted mcp, because the tool handler's deferred annotations
    referenced a `Context` imported inside a function and so absent from the
    module globals fastmcp evaluates against. A cap alone would not have caught
    that -- only building the thing does.
    """
    from oubliette_trap.server import OublietteTrap, create_mcp_server

    assert create_mcp_server(OublietteTrap()) is not None
