"""``oubliette_trap.__version__`` must match ``[project].version`` in pyproject.toml.

Published wheels advertise the pyproject version; code that reports its own
version reads ``oubliette_trap.__version__``. PyPI 0.3.1 shipped with a runtime
``__version__`` of 0.3.0 (and 0.2.0 with 0.1.0), which this test now prevents.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from oubliette_trap import __version__

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python < 3.11
    tomllib = None  # type: ignore[assignment]

PYPROJECT = Path(__file__).resolve().parents[1] / "pyproject.toml"


@pytest.mark.skipif(tomllib is None, reason="tomllib requires Python 3.11+")
def test_runtime_version_matches_pyproject() -> None:
    with PYPROJECT.open("rb") as fh:
        declared = tomllib.load(fh)["project"]["version"]
    assert isinstance(declared, str) and declared, declared
    assert __version__ == declared, (
        f"version drift: oubliette_trap.__version__={__version__!r} "
        f"!= pyproject.toml project.version={declared!r}"
    )
