"""Fixtures over the synthetic snapshots in host_snapshots.py."""

from __future__ import annotations

from typing import Any

import pytest
from host_snapshots import PKG_META, PKG_NEW, PKG_OLD, PKG_OTHER, make_snapshot


@pytest.fixture
def clean_snapshot() -> dict[str, Any]:
    return make_snapshot()


@pytest.fixture
def positive_snapshot() -> dict[str, Any]:
    return make_snapshot(packages=[PKG_OLD, PKG_NEW, PKG_META, PKG_OTHER], root_login="yes")


@pytest.fixture
def container_snapshot() -> dict[str, Any]:
    return make_snapshot(packages=[PKG_OLD, PKG_NEW], ownership="shared")


@pytest.fixture
def ssh_errored_snapshot() -> dict[str, Any]:
    return make_snapshot(ssh="error")
