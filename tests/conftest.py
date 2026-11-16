"""Shared fixtures: a loaded MHDDoS source and a run/link/ctx triple."""

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
TREX = ROOT.parent / "trex-core"
sys.path.insert(0, str(TREX / "scripts" / "automation" / "trex_control_plane" / "interactive"))
sys.path.insert(0, str(TREX / "scripts" / "external_libs" / "scapy-2.4.3"))
sys.path.insert(0, str(ROOT))

from mhddos_trex import mhddos  # noqa: E402


@pytest.fixture(scope="session")
def source():
    return mhddos.load(mhddos.locate(ROOT.parent / "MHDDoS"))
