"""Drive a running TRex server and check that the streams actually transmit.

Skips unless ``TREX_SERVER`` names a reachable STL server:

    TREX_SERVER=127.0.0.1 pytest tests/test_live.py -q

Unlike ``test_dataplane.py`` this goes through the real ZMQ control plane, so it covers
what the simulator cannot: acquire, stream load, transmit, per-port counters and release.
"""

import os

import pytest

from mhddos_trex import catalog, mhddos
from mhddos_trex.spec import BuildCtx, LinkSpec, RunSpec
from mhddos_trex.streams import build_streams

SERVER = os.environ.get("TREX_SERVER")
PORT = int(os.environ.get("TREX_PORT", "0"))

pytestmark = pytest.mark.skipif(not SERVER, reason="TREX_SERVER not set")


def _client():
    from trex.stl.api import STLClient

    client = STLClient(server=SERVER, verbose_level="error")
    client.connect()
    return client


@pytest.fixture
def client():
    client = _client()
    client.acquire(ports=[PORT], force=True)
    yield client
    for teardown in (
        lambda: client.stop(ports=[PORT]),
        lambda: client.remove_all_streams(ports=[PORT]),
        lambda: client.release(ports=[PORT]),
        client.disconnect,
    ):
        try:
            teardown()
        except Exception:  # noqa: BLE001 - teardown must not mask the real failure
            pass


def _run_spec(pps: int) -> RunSpec:
    return RunSpec("198.19.0.2", 80, pps, 4, "203.0.113.0/24", None, ())


def test_server_reports_stateless_mode():
    client = _client()
    try:
        assert client.get_server_version()["mode"] == "STL"
    finally:
        client.disconnect()


def test_a_profile_transmits_through_the_control_plane(client):
    source = mhddos.load(mhddos.locate())
    link = LinkSpec("00:00:00:00:00:01", "00:00:00:00:00:02")
    ctx = BuildCtx(host="198.19.0.2", port=80, user_agents=source.user_agents, referers=source.referers)
    streams = build_streams("GET", _run_spec(100_000), link, ctx, source)

    client.reset(ports=[PORT])
    client.remove_all_streams(ports=[PORT])
    client.add_streams(streams, ports=[PORT])
    client.clear_stats(ports=[PORT])
    client.start(ports=[PORT], duration=2, force=True)
    client.wait_on_traffic(ports=[PORT], timeout=20)
    stats = client.get_stats(ports=[PORT])[PORT]

    assert stats["opackets"] > 0, "server accepted the profile but transmitted nothing"
    assert stats["obytes"] > 0
    assert stats["oerrors"] == 0


def test_every_emittable_profile_loads(client):
    """A profile the server rejects would never be noticed by compiling it locally."""
    source = mhddos.load(mhddos.locate())
    link = LinkSpec("00:00:00:00:00:01", "00:00:00:00:00:02")
    ctx = BuildCtx(host="198.19.0.2", port=80, user_agents=source.user_agents, referers=source.referers)
    for name in catalog.emittable():
        streams = build_streams(name, _run_spec(1000), link, ctx, source)
        client.remove_all_streams(ports=[PORT])
        client.add_streams(streams, ports=[PORT])


@pytest.mark.parametrize("name", ["GET", "UDP", "SYN"])
@pytest.mark.parametrize("pps", [100_000, 1_000_000])
def test_the_requested_rate_is_actually_transmitted(client, name, pps):
    """What the whole package is for: the rate is set by TRex, not by a Python loop.

    ``--pps`` is split across ``--flows`` streams, so the port sees the sum back.
    """
    source = mhddos.load(mhddos.locate())
    link = LinkSpec("00:00:00:00:00:01", "00:00:00:00:00:02")
    ctx = BuildCtx(host="198.19.0.2", port=80, user_agents=source.user_agents, referers=source.referers)
    run = RunSpec("198.19.0.2", 80, pps, 8, "203.0.113.0/24", None, ())
    streams = build_streams(name, run, link, ctx, source)

    client.reset(ports=[PORT])
    client.remove_all_streams(ports=[PORT])
    client.add_streams(streams, ports=[PORT])
    client.clear_stats(ports=[PORT])
    client.start(ports=[PORT], duration=3, force=True)
    client.wait_on_traffic(ports=[PORT], timeout=20)
    stats = client.get_stats(ports=[PORT])[PORT]
    client.stop(ports=[PORT])

    achieved = stats["opackets"] / 3
    print(
        f"\n{name:5} asked={pps:>9,} pps  sent={stats['opackets']:>10,}  "
        f"achieved={achieved:>11,.0f} pps  l1={stats['obytes'] * 8 / 3 / 1e9:.2f} Gbps  "
        f"oerrors={stats['oerrors']}"
    )
    assert stats["opackets"] > 0
    assert stats["oerrors"] == 0
    assert achieved > pps * 0.9, f"{name} sent {achieved:,.0f} pps of the {pps:,} asked for"

