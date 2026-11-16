"""Runner behaviour against a stub client: call order, stats arithmetic, teardown."""

import base64

import pytest

from mhddos_trex import catalog
from mhddos_trex.runner import Runner
from mhddos_trex.spec import BuildCtx, LinkSpec, RunSpec
from mhddos_trex.streams import build_streams


class StubClient:
    def __init__(self, stats=None):
        self.calls: list[str] = []
        self.stats = stats or {}
        self.connected = False
        self.released = False

    def _record(self, name, **kwargs):
        self.calls.append(name)

    def connect(self):
        self.connected = True
        self.calls.append("connect")

    def acquire(self, ports, force=None):
        self.calls.append("acquire")

    def reset(self, ports):
        self._record("reset", ports=ports)

    def remove_all_streams(self, ports):
        self._record("remove_all_streams", ports=ports)

    def add_streams(self, streams, ports):
        assert streams, "a profile always has at least one stream"
        self.calls.append("add_streams")

    def clear_stats(self, ports):
        self._record("clear_stats", ports=ports)

    def start(self, ports, duration, force=None):
        self._record("start", ports=ports)

    def wait_on_traffic(self, ports, timeout=None):
        self.calls.append("wait_on_traffic")

    def get_stats(self, ports):
        return {0: self.stats}

    def stop(self, ports):
        self._record("stop", ports=ports)

    def release(self, ports):
        self.released = True
        self.calls.append("release")

    def disconnect(self):
        self.calls.append("disconnect")


@pytest.fixture
def runner(monkeypatch):
    client = StubClient({"opackets": 100_000, "oerrors": 3})
    r = Runner()
    r._client = client
    return r, client


def _setup(source, flows=2, size=1518, pps=100_000):
    ctx = BuildCtx(host="198.19.0.2", port=80, user_agents=source.user_agents, referers=source.referers)
    run = RunSpec(victim="198.19.0.2", dport=80, pps=pps, flows=flows, src_prefix="203.0.113.0/24", size=size)
    link = LinkSpec(src_mac="00:00:00:00:00:01", dst_mac="00:00:00:00:00:02", vlan=None)
    return run, build_streams("GET", run, link, ctx, source)


def test_run_clears_between_profiles_and_reports_counts(runner, source):
    r, client = runner
    run, streams = _setup(source)
    result = r.run("GET", streams, run, seconds=10)

    assert client.calls.index("reset") < client.calls.index("add_streams")
    assert client.calls.index("add_streams") < client.calls.index("start")
    assert result.sent == 100_000
    assert result.pps == 10_000
    assert result.oerrors == 3
    assert result.frame_bytes == 1518


def test_l1_rate_includes_preamble_and_ifg(runner, source):
    r, _ = runner
    run, streams = _setup(source, size=64, pps=10)
    result = r.run("GET", streams, run, seconds=10)
    expected = 100_000 * (64 + 20) * 8 / 10 / 1e9
    assert result.l1_gbps == pytest.approx(round(expected, 3))


def test_frame_size_falls_back_to_the_compiled_packet(runner, source):
    r, _ = runner
    run, streams = _setup(source, size=None, pps=10)
    result = r.run("GET", streams, run, seconds=10)
    assert result.frame_bytes == len(base64.b64decode(streams[0].to_json()["packet"]["binary"]))


def test_near_zero_pps_does_not_divide_by_nothing(runner, source):
    r, _ = runner
    run, streams = _setup(source, pps=1)
    result = r.run("GET", streams, run, seconds=60)
    assert result.pps == pytest.approx(round(100_000 / 60))


def test_teardown_releases_the_port_even_when_stop_fails(source):
    class Failing(StubClient):
        def stop(self, ports):
            raise RuntimeError("rpc down")

    client = Failing()
    runner = Runner()
    runner._client = client
    runner.__exit__(None, None, None)
    assert client.released
    assert client.calls == ["remove_all_streams", "release", "disconnect"]


def test_every_emittable_profile_runs_through_the_client(runner, source):
    r, client = runner
    ctx = BuildCtx(host="198.19.0.2", port=80, user_agents=source.user_agents, referers=source.referers)
    link = LinkSpec(src_mac="00:00:00:00:00:01", dst_mac="00:00:00:00:00:02", vlan=210)
    for name in catalog.emittable():
        run = RunSpec(victim="198.19.0.2", dport=80, pps=1000, flows=2, src_prefix="203.0.113.0/24")
        result = r.run(name, build_streams(name, run, link, ctx, source), run, seconds=1)
        assert result.profile == name
