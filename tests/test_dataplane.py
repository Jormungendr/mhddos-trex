"""Execute the profiles in TRex's own C++ data plane and check the packets it emits.

Skips when the simulator has not been built:

    cd trex-core/linux && python3 ./waf-2.0.21 configure -o /tmp/trex-build
    cd trex-core/linux && python3 ./waf-2.0.21 build -o /tmp/trex-build --targets=bp-sim-64

Point ``TREX_SIM_DIR`` at the directory holding ``bp-sim-64`` to enable.
"""

import contextlib
import ipaddress
import os
import struct
from pathlib import Path

import pytest
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.utils import rdpcap

from mhddos_trex import catalog
from mhddos_trex.spec import BuildCtx, LinkSpec, RunSpec
from mhddos_trex.streams import build_streams

SIM_DIR = Path(os.environ.get("TREX_SIM_DIR", "/tmp/trex-build/linux"))
REFLECTORS = ("8.8.8.8", "1.1.1.1")

pytestmark = pytest.mark.skipif(
    not (SIM_DIR / "bp-sim-64").is_file(),
    reason="bp-sim-64 not built; set TREX_SIM_DIR",
)


def _sim():
    from trex.stl.trex_stl_sim import STLSim

    return STLSim(bp_sim_path=str(SIM_DIR))


def ctx(source):
    return BuildCtx(host="198.19.0.2", port=80, user_agents=source.user_agents, referers=source.referers)


def run_spec(carpet=None):
    return RunSpec("198.19.0.2", 80, 1000, 1, "203.0.113.0/24", None, REFLECTORS, carpet)


def emitted(name, source, tmp_path, count=30, carpet=None):
    out = tmp_path / f"{name}.pcap"
    link = LinkSpec("00:00:00:00:00:01", "00:00:00:00:00:02", 210)
    streams = build_streams(name, run_spec(carpet), link, ctx(source), source)
    with contextlib.redirect_stdout(open(os.devnull, "w")):
        _sim().run(streams, outfile=str(out), pkt_limit=count, is_debug=False, tunables=[], silent=True)
    return [Ether(bytes(pkt)) for pkt in rdpcap(str(out))]


def _sum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f">{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return total & 0xFFFF


def _pseudo(pkt, length: int) -> int:
    return _sum(
        bytes(int(x) for x in pkt[IP].src.split("."))
        + bytes(int(x) for x in pkt[IP].dst.split("."))
        + bytes([0, pkt[IP].proto])
        + length.to_bytes(2, "big")
    )


def test_every_emittable_profile_produces_packets(source, tmp_path):
    for name in catalog.emittable():
        pkts = emitted(name, source, tmp_path, count=5)
        assert pkts, f"{name} produced no traffic"


def test_hardware_offload_writes_the_pseudo_header_partial_sum(source, tmp_path):
    """``STLVmFixChecksumHw`` leaves the NIC a partial checksum to finish; the data plane
    must write exactly that, or every offloaded packet is rejected by the receiver."""
    for name in ("GET", "UDP", "DNS"):
        for pkt in emitted(name, source, tmp_path, count=3):
            if pkt.haslayer(TCP):
                emitted_sum, length = pkt[TCP].chksum, len(bytes(pkt[TCP]))
            elif pkt.haslayer(UDP):
                emitted_sum, length = pkt[UDP].chksum, len(bytes(pkt[UDP]))
            else:
                continue
            assert emitted_sum == _pseudo(pkt, length), name


def test_icmp_flood_carries_a_real_ip_checksum(source, tmp_path):
    for pkt in emitted("ICMP", source, tmp_path, count=5):
        header = bytearray(bytes(pkt[IP])[:20])
        header[10:12] = b"\x00\x00"
        assert pkt[IP].chksum == (~_sum(bytes(header))) & 0xFFFF


def test_sequence_continues_across_generated_packets(source, tmp_path):
    pkts = emitted("GET", source, tmp_path, count=30)
    seqs = [pkt[TCP].seq for pkt in pkts]
    step = len(bytes(pkts[0][TCP].payload))
    assert all(b == (a + step) % 2**32 for a, b in zip(seqs, seqs[1:]))


def test_reflector_traffic_only_addresses_the_list(source, tmp_path):
    pkts = emitted("DNS", source, tmp_path, count=20)
    assert {pkt[IP].dst for pkt in pkts} <= set(REFLECTORS)
    assert {pkt[IP].src for pkt in pkts} == {"198.19.0.2"}


def test_no_generated_frame_exceeds_the_mtu(source, tmp_path):
    for name in catalog.emittable():
        for pkt in emitted(name, source, tmp_path, count=3):
            assert len(bytes(pkt)) <= 1518, name


def test_carpet_spreads_the_destination_over_the_prefix(source, tmp_path):
    """The data plane must draw a fresh address per packet, not one drawn at compile time."""
    net = ipaddress.ip_network("198.19.0.0/24")
    for name in ("GET", "UDP", "SYN"):
        pkts = emitted(name, source, tmp_path, count=40, carpet="198.19.0.0/24")
        dests = [ipaddress.ip_address(pkt[IP].dst) for pkt in pkts]
        assert all(d in net for d in dests), name
        assert len(set(dests)) > 1, f"{name} sent every packet to one host"
        assert len({pkt[IP].src for pkt in pkts}) > 1, f"{name} kept one source host"

