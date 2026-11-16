"""Stream shape: source model, sequence continuity, rate split, padding.

These run without a TRex server - the stream objects compile to profile JSON locally.
"""

import ipaddress

import pytest
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Dot1Q, Ether
from scapy.packet import Raw

from mhddos_trex import catalog
from mhddos_trex.spec import BuildCtx, LinkSpec, RunSpec, SrcMode
from mhddos_trex.streams import build_streams

LINK = LinkSpec(src_mac="00:00:00:00:00:01", dst_mac="00:00:00:00:00:02", vlan=210)
REFLECTORS = ("8.8.8.8", "1.1.1.1", "9.9.9.9")


def ctx(source) -> BuildCtx:
    return BuildCtx(host="198.19.0.2", port=80, user_agents=source.user_agents, referers=source.referers)


def run(**over) -> RunSpec:
    base = dict(victim="198.19.0.2", dport=80, pps=10_000, flows=4, src_prefix="203.0.113.0/24")
    base.update(over)
    return RunSpec(**base)


def frame(stream):
    """Decode a compiled stream back into a scapy packet."""
    import base64

    raw = base64.b64decode(stream.to_json()["packet"]["binary"])
    return Ether(raw)


def test_every_emittable_method_builds(source):
    for name in catalog.emittable():
        streams = build_streams(name, run(), LINK, ctx(source), source)
        assert len(streams) == 4, name
        assert all(s.to_json()["vm"] is not None for s in streams), name


def test_deferred_method_is_refused(source):
    for name in catalog.REASONS:
        with pytest.raises(ValueError):
            build_streams(name, run(), LINK, ctx(source), source)


def test_vlan_and_macs_are_preserved(source):
    pkt = frame(build_streams("GET", run(), LINK, ctx(source), source)[0])
    assert pkt[Dot1Q].vlan == 210
    assert pkt[Ether].src == LINK.src_mac
    assert pkt[Ether].dst == LINK.dst_mac


def test_no_vlan_tag_when_unset(source):
    link = LinkSpec(src_mac=LINK.src_mac, dst_mac=LINK.dst_mac, vlan=None)
    pkt = frame(build_streams("GET", run(), link, ctx(source), source)[0])
    assert not pkt.haslayer(Dot1Q)


def test_pool_mode_keeps_one_source_per_stream(source):
    """A client-side flood came from N distinct hosts, not one host inventing SPRTs."""
    streams = build_streams("GET", run(flows=4), LINK, ctx(source), source)
    sources = {frame(s)[IP].src for s in streams}
    sports = {frame(s)[TCP].sport for s in streams}
    assert len(sources) == 4
    assert len(sports) == 4
    assert not any(i["type"] == "flow_var" and i.get("name") == "src" for s in streams for i in s.to_json()["vm"]["instructions"])


def _offset(pkt, layer: type, field: str) -> int:
    """Byte offset of a field within the whole frame.

    Uses the per-field ``_offset`` that TRex's vendored scapy adds - the same value the
    field engine's name resolver reads, so the assertion cannot disagree with the compiler.
    """
    layer_pkt = pkt[layer]
    base = len(bytes(pkt)) - len(bytes(layer_pkt))
    desc = next(d for d in layer_pkt.fields_desc if d.name == field)
    return base + desc._offset


def test_tcp_sequence_advances_by_payload_length(source):
    streams = build_streams("GET", run(flows=1), LINK, ctx(source), source)
    instructions = streams[0].to_json()["vm"]["instructions"]
    step = next(i["step"] for i in instructions if i["type"] == "flow_var" and i["name"] == "seq")
    pkt = frame(streams[0])
    payload_len = len(bytes(pkt[Raw].load))
    assert step == payload_len, "seq must advance by exactly what was sent"
    assert instructions[1]["pkt_offset"] == _offset(pkt, TCP, "seq")


def test_spoofed_modes_rewrite_and_repair_checksums(source):
    """UDP/ICMP floods randomize the source per packet, so the checksums must be repaired."""
    for name in ("UDP", "SYN", "ICMP", "OVH-UDP"):
        spec = catalog.SPECS[name]
        assert spec.src_mode is SrcMode.RANDOM
        types = {i["type"] for i in build_streams(name, run(flows=1), LINK, ctx(source), source)[0].to_json()["vm"]["instructions"]}
        assert "write_flow_var" in types
        assert types & {"fix_checksum_hw", "fix_checksum_ipv4"}


def test_reflector_sends_from_victim_to_reflector(source):
    for stream in build_streams("DNS", run(reflectors=REFLECTORS), LINK, ctx(source), source):
        pkt = frame(stream)
        assert pkt[IP].src == "198.19.0.2"
        assert pkt[IP].dst in REFLECTORS
        assert pkt[UDP].dport == 53


def test_reflector_request_keeps_the_victim_port_as_source(source):
    """The reflector replies to the victim's port, so that is what the source port must be."""
    streams = build_streams("DNS", run(dport=8080, reflectors=REFLECTORS), LINK, ctx(source), source)
    for stream in streams:
        pkt = frame(stream)
        assert pkt[UDP].sport == 8080
        assert pkt[UDP].dport == 53


def test_reflector_rotates_destination_in_the_field_engine(source):
    streams = build_streams("DNS", run(reflectors=REFLECTORS), LINK, ctx(source), source)
    instructions = streams[0].to_json()["vm"]["instructions"]
    field = next(i for i in instructions if i["type"] == "write_flow_var" and i.get("name") == "dst")
    assert field["pkt_offset"] == _offset(frame(streams[0]), IP, "dst")


def test_reflector_requires_a_list_to_stay_honest(source):
    """With no list, the victim is its own reflector - the stream still builds, one target."""
    streams = build_streams("NTP", run(reflectors=()), LINK, ctx(source), source)
    assert frame(streams[0])[IP].dst == "198.19.0.2"


def test_rate_is_split_across_flows(source):
    streams = build_streams("UDP", run(pps=10_000, flows=4), LINK, ctx(source), source)
    assert [s.to_json()["mode"]["rate"]["value"] for s in streams] == [2_500] * 4


def test_rate_never_rounds_to_zero(source):
    streams = build_streams("UDP", run(pps=2, flows=8), LINK, ctx(source), source)
    assert all(s.to_json()["mode"]["rate"]["value"] >= 1 for s in streams)


def test_padding_lands_outside_the_headers(source):
    pkt = frame(build_streams("GET", run(size=1518), LINK, ctx(source), source)[0])
    assert len(bytes(pkt)) == 1518
    assert pkt[TCP].dport == 80


def test_padding_is_off_by_default(source):
    pkt = frame(build_streams("PPS", run(), LINK, ctx(source), source)[0])
    assert len(bytes(pkt)) < 200


def test_amplifier_ports_come_from_the_spec(source):
    expected = {"DNS": 53, "NTP": 123, "MEM": 11211, "CLDAP": 389, "CHAR": 19, "ARD": 3283, "RDP": 3389}
    for name, port in expected.items():
        pkt = frame(build_streams(name, run(reflectors=REFLECTORS), LINK, ctx(source), source)[0])
        assert pkt[UDP].dport == port, name


def test_protocol_queries_go_to_the_target_port(source):
    """MHDDoS sends VSE/TS3/MCPE/FIVEM to the target's own port, not a protocol default."""
    for name in ("VSE", "TS3", "MCPE", "FIVEM", "FIVEM-TOKEN"):
        pkt = frame(build_streams(name, run(dport=27015), LINK, ctx(source), source)[0])
        assert pkt[UDP].dport == 27015, name


def test_payloads_differ_between_streams(source):
    """Each stream carries its own identity, so N streams look like N clients."""
    payloads = [bytes(frame(s)[Raw].load) for s in build_streams("GET", run(flows=8), LINK, ctx(source), source)]
    assert len(set(payloads)) == len(payloads)


def test_source_pool_stays_inside_the_prefix(source):
    streams = build_streams("GET", run(flows=8, src_prefix="203.0.113.0/24"), LINK, ctx(source), source)
    net = ipaddress.ip_network("203.0.113.0/24")
    assert all(ipaddress.ip_address(frame(s)[IP].src) in net for s in streams)


def test_host_prefix_collapses_to_the_single_address(source):
    """A /32 has no host range; stepping past it would forge an address nobody configured."""
    streams = build_streams("GET", run(flows=4, src_prefix="198.18.5.10/32"), LINK, ctx(source), source)
    assert {frame(s)[IP].src for s in streams} == {"198.18.5.10"}


def test_syn_has_no_payload(source):
    pkt = frame(build_streams("SYN", run(), LINK, ctx(source), source)[0])
    assert pkt[TCP].flags == "S"
    assert not pkt.haslayer(Raw)
