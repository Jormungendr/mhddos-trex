"""Generate the packets a compiled stream would actually put on the wire, and check them.

The field engine is replayed from TRex's own opcode semantics (``field_engine.py``), so
these assertions cover what compilation alone cannot: whether the Nth packet is still a
valid, coherent segment.
"""

from scapy.layers.inet import IP, TCP, UDP

from field_engine import FieldEngine, packets
from mhddos_trex import catalog
from mhddos_trex.spec import BuildCtx, LinkSpec, RunSpec
from mhddos_trex.streams import build_streams

LINK = LinkSpec(src_mac="00:00:00:00:00:01", dst_mac="00:00:00:00:00:02", vlan=210)
REFLECTORS = ("8.8.8.8", "1.1.1.1", "9.9.9.9")


def ctx(source):
    return BuildCtx(host="198.19.0.2", port=80, user_agents=source.user_agents, referers=source.referers)


def run(**over):
    base = dict(victim="198.19.0.2", dport=80, pps=10_000, flows=1, src_prefix="203.0.113.0/24")
    base.update(over)
    return RunSpec(**base)


def stream(name, source, **over):
    return build_streams(name, run(**over), LINK, ctx(source), source)[0].to_json()


def test_sequence_numbers_are_contiguous_across_a_thousand_packets(source):
    """A receiver reassembles by sequence number; a wrap or a gap breaks the stream."""
    pkts = packets(stream("GET", source), 1000)
    seqs = [p[TCP].seq for p in pkts]
    payload = len(bytes(pkts[0][TCP].payload))
    for previous, current in zip(seqs, seqs[1:]):
        assert current == (previous + payload) % 2**32, "sequence must advance by the payload length"


def test_checksums_are_valid_for_every_generated_packet(source):
    for pkt in packets(stream("GET", source), 200):
        assert pkt[IP].chksum == _ip_checksum(pkt), "IP checksum must match the bytes"
        assert pkt[TCP].chksum == _tcp_checksum(pkt), "TCP checksum must match the bytes"


def test_udp_checksum_is_valid_with_a_rotating_destination(source):
    for pkt in packets(stream("DNS", source, reflectors=REFLECTORS), 200):
        assert pkt[UDP].chksum == _udp_checksum(pkt)


def test_reflector_only_ever_addresses_the_given_list(source):
    pkts = packets(stream("NTP", source, reflectors=REFLECTORS), 30)
    assert {pkt[IP].dst for pkt in pkts} == set(REFLECTORS)
    assert {pkt[IP].src for pkt in pkts} == {"198.19.0.2"}


def test_reflector_rotates_in_order(source):
    pkts = packets(stream("DNS", source, reflectors=REFLECTORS), 6)
    assert [pkt[IP].dst for pkt in pkts] == list(REFLECTORS) * 2


def test_amplifier_payload_survives_every_packet(source):
    pkts = packets(stream("MEM", source, reflectors=REFLECTORS), 40)
    assert {bytes(pkt[UDP].payload) for pkt in pkts} == {
        catalog.SPECS["MEM"].build(ctx(source), 0, source)
    }


def test_fivem_token_payload_is_stable_per_stream(source):
    payloads = {bytes(pkt[UDP].payload) for pkt in packets(stream("FIVEM-TOKEN", source), 20, hold_random=True)}
    assert len(payloads) == 1
    assert payloads.pop().startswith(b"token=")


def test_padded_frames_keep_their_checksums(source):
    for pkt in packets(stream("GET", source, size=1518), 100):
        assert len(bytes(pkt)) == 1518
        assert pkt[IP].chksum == _ip_checksum(pkt)
        assert pkt[TCP].chksum == _tcp_checksum(pkt)


def test_trimmed_frame_keeps_a_well_formed_request(source):
    pkts = packets(stream("APACHE", source), 10)
    for pkt in pkts:
        payload = bytes(pkt[TCP].payload)
        assert len(bytes(pkt)) <= 1518
        assert payload.startswith(b"GET / HTTP/1.1")
        assert payload.endswith(b"\r\n\r\n")


def test_every_replayable_profile_generates_valid_packets(source):
    """Anything the engine can replay must stay coherent for many packets, not one."""
    for name in catalog.emittable():
        stream_json = stream(name, source, reflectors=REFLECTORS)
        engine = FieldEngine(stream_json)
        if not engine.reproducible:
            continue
        for pkt in packets(stream_json, 50):
            assert pkt[IP].chksum == _ip_checksum(pkt), name
            if pkt.haslayer(TCP):
                assert pkt[TCP].chksum == _tcp_checksum(pkt), name
            elif pkt.haslayer(UDP) and pkt[UDP].chksum:
                assert pkt[UDP].chksum == _udp_checksum(pkt), name


def _pseudo(pkt, seg: bytes) -> bytes:
    return (
        bytes(int(x) for x in pkt[IP].src.split("."))
        + bytes(int(x) for x in pkt[IP].dst.split("."))
        + bytes([0, pkt[IP].proto])
        + len(seg).to_bytes(2, "big")
    )


def _ip_checksum(pkt):
    from field_engine import checksum

    header = bytearray(bytes(pkt[IP])[:20])
    header[10:12] = b"\x00\x00"
    return checksum(bytes(header))


def _tcp_checksum(pkt):
    from field_engine import checksum

    seg = bytearray(bytes(pkt[TCP]))
    seg[16:18] = b"\x00\x00"
    return checksum(_pseudo(pkt, bytes(seg)) + bytes(seg))


def _udp_checksum(pkt):
    from field_engine import checksum

    seg = bytearray(bytes(pkt[UDP]))
    seg[6:8] = b"\x00\x00"
    return checksum(_pseudo(pkt, bytes(seg)) + bytes(seg)) or 0xFFFF
