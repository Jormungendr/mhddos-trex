"""Replay compiled streams the way TRex's data plane would, and check what comes out.

Compiling a profile only proves the server would accept it. This replays the field engine
over a template to produce the packets that would actually go on the wire, so a wrong
offset, a wrong step or a sequence range that wraps can be caught without a TRex host.
Opcode semantics are transcribed from ``src/stx/stl/trex_stl_stream_vm.h``; only ``inc``
and ``dec`` are reproducible, since ``random`` draws from the data plane's RNG.
"""

import base64
import struct

from scapy.layers.l2 import Ether

L4_TYPE_UDP = 11
L4_TYPE_TCP = 13
REPRODUCIBLE_OPS = ("inc", "dec")


def inc_mod(low: int, high: int, current: int, step: int) -> int:
    """Forward with wrap at ``high``, per ``inc_mod`` in trex_stl_stream_vm.h."""
    left = high - current
    return current + step if step <= left else low + (step - left - 1)


def dec_mod(low: int, high: int, current: int, step: int) -> int:
    left = current - low
    return current - step if step <= left else high - (step - left - 1)


def inc_mod_list(size: int, index: int, step: int) -> int:
    nxt = index + step
    return nxt - size if nxt >= size else nxt


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f">{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


class FieldEngine:
    def __init__(self, stream_json: dict, hold_random: bool = False):
        self.template = bytearray(base64.b64decode(stream_json["packet"]["binary"]))
        self.instructions = (stream_json.get("vm") or {}).get("instructions", [])
        self.hold_random = hold_random
        self.sizes = {i["name"]: i.get("size", 4) for i in self.instructions if i["type"] == "flow_var"}
        self.values: dict[str, int] = {}
        self.lists: dict[str, tuple[list[int], int]] = {}
        for inst in self.instructions:
            if inst["type"] != "flow_var":
                continue
            if inst.get("value_list"):
                self.lists[inst["name"]] = (list(inst["value_list"]), 0)
                self.values[inst["name"]] = inst["value_list"][0]
            else:
                self.values[inst["name"]] = inst.get("init_value", inst["min_value"])

    @property
    def reproducible(self) -> bool:
        return self.hold_random or all(
            inst["type"] != "flow_var" or inst.get("op") in REPRODUCIBLE_OPS
            for inst in self.instructions
        )

    def next_packet(self) -> bytearray:
        pkt = bytearray(self.template)
        for inst in self.instructions:
            kind = inst["type"]
            if kind == "write_flow_var":
                self._write(pkt, inst)
            elif kind == "fix_checksum_ipv4":
                self._fix_ipv4(pkt, inst["pkt_offset"])
            elif kind == "fix_checksum_hw":
                self._fix_hw(pkt, inst)
        self._advance()
        return pkt

    def _write(self, pkt: bytearray, inst: dict) -> None:
        name = inst["name"]
        size = self.sizes[name]
        offset = inst["pkt_offset"] + inst.get("offset_fixup", 0)
        value = (self.values[name] + inst.get("add_value", 0)) & (2 ** (size * 8) - 1)
        pkt[offset : offset + size] = value.to_bytes(size, "big")

    def _advance(self) -> None:
        for inst in self.instructions:
            if inst["type"] != "flow_var":
                continue
            name = inst["name"]
            step = inst.get("step", 1)
            if name in self.lists:
                values, index = self.lists[name]
                index = inc_mod_list(len(values), index, step)
                self.values[name] = values[index]
                self.lists[name] = (values, index)
            elif inst["op"] == "random":
                if not self.hold_random:
                    raise ValueError("random flow var cannot be replayed")
            elif inst["op"] == "inc":
                self.values[name] = inc_mod(inst["min_value"], inst["max_value"], self.values[name], step)
            elif inst["op"] == "dec":
                self.values[name] = dec_mod(inst["min_value"], inst["max_value"], self.values[name], step)

    def _fix_ipv4(self, pkt: bytearray, offset: int) -> None:
        pkt[offset + 10 : offset + 12] = b"\x00\x00"
        pkt[offset + 10 : offset + 12] = struct.pack(">H", checksum(bytes(pkt[offset : offset + 20])))

    def _fix_hw(self, pkt: bytearray, inst: dict) -> None:
        l3 = inst["l2_len"]
        self._fix_ipv4(pkt, l3)
        l4 = l3 + (pkt[l3] & 0x0F) * 4
        seg = bytes(pkt[l4:])
        pseudo = bytes(pkt[l3 + 12 : l3 + 20]) + bytes([0, pkt[l3 + 9]]) + struct.pack(">H", len(seg))
        if inst["l4_type"] == L4_TYPE_TCP:
            body = bytearray(seg)
            body[16:18] = b"\x00\x00"
            pkt[l4 + 16 : l4 + 18] = struct.pack(">H", checksum(pseudo + bytes(body)))
        elif inst["l4_type"] == L4_TYPE_UDP:
            body = bytearray(seg)
            body[6:8] = b"\x00\x00"
            pkt[l4 + 6 : l4 + 8] = struct.pack(">H", checksum(pseudo + bytes(body)) or 0xFFFF)


def packets(stream_json: dict, count: int, hold_random: bool = False) -> list[Ether]:
    engine = FieldEngine(stream_json, hold_random=hold_random)
    if not engine.reproducible:
        raise ValueError("stream uses random ops and cannot be replayed")
    return [Ether(bytes(engine.next_packet())) for _ in range(count)]
