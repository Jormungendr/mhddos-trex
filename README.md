# mhddos-trex

MHDDoS attack shapes emitted by TRex at line rate, so a DDoS detection and scrubbing path
can be exercised with the same packet-level evidence a Python attacker produces, without
Python's per-packet cost.

MHDDoS is a single-file Python tool: its attack methods are only as fast as one thread's
socket loop. This package keeps the wire shapes and moves transmission to TRex's DPDK data
plane.

## Install

TRex's control plane and its vendored scapy must be importable (both ship with TRex):

```sh
export TREX=/opt/v3.07
export PYTHONPATH=$TREX/automation/trex_control_plane/interactive:$TREX/external_libs/scapy-2.4.3
pip install mhddos-trex
```

Use the interpreter TRex ships (`/opt/trex-python/bin/python3`). The vendored scapy is
required: TRex annotates each scapy field with the byte offset its field engine resolves,
and a stock scapy does not.

## Use

```sh
mhddos-trex list                      # every MHDDoS method and whether it can be emitted
mhddos-trex dry-run GET --victim 198.19.0.2 --flows 64   # print the compiled profile, no traffic
mhddos-trex run GET POST --victim 198.19.0.2 --pps 1000000 --seconds 30
mhddos-trex run all --victim 198.19.0.2 --pps 50000 --seconds 5   # smoke every profile
mhddos-trex run DNS --victim 198.19.0.2 --reflectors reflectors.txt --pps 200000
```

MHDDoS's own checkout is located via `--mhddos-dir` or `MHDDOS_DIR`. It is read, never
executed: payload constants and wordlists are lifted from `start.py` with `ast`, so this
package carries no second copy of them and follows an upstream update without code change.

`--host` sets the hostname used in `Host:` when it differs from the packet destination.

## What is reproduced

36 of MHDDoS's 46 methods. `mhddos-trex list` prints the verdict for every one:

| Verdict | Meaning |
|---|---|
| `wire` | payload bytes and header layout identical to MHDDoS |
| `shape` | request shape identical; no handshake, or a response-driven step becomes a fixed-rate stream |
| `needs_astf` | needs a real TCP session — deferred, see below |
| `client_logic` | the decision lives in the attacking client; nothing distinguishable on the wire |

`needs_astf` covers MINECRAFT, CPS, CONNECTION, MCBOT, SLOW and DOWNLOADER. It is blocked
on the lab return path, not on effort: ASTF needs the DUT to answer SYN, and the current
single-port lab drops in hardware. `client_logic` covers CFB, BYPASS, DGB and TOR.

Amplification profiles emit the **request**: source spoofed as the victim, destination
rotating over the reflector list. Amplified response volume needs a real reflector.

## Source models

- **pool** (TCP carriers): one source address and port per stream, `TCP.seq` advancing by
  the payload length, so a scrubber reassembles a coherent request stream from one client.
- **random / reflector** (UDP, ICMP, amplifiers): `IP.src` or `IP.dst` and `sport`
  rewritten per packet by the field engine — a spoofed flood.

Rewritten headers invalidate both checksums, so those streams carry a repair instruction:
`STLVmFixChecksumHw` uses NIC TX offload (TRex has no software L4 checksum instruction),
`STLVmFixIpv4` for ICMP. **A NIC without TX checksum offload will emit wrong checksums** —
the mlx5 lab NICs support it.

## Limits worth knowing

- Payload bytes are baked into the template. MHDDoS draws fresh `urandom` per packet; here
  a fixed set cycles across streams, so entropy across the attack is preserved but not per
  packet.
- The field engine cannot resize a packet, so variable-length methods carry a few size
  variants instead of one random length.
- `STLTXCont` cannot chain, so payload variety comes from N parallel streams at
  `pps/N`, not from a rotating packet list.
- `--pps` is the total across flows.

## Tests

```sh
pytest -q
```

No TRex server needed: streams compile to profile JSON locally, and the MHDDoS source is
parsed to cross-check every extracted constant.

Lab verification runs against the TRex host over SSH, the same way the existing lab
scripts do. That step is manual and needs the TRex service up.
