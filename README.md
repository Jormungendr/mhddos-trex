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

`scripts/install-remote.sh` deploys the package, an MHDDoS checkout and a `mhddos-trex`
wrapper onto a TRex host, and installs this guide beside it as `AGENT-USAGE.md`. The lab VM
at `root@10.172.10.34` is deployed that way; [docs/agent-usage-261116.md](docs/agent-usage-261116.md)
is what an agent should read before driving it.

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

`tests/test_dataplane.py` goes further and executes every profile in TRex's own C++ data
plane, then reads the emitted frames back out of a pcap. Build the simulator once and
point `TREX_SIM_DIR` at it:

```sh
cd ../trex-core/linux
python3 ./waf-2.0.21 configure -o /tmp/trex-build
python3 ./waf-2.0.21 build -o /tmp/trex-build --targets=bp-sim-64
TREX_SIM_DIR=/tmp/trex-build/linux pytest -q
```

That covers frame sizes, source/destination addressing, sequence continuity and the
hardware-offload checksum the spoofed profiles depend on.

`tests/test_live.py` drives a real STL server over ZMQ — acquire, load, transmit, read the
per-port counters, release. Skipped unless `TREX_SERVER` names one:

```sh
TREX_SERVER=127.0.0.1 pytest tests/test_live.py -q
```

## Measured

TRex v3.08 on `net_null` ports, 8 flows, 3-second runs, zero output errors. The rate the
operator asked for is the rate that leaves the port:

| Profile | asked | transmitted | L1 |
|---|---|---|---|
| GET | 1M pps | 1,000,000 pps | 5.3 Gbps |
| UDP | 1M pps | 1,000,000 pps | 8.6 Gbps |
| SYN | 1M pps | 1,000,000 pps | 0.5 Gbps |
| GET | 10M pps | 10,000,000 pps | 53 Gbps |
| UDP | 10M pps | 10,000,000 pps | 86 Gbps |
| SYN | 10M pps | 10,000,000 pps | 5.1 Gbps |

MHDDoS's own Python loop tops out orders of magnitude below this. The numbers are per
server core, on a port that discards its output, so they measure the generator and not the
link; a real NIC and the scrubbing DUT add their own ceiling.
