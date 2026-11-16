"""Command line: `python -m mhddos_trex`."""

import argparse
import json
import sys
from pathlib import Path

from . import catalog, mhddos
from .spec import BuildCtx, LinkSpec, RunSpec, Verdict


def build_ctx(source, host: str, port: int) -> BuildCtx:
    return BuildCtx(host=host, port=port, user_agents=source.user_agents, referers=source.referers)


def resolve_target(args) -> tuple[str, int]:
    host = args.host
    if host is None:
        raise SystemExit("--host must be set to the victim hostname (MHDDoS builds Host: from it)")
    port = args.dport or (443 if args.scheme == "https" else 80)
    return host, port


def make_run_spec(args) -> RunSpec:
    reflectors = ()
    if args.reflectors:
        text = Path(args.reflectors).read_text(errors="ignore")
        reflectors = tuple(dict.fromkeys(line.split()[0] for line in text.splitlines() if line.strip()))
    return RunSpec(
        victim=args.victim,
        dport=args.dport,
        pps=args.pps,
        flows=args.flows,
        src_prefix=args.src_prefix,
        size=args.size,
        reflectors=reflectors,
    )


def make_link_spec(args) -> LinkSpec:
    return LinkSpec(src_mac=args.src_mac, dst_mac=args.dst_mac, vlan=args.vlan)


def do_list(args) -> int:
    source = mhddos.load(mhddos.locate(args.mhddos_dir))
    missing = catalog.unimplemented(source)
    if missing:
        print(f"uncovered MHDDoS methods: {', '.join(missing)}", file=sys.stderr)
        return 1
    for name in sorted(catalog.SPECS):
        spec = catalog.SPECS[name]
        note = catalog.REASONS.get(name, "")
        print(f"{name:<12} {spec.proto.value:<5} {spec.verdict.value:<13} {note}")
    print(f"\n{len(catalog.emittable())} emittable, {len(catalog.REASONS)} deferred", file=sys.stderr)
    return 0


def do_dry_run(args) -> int:
    from .streams import build_streams

    source = mhddos.load(mhddos.locate(args.mhddos_dir))
    host, port = resolve_target(args)
    ctx = build_ctx(source, host, port)
    run = make_run_spec(args)
    link = make_link_spec(args)
    out = [
        {"profile": name, "streams": [s.to_json() for s in build_streams(name, run, link, ctx, source)]}
        for name in args.profile
    ]
    json.dump(out, sys.stdout, indent=2)
    return 0


def do_run(args) -> int:
    from .runner import Runner
    from .streams import build_streams

    source = mhddos.load(mhddos.locate(args.mhddos_dir))
    host, port = resolve_target(args)
    ctx = build_ctx(source, host, port)
    run = make_run_spec(args)
    link = make_link_spec(args)

    results = []
    with Runner(server=args.server, port=args.trex_port) as runner:
        for name in args.profile:
            streams = build_streams(name, run, link, ctx, source)
            result = runner.run(name, streams, run, args.seconds)
            results.append(result.to_dict())
            print(json.dumps(result.to_dict()))

    if args.out:
        Path(args.out).write_text(json.dumps(results, indent=2))
    return 0


def parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="mhddos_trex", description=__doc__)
    ap.add_argument("--mhddos-dir", help="MHDDoS checkout holding start.py")
    sub = ap.add_subparsers(dest="command", required=True)

    sub.add_parser("list", help="show every MHDDoS method and whether it can be emitted")

    for name in ("dry-run", "run"):
        p = sub.add_parser(name)
        p.add_argument("profile", nargs="+", help="method name(s), or 'all'")
        p.add_argument("--victim", required=True)
        p.add_argument("--host", help="hostname in Host: (defaults to --victim)")
        p.add_argument("--scheme", default="http", choices=("http", "https"))
        p.add_argument("--dport", type=int, default=0)
        p.add_argument("--pps", type=int, default=100_000)
        p.add_argument("--flows", type=int, default=64)
        p.add_argument("--seconds", type=int, default=10)
        p.add_argument("--src-prefix", default="203.0.113.0/24")
        p.add_argument("--size", type=int, default=None, help="pad frames to this L2 size")
        p.add_argument("--vlan", type=int, default=None)
        p.add_argument("--src-mac", default="00:00:00:00:00:01")
        p.add_argument("--dst-mac", default="00:00:00:00:00:02")
        p.add_argument("--reflectors", help="file of reflector addresses, one per line")
        p.add_argument("--server", default="127.0.0.1")
        p.add_argument("--trex-port", type=int, default=0)
        p.add_argument("--out", help="write results JSON here")
    return ap


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if args.command == "list":
        return do_list(args)
    if getattr(args, "host", None) is None:
        args.host = args.victim
    if "all" in args.profile:
        args.profile = catalog.emittable()
    else:
        unknown = [p for p in args.profile if p not in catalog.SPECS]
        if unknown:
            raise SystemExit(f"unknown method(s): {', '.join(unknown)}")
        deferred = [p for p in args.profile if catalog.SPECS[p].verdict not in (Verdict.WIRE, Verdict.SHAPE)]
        if deferred:
            for name in deferred:
                print(f"{name}: {catalog.REASONS.get(name, 'not emittable')}", file=sys.stderr)
            raise SystemExit("refusing to run non-emittable methods")
    return do_dry_run(args) if args.command == "dry-run" else do_run(args)


if __name__ == "__main__":
    raise SystemExit(main())
