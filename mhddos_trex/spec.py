"""Attack description shared by the catalog, the stream builder and the CLI."""

from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum


class Proto(Enum):
    UDP = "udp"
    TCP = "tcp"
    ICMP = "icmp"


class SrcMode(Enum):
    """Where the source address comes from."""

    POOL = "pool"
    RANDOM = "random"
    REFLECTOR = "reflector"


class Verdict(Enum):
    WIRE = "wire"
    SHAPE = "shape"
    NEEDS_ASTF = "needs_astf"
    CLIENT_LOGIC = "client_logic"


@dataclass(frozen=True)
class AttackSpec:
    """One MHDDoS method reduced to what the wire can carry.

    ``build`` maps (context, stream index) to one L7 payload, so methods whose MHDDoS
    implementation varies the payload per packet vary it per stream instead.
    """

    name: str
    verdict: Verdict
    proto: Proto
    build: Callable | None = None
    dport: int = PORT_ANY
    flags: str = "PA"
    src_mode: SrcMode = SrcMode.POOL


@dataclass(frozen=True)
class LinkSpec:
    src_mac: str
    dst_mac: str
    vlan: int | None = None


@dataclass(frozen=True)
class RunSpec:
    victim: str
    dport: int
    pps: int
    flows: int
    src_prefix: str
    size: int | None = None
    reflectors: tuple[str, ...] = ()


@dataclass(frozen=True)
class BuildCtx:
    """Target identity the payload builders embed in L7."""

    host: str
    port: int
    user_agents: tuple[str, ...] = field(default=())
    referers: tuple[str, ...] = field(default=())

    @property
    def authority(self) -> str:
        return self.host if self.port in (80, 443) else f"{self.host}:{self.port}"
