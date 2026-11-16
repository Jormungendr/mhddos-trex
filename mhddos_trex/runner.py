"""Drive one attack batch on a TRex server and report what was transmitted."""

import base64
from dataclasses import dataclass, field

from .spec import RunSpec


@dataclass
class ProfileResult:
    profile: str
    seconds: int
    sent: int
    pps: int
    frame_bytes: int
    flows: int
    l1_gbps: float
    oerrors: int = 0
    tx_bps_L1: float = 0.0
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "profile": self.profile,
            "seconds": self.seconds,
            "sent": self.sent,
            "pps": self.pps,
            "l1_gbps": self.l1_gbps,
            "frame_bytes": self.frame_bytes,
            "flows": self.flows,
            "oerrors": self.oerrors,
            **self.extra,
        }


class Runner:
    """Owns the TRex session for a whole batch.

    Acquiring once per batch matters: ``stop()`` needs the port held, and a per-profile
    connect/acquire cycle costs a full server round trip on a box that takes seconds to
    settle after a high-rate run.
    """

    def __init__(self, server: str = "127.0.0.1", port: int = 0):
        self.server = server
        self.port = port
        self._client = None

    def __enter__(self):
        from trex.stl.api import STLClient

        self._client = STLClient(server=self.server, verbose_level="error")
        try:
            self._client.connect()
        except Exception as error:  # noqa: BLE001 - any failure means the server is not up
            self._client = None
            raise SystemExit(
                f"TRex server unreachable at {self.server}: {error}\n"
                "start the TRex service on that host, or point --server at the running one"
            ) from error
        self._client.acquire(ports=[self.port], force=True)
        return self

    def __exit__(self, *exc):
        client = self._client
        if client is None:
            return
        for teardown in (
            lambda: client.stop(ports=[self.port]),
            lambda: client.remove_all_streams(ports=[self.port]),
            lambda: client.release(ports=[self.port]),
            client.disconnect,
        ):
            try:
                teardown()
            except Exception:  # noqa: BLE001 - teardown must not mask the real error
                pass
        self._client = None

    def run(self, profile: str, streams, run: RunSpec, seconds: int) -> ProfileResult:
        client = self._client
        client.reset(ports=[self.port])
        client.remove_all_streams(ports=[self.port])
        client.add_streams(streams, ports=[self.port])
        client.clear_stats(ports=[self.port])
        client.start(ports=[self.port], duration=seconds, force=True)
        client.wait_on_traffic(ports=[self.port], timeout=seconds + 10)
        stats = client.get_stats(ports=[self.port]).get(self.port, {})
        client.stop(ports=[self.port])

        sent = stats.get("opackets") or 0
        frame = run.size or _first_frame(streams)
        l1_bps = sent * (frame + 20) * 8 / seconds
        return ProfileResult(
            profile=profile,
            seconds=seconds,
            sent=sent,
            pps=round(sent / seconds),
            frame_bytes=frame,
            flows=run.flows,
            l1_gbps=round(l1_bps / 1e9, 3),
            oerrors=stats.get("oerrors") or 0,
        )


def _first_frame(streams) -> int:
    return len(base64.b64decode(streams[0].to_json()["packet"]["binary"]))
