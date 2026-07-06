"""Read packets from a PCAP file and yield PacketEvents."""
from __future__ import annotations

import asyncio
from pathlib import Path
from typing import AsyncIterator

from ..models import PacketEvent
from .parser import parse_scapy


async def pcap_stream(path: str | Path, replay_realtime: bool = False) -> AsyncIterator[PacketEvent]:
    from scapy.all import PcapReader  # imported lazily; scapy import is slow

    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"PCAP not found: {p}")

    loop = asyncio.get_event_loop()
    reader = PcapReader(str(p))

    def _next():
        try:
            return next(reader)
        except StopIteration:
            return None

    last_pkt_time: float | None = None
    while True:
        pkt = await loop.run_in_executor(None, _next)
        if pkt is None:
            break
        ts = float(getattr(pkt, "time", 0.0)) or 0.0
        if replay_realtime and last_pkt_time is not None and ts > last_pkt_time:
            await asyncio.sleep(min(ts - last_pkt_time, 1.0))
        last_pkt_time = ts
        event = parse_scapy(pkt, ts)
        if event is not None:
            yield event
