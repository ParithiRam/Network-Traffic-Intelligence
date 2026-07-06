"""Rolling metrics: top talkers, protocol distribution, bandwidth time-series.

Everything is in-memory and bounded by `window_s` so memory stays flat. We
also keep monotonic totals for the headline counters.
"""
from __future__ import annotations

import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Deque

from ..models import (
    BandwidthPoint,
    MetricsSnapshot,
    PacketEvent,
    ProtocolStat,
    TopTalker,
)


@dataclass
class _Bucket:
    bytes: int = 0
    packets: int = 0


@dataclass
class _IpStat:
    bytes: int = 0
    packets: int = 0


class MetricsStore:
    def __init__(self, window_s: int = 120) -> None:
        self.window_s = window_s
        self.total_packets = 0
        self.total_bytes = 0
        self.dropped_packets = 0
        self.alerts_count = 0
        self._talkers: dict[str, _IpStat] = defaultdict(_IpStat)
        self._protos: dict[str, _IpStat] = defaultdict(_IpStat)
        self._buckets: Deque[tuple[int, _Bucket]] = deque()

    def record_packet(self, pkt: PacketEvent) -> None:
        self.total_packets += 1
        self.total_bytes += pkt.bytes
        self._talkers[pkt.src_ip].bytes += pkt.bytes
        self._talkers[pkt.src_ip].packets += 1
        self._protos[pkt.proto].bytes += pkt.bytes
        self._protos[pkt.proto].packets += 1
        self._add_to_bucket(pkt.ts, pkt.bytes)

    def record_drop(self) -> None:
        self.dropped_packets += 1

    def record_alert(self) -> None:
        self.alerts_count += 1

    def _add_to_bucket(self, ts: float, nbytes: int) -> None:
        sec = int(ts)
        if self._buckets and self._buckets[-1][0] == sec:
            self._buckets[-1][1].bytes += nbytes
            self._buckets[-1][1].packets += 1
        else:
            self._buckets.append((sec, _Bucket(bytes=nbytes, packets=1)))
        cutoff = int(time.time()) - self.window_s
        while self._buckets and self._buckets[0][0] < cutoff:
            self._buckets.popleft()

    def bandwidth(self) -> list[BandwidthPoint]:
        return [BandwidthPoint(ts=sec, bytes=b.bytes, packets=b.packets) for sec, b in self._buckets]

    def top_talkers(self, n: int = 10) -> list[TopTalker]:
        items = sorted(self._talkers.items(), key=lambda kv: kv[1].bytes, reverse=True)[:n]
        return [TopTalker(ip=ip, bytes=s.bytes, packets=s.packets) for ip, s in items]

    def protocol_distribution(self) -> list[ProtocolStat]:
        items = sorted(self._protos.items(), key=lambda kv: kv[1].bytes, reverse=True)
        return [ProtocolStat(proto=p, bytes=s.bytes, packets=s.packets) for p, s in items]

    def snapshot(self) -> MetricsSnapshot:
        return MetricsSnapshot(
            generated_at=time.time(),
            total_packets=self.total_packets,
            total_bytes=self.total_bytes,
            dropped_packets=self.dropped_packets,
            alerts_count=self.alerts_count,
            top_talkers=self.top_talkers(),
            protocols=self.protocol_distribution(),
            bandwidth=self.bandwidth(),
        )
