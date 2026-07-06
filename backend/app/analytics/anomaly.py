"""Anomaly detectors that emit synthetic Alerts (no Rule match needed).

- PortScanDetector: same src hits >= N distinct dst_ports inside `window_s`.
- BandwidthSpikeDetector: per-second byte rate exceeds mean + z*stddev over a
  rolling baseline.
"""
from __future__ import annotations

import math
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Deque, Optional

from ..models import Alert, PacketEvent


@dataclass
class _ScanState:
    ports: dict[int, float] = field(default_factory=dict)  # port -> first-seen ts
    last_alert: float = 0.0


class PortScanDetector:
    def __init__(self, threshold: int = 20, window_s: float = 10.0, cooldown_s: float = 30.0) -> None:
        self.threshold = threshold
        self.window_s = window_s
        self.cooldown_s = cooldown_s
        self._state: dict[str, _ScanState] = defaultdict(_ScanState)

    def observe(self, pkt: PacketEvent) -> Optional[Alert]:
        st = self._state[pkt.src_ip]
        cutoff = pkt.ts - self.window_s
        st.ports = {p: ts for p, ts in st.ports.items() if ts >= cutoff}
        if pkt.dst_port:
            st.ports[pkt.dst_port] = pkt.ts
        if len(st.ports) >= self.threshold and (pkt.ts - st.last_alert) > self.cooldown_s:
            st.last_alert = pkt.ts
            return Alert(
                ts=pkt.ts,
                rule="anomaly:port_scan",
                severity="high",
                src_ip=pkt.src_ip,
                dst_ip=pkt.dst_ip,
                proto=pkt.proto,
                detail=f"{len(st.ports)} distinct dst ports in {self.window_s:.0f}s",
            )
        return None


class BandwidthSpikeDetector:
    """One-second buckets, EWMA baseline, z-score test."""

    def __init__(self, z: float = 3.0, baseline_window: int = 60, cooldown_s: float = 20.0) -> None:
        self.z = z
        self.baseline_window = baseline_window
        self.cooldown_s = cooldown_s
        self._buckets: Deque[tuple[int, int]] = deque()  # (sec, bytes)
        self._last_alert = 0.0

    def observe(self, pkt: PacketEvent) -> Optional[Alert]:
        sec = int(pkt.ts)
        if self._buckets and self._buckets[-1][0] == sec:
            self._buckets[-1] = (sec, self._buckets[-1][1] + pkt.bytes)
        else:
            self._buckets.append((sec, pkt.bytes))
        while len(self._buckets) > self.baseline_window:
            self._buckets.popleft()

        if len(self._buckets) < 10:
            return None

        history = [b for _, b in list(self._buckets)[:-1]]
        current = self._buckets[-1][1]
        mean = sum(history) / len(history)
        var = sum((x - mean) ** 2 for x in history) / len(history)
        stddev = math.sqrt(var)
        if stddev == 0:
            return None
        score = (current - mean) / stddev
        if score >= self.z and (pkt.ts - self._last_alert) > self.cooldown_s:
            self._last_alert = pkt.ts
            return Alert(
                ts=pkt.ts,
                rule="anomaly:bandwidth_spike",
                severity="medium",
                src_ip=pkt.src_ip,
                dst_ip=pkt.dst_ip,
                proto=pkt.proto,
                detail=f"z={score:.2f} bytes/s={current} mean={mean:.0f}",
            )
        return None
