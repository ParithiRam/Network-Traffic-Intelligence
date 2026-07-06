"""Shared application state — singletons created at startup."""
from __future__ import annotations

import asyncio
from dataclasses import dataclass

from .analytics.anomaly import BandwidthSpikeDetector, PortScanDetector
from .analytics.metrics import MetricsStore
from .config import settings
from .filters.engine import RuleEngine
from .models import PacketEvent
from .pipeline.broadcast import Broadcaster
from .pipeline.worker import Worker


@dataclass
class AppState:
    queue: asyncio.Queue[PacketEvent]
    engine: RuleEngine
    metrics: MetricsStore
    broadcaster: Broadcaster
    worker: Worker
    ingest_task: asyncio.Task | None = None


def build_state() -> AppState:
    queue: asyncio.Queue[PacketEvent] = asyncio.Queue(maxsize=settings.queue_size)
    engine = RuleEngine.from_file(settings.rules_path)
    metrics = MetricsStore(window_s=settings.metrics_window_s)
    broadcaster = Broadcaster()
    worker = Worker(
        queue=queue,
        engine=engine,
        metrics=metrics,
        broadcaster=broadcaster,
        port_scan=PortScanDetector(
            threshold=settings.portscan_distinct_ports,
            window_s=settings.portscan_window_s,
        ),
        bw_spike=BandwidthSpikeDetector(z=settings.spike_zscore),
    )
    return AppState(queue=queue, engine=engine, metrics=metrics, broadcaster=broadcaster, worker=worker)
