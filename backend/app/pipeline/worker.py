"""The processing worker.

A single coroutine reads PacketEvents from the asyncio queue, runs them through
the rule engine, updates metrics, fires anomaly detectors, persists Alerts to
SQLite, and broadcasts deltas to WebSocket subscribers.
"""
from __future__ import annotations

import asyncio
import logging
import time
from typing import Optional

from ..analytics.anomaly import BandwidthSpikeDetector, PortScanDetector
from ..analytics.metrics import MetricsStore
from ..db import AlertRow, SessionLocal
from ..filters.engine import RuleEngine
from ..models import Alert, PacketEvent
from .broadcast import Broadcaster

log = logging.getLogger(__name__)


class Worker:
    def __init__(
        self,
        queue: asyncio.Queue[PacketEvent],
        engine: RuleEngine,
        metrics: MetricsStore,
        broadcaster: Broadcaster,
        port_scan: Optional[PortScanDetector] = None,
        bw_spike: Optional[BandwidthSpikeDetector] = None,
    ) -> None:
        self.queue = queue
        self.engine = engine
        self.metrics = metrics
        self.broadcaster = broadcaster
        self.port_scan = port_scan or PortScanDetector()
        self.bw_spike = bw_spike or BandwidthSpikeDetector()
        self._task: Optional[asyncio.Task] = None
        self._stopping = asyncio.Event()
        self._packet_throttle_ts = 0.0

    def start(self) -> None:
        if self._task is None or self._task.done():
            self._stopping.clear()
            self._task = asyncio.create_task(self._run(), name="nti-worker")

    async def stop(self) -> None:
        self._stopping.set()
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):
                pass

    async def _run(self) -> None:
        while not self._stopping.is_set():
            try:
                pkt = await self.queue.get()
            except asyncio.CancelledError:
                break
            try:
                await self._process(pkt)
            except Exception:  # never let one bad packet kill the loop
                log.exception("worker failed on packet %r", pkt)

    async def _process(self, pkt: PacketEvent) -> None:
        decision = self.engine.evaluate(pkt)
        if decision.action == "drop":
            self.metrics.record_drop()
            return
        self.metrics.record_packet(pkt)

        alerts: list[Alert] = []
        if decision.action == "alert" and decision.rule is not None:
            alerts.append(self.engine.make_alert(pkt, decision.rule))

        if (anomaly := self.port_scan.observe(pkt)) is not None:
            alerts.append(anomaly)
        if (anomaly := self.bw_spike.observe(pkt)) is not None:
            alerts.append(anomaly)

        for alert in alerts:
            self.metrics.record_alert()
            await self._persist_alert(alert)
            self.broadcaster.publish({"type": "alert", "data": alert.model_dump()})

        # Throttle packet broadcasts to ~10/s so the WebSocket isn't a firehose.
        now = time.time()
        if now - self._packet_throttle_ts >= 0.1:
            self._packet_throttle_ts = now
            self.broadcaster.publish({"type": "packet", "data": pkt.model_dump()})

    async def _persist_alert(self, alert: Alert) -> None:
        async with SessionLocal() as session:
            row = AlertRow(
                ts=alert.ts,
                rule=alert.rule,
                severity=alert.severity,
                src_ip=alert.src_ip,
                dst_ip=alert.dst_ip,
                proto=alert.proto,
                detail=alert.detail,
            )
            session.add(row)
            await session.commit()
