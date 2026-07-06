"""Generates synthetic PacketEvents that look like a real LAN.

Why: live capture needs admin/Npcap and a noisy network, neither of which is
reliable in CI or Docker. The simulator weaves in a port scan + traffic spike
every ~30s so the analytics layer has signals to find.
"""
from __future__ import annotations

import asyncio
import random
import time
from typing import AsyncIterator

from ..models import PacketEvent

_INTERNAL_HOSTS = [f"10.0.1.{i}" for i in range(2, 12)]
_EXTERNAL_HOSTS = [
    "8.8.8.8",
    "1.1.1.1",
    "151.101.1.69",
    "140.82.112.3",
    "142.250.80.46",
    "13.107.42.14",
]
_SNIS = ["github.com", "google.com", "cloudflare.com", "anthropic.com", "stackoverflow.com"]
_HTTP_HOSTS = ["api.internal", "metrics.internal", "auth.internal"]


def _normal_packet(now: float) -> PacketEvent:
    src = random.choice(_INTERNAL_HOSTS)
    roll = random.random()
    if roll < 0.55:
        return PacketEvent(
            ts=now,
            src_ip=src,
            dst_ip=random.choice(_EXTERNAL_HOSTS),
            src_port=random.randint(30000, 60000),
            dst_port=443,
            proto="TLS",
            bytes=random.randint(120, 1500),
            tls_sni=random.choice(_SNIS),
        )
    if roll < 0.75:
        return PacketEvent(
            ts=now,
            src_ip=src,
            dst_ip=random.choice(_INTERNAL_HOSTS),
            src_port=random.randint(30000, 60000),
            dst_port=80,
            proto="HTTP",
            bytes=random.randint(200, 1200),
            http_host=random.choice(_HTTP_HOSTS),
        )
    if roll < 0.9:
        return PacketEvent(
            ts=now,
            src_ip=src,
            dst_ip=random.choice(_EXTERNAL_HOSTS),
            src_port=random.randint(30000, 60000),
            dst_port=53,
            proto="DNS",
            bytes=random.randint(60, 200),
        )
    return PacketEvent(
        ts=now,
        src_ip=src,
        dst_ip=random.choice(_INTERNAL_HOSTS),
        src_port=random.randint(30000, 60000),
        dst_port=random.choice([22, 3306, 6379, 5432]),
        proto="TCP",
        bytes=random.randint(80, 600),
    )


async def synthetic_stream(pps: int = 40) -> AsyncIterator[PacketEvent]:
    interval = 1.0 / max(pps, 1)
    next_anomaly = time.time() + 30
    while True:
        now = time.time()
        # Inject port scan: same src hits 30 distinct ports rapidly.
        if now >= next_anomaly:
            attacker = random.choice(_INTERNAL_HOSTS)
            target = random.choice(_INTERNAL_HOSTS)
            for port in random.sample(range(1, 1025), 30):
                yield PacketEvent(
                    ts=time.time(),
                    src_ip=attacker,
                    dst_ip=target,
                    src_port=random.randint(40000, 60000),
                    dst_port=port,
                    proto="TCP",
                    bytes=64,
                    flags=["SYN"],
                )
                await asyncio.sleep(0.002)
            # Then a bandwidth spike.
            for _ in range(120):
                yield PacketEvent(
                    ts=time.time(),
                    src_ip=attacker,
                    dst_ip=random.choice(_EXTERNAL_HOSTS),
                    src_port=random.randint(40000, 60000),
                    dst_port=443,
                    proto="TLS",
                    bytes=random.randint(8000, 12000),
                    tls_sni=random.choice(_SNIS),
                )
                await asyncio.sleep(0.001)
            next_anomaly = time.time() + 60
            continue

        yield _normal_packet(now)
        await asyncio.sleep(interval)
