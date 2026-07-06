"""Tiny pub/sub: each subscriber gets its own bounded asyncio.Queue.

Used by the WebSocket layer so multiple dashboards can tail the same stream
without coupling to the worker.
"""
from __future__ import annotations

import asyncio
from typing import Any


class Broadcaster:
    def __init__(self, max_per_subscriber: int = 256) -> None:
        self._subs: list[asyncio.Queue] = []
        self._max = max_per_subscriber

    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=self._max)
        self._subs.append(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        try:
            self._subs.remove(q)
        except ValueError:
            pass

    def publish(self, message: Any) -> None:
        for q in list(self._subs):
            if q.full():
                # Drop oldest to keep slow consumers from blocking the worker.
                try:
                    q.get_nowait()
                except asyncio.QueueEmpty:
                    pass
            try:
                q.put_nowait(message)
            except asyncio.QueueFull:
                pass
