from __future__ import annotations

import asyncio
import json
import logging

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from .deps import get_state

router = APIRouter()
log = logging.getLogger(__name__)


@router.websocket("/ws/stream")
async def stream(ws: WebSocket) -> None:
    await ws.accept()
    state = get_state(ws)  # type: ignore[arg-type]
    queue = state.broadcaster.subscribe()

    async def metric_pump() -> None:
        while True:
            snap = state.metrics.snapshot()
            await ws.send_text(json.dumps({"type": "metrics", "data": snap.model_dump()}))
            await asyncio.sleep(1.0)

    pump = asyncio.create_task(metric_pump())
    try:
        while True:
            message = await queue.get()
            await ws.send_text(json.dumps(message, default=str))
    except WebSocketDisconnect:
        pass
    except Exception:
        log.exception("ws stream failure")
    finally:
        pump.cancel()
        state.broadcaster.unsubscribe(queue)
