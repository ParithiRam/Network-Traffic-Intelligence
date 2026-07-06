from __future__ import annotations

from fastapi import APIRouter, Depends

from ..state import AppState
from .deps import get_state

router = APIRouter(tags=["health"])


@router.get("/api/health")
def health(state: AppState = Depends(get_state)) -> dict:
    return {
        "status": "ok",
        "queue_size": state.queue.qsize(),
        "queue_max": state.queue.maxsize,
        "rules": len(state.engine.rules),
        "total_packets": state.metrics.total_packets,
    }
