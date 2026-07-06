from __future__ import annotations

from fastapi import APIRouter, Depends

from ..models import MetricsSnapshot
from ..state import AppState
from .deps import get_state

router = APIRouter(prefix="/api/metrics", tags=["metrics"])


@router.get("", response_model=MetricsSnapshot)
def get_metrics(state: AppState = Depends(get_state)) -> MetricsSnapshot:
    return state.metrics.snapshot()
