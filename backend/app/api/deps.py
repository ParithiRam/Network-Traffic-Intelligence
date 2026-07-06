from __future__ import annotations

from fastapi import Request

from ..state import AppState


def get_state(request: Request) -> AppState:
    return request.app.state.nti  # type: ignore[attr-defined,no-any-return]
