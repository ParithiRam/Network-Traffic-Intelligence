from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Response

from ..config import settings
from ..models import Rule
from ..state import AppState
from .deps import get_state

router = APIRouter(prefix="/api/rules", tags=["rules"])


@router.get("", response_model=list[Rule])
def list_rules(state: AppState = Depends(get_state)) -> list[Rule]:
    return state.engine.rules


@router.post("", response_model=Rule, status_code=201)
def upsert_rule(rule: Rule, state: AppState = Depends(get_state)) -> Rule:
    state.engine.add(rule)
    state.engine.save(settings.rules_path)
    return rule


@router.delete("/{name}", status_code=204, response_class=Response)
def delete_rule(name: str, state: AppState = Depends(get_state)) -> Response:
    if not state.engine.remove(name):
        raise HTTPException(status_code=404, detail=f"rule {name!r} not found")
    state.engine.save(settings.rules_path)
    return Response(status_code=204)
