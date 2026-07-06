from __future__ import annotations

from fastapi import APIRouter, Query
from sqlalchemy import desc, select

from ..db import AlertRow, SessionLocal
from ..models import Alert

router = APIRouter(prefix="/api/alerts", tags=["alerts"])


@router.get("", response_model=list[Alert])
async def list_alerts(limit: int = Query(100, ge=1, le=1000)) -> list[Alert]:
    async with SessionLocal() as session:
        result = await session.execute(select(AlertRow).order_by(desc(AlertRow.ts)).limit(limit))
        rows = result.scalars().all()
        return [
            Alert(
                id=r.id,
                ts=r.ts,
                rule=r.rule,
                severity=r.severity,  # type: ignore[arg-type]
                src_ip=r.src_ip,
                dst_ip=r.dst_ip,
                proto=r.proto,
                detail=r.detail or "",
            )
            for r in rows
        ]
