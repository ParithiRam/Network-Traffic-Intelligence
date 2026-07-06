"""SIEM-friendly export endpoints.

CEF (ArcSight Common Event Format) is the lingua franca of most SIEM tools;
JSON Lines is what Splunk/ELK actually want to ingest. We expose both.
"""
from __future__ import annotations

import json
from typing import AsyncIterator

from fastapi import APIRouter, Query
from fastapi.responses import StreamingResponse
from sqlalchemy import desc, select

from ..db import AlertRow, SessionLocal

router = APIRouter(prefix="/api/export", tags=["export"])

_SEVERITY_TO_CEF = {"low": 3, "medium": 6, "high": 9}


def _alert_to_cef(row: AlertRow) -> str:
    sev = _SEVERITY_TO_CEF.get(str(row.severity), 5)
    name = str(row.rule).replace("|", "\\|")
    detail = (row.detail or "").replace("\n", " ").replace("=", "\\=")
    return (
        f"CEF:0|NTI|gigamon-traffic-intel|0.1|{name}|{name}|{sev}|"
        f"src={row.src_ip} dst={row.dst_ip} proto={row.proto} "
        f"rt={int(row.ts * 1000)} msg={detail}"
    )


@router.get("/cef")
async def export_cef(limit: int = Query(1000, ge=1, le=100000)) -> StreamingResponse:
    async def iterator() -> AsyncIterator[bytes]:
        async with SessionLocal() as session:
            result = await session.execute(
                select(AlertRow).order_by(desc(AlertRow.ts)).limit(limit)
            )
            for row in result.scalars():
                yield (_alert_to_cef(row) + "\n").encode()

    return StreamingResponse(iterator(), media_type="text/plain")


@router.get("/jsonl")
async def export_jsonl(limit: int = Query(1000, ge=1, le=100000)) -> StreamingResponse:
    async def iterator() -> AsyncIterator[bytes]:
        async with SessionLocal() as session:
            result = await session.execute(
                select(AlertRow).order_by(desc(AlertRow.ts)).limit(limit)
            )
            for row in result.scalars():
                payload = {
                    "ts": row.ts,
                    "rule": row.rule,
                    "severity": row.severity,
                    "src_ip": row.src_ip,
                    "dst_ip": row.dst_ip,
                    "proto": row.proto,
                    "detail": row.detail,
                }
                yield (json.dumps(payload) + "\n").encode()

    return StreamingResponse(iterator(), media_type="application/x-ndjson")
