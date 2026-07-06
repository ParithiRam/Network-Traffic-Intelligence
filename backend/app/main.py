from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .api import alerts as alerts_router
from .api import export as export_router
from .api import health as health_router
from .api import metrics as metrics_router
from .api import rules as rules_router
from .api import ws as ws_router
from .config import settings
from .db import init_db
from .ingest.pcap import pcap_stream
from .ingest.simulator import synthetic_stream
from .state import AppState, build_state

log = logging.getLogger("nti")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")


async def _ingest_loop(state: AppState) -> None:
    """Pulls events from the configured source into the worker's queue."""
    try:
        if settings.pcap_path:
            log.info("ingesting from PCAP %s", settings.pcap_path)
            source = pcap_stream(settings.pcap_path, replay_realtime=False)
        else:
            log.info("ingesting from simulator at %d pps", settings.sim_pps)
            source = synthetic_stream(pps=settings.sim_pps)
        async for event in source:
            try:
                state.queue.put_nowait(event)
            except asyncio.QueueFull:
                # Backpressure: drop oldest, push newest. Keeps the dashboard live
                # under load instead of stalling ingestion entirely.
                try:
                    _ = state.queue.get_nowait()
                except asyncio.QueueEmpty:
                    pass
                try:
                    state.queue.put_nowait(event)
                except asyncio.QueueFull:
                    pass
    except asyncio.CancelledError:
        raise
    except Exception:
        log.exception("ingest loop crashed")


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    state = build_state()
    app.state.nti = state
    state.worker.start()
    state.ingest_task = asyncio.create_task(_ingest_loop(state), name="nti-ingest")
    log.info("NTI started")
    try:
        yield
    finally:
        if state.ingest_task:
            state.ingest_task.cancel()
            try:
                await state.ingest_task
            except (asyncio.CancelledError, Exception):
                pass
        await state.worker.stop()
        log.info("NTI stopped")


app = FastAPI(title="Network Traffic Intelligence", version="0.1.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.cors_origin] if settings.cors_origin != "*" else ["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health_router.router)
app.include_router(metrics_router.router)
app.include_router(rules_router.router)
app.include_router(alerts_router.router)
app.include_router(export_router.router)
app.include_router(ws_router.router)
