from __future__ import annotations

from sqlalchemy import Column, Float, Integer, String, Text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from .config import settings


class Base(DeclarativeBase):
    pass


class AlertRow(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    ts = Column(Float, nullable=False, index=True)
    rule = Column(String(128), nullable=False)
    severity = Column(String(16), nullable=False)
    src_ip = Column(String(64), nullable=False)
    dst_ip = Column(String(64), nullable=False)
    proto = Column(String(16), nullable=False)
    detail = Column(Text, default="")


engine = create_async_engine(settings.db_url, future=True)
SessionLocal = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


async def init_db() -> None:
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
