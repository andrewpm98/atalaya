"""Fixtures compartidas de la suite.

La sesión de base de datos usa SQLite en memoria (`StaticPool` para que
todas las conexiones del test vean el mismo esquema), nunca el
`DATABASE_URL` de `.env`: las pruebas deben poder ejecutarse sin Postgres
levantado y sin tocar datos reales.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator

import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from atalaya.core import models  # noqa: F401 - registra las tablas en Base.metadata
from atalaya.core.database import Base


@pytest_asyncio.fixture
async def db_session() -> AsyncGenerator[AsyncSession, None]:
    """Sesión async contra un esquema SQLite en memoria, limpio por test."""
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    async with session_factory() as session:
        yield session

    await engine.dispose()
