"""Motor de base de datos asíncrono y sesión (SQLAlchemy 2.0).

Los modelos concretos (activos, escaneos, hallazgos) se definen en el Paso 3.
Aquí queda listo el engine, la Base declarativa y el proveedor de sesión.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from atalaya.config import settings

engine = create_async_engine(settings.database_url, echo=False, future=True)
SessionLocal = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)


class Base(DeclarativeBase):
    """Base declarativa común a todos los modelos ORM."""


async def get_session() -> AsyncGenerator[AsyncSession, None]:
    """Dependencia FastAPI: entrega una sesión de BD por petición."""
    async with SessionLocal() as session:
        yield session
