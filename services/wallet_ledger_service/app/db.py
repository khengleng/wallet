from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from .config import settings


class Base(DeclarativeBase):
    pass


def _normalize_database_url(url: str) -> str:
    if url.startswith("postgres://"):
        return url.replace("postgres://", "postgresql+psycopg://", 1)
    if url.startswith("postgresql://") and "+psycopg" not in url.split("://", 1)[0]:
        return url.replace("postgresql://", "postgresql+psycopg://", 1)
    return url


engine = create_engine(
    _normalize_database_url(settings.database_url),
    future=True,
    pool_pre_ping=True,
    pool_size=20,
    max_overflow=40,
)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)
