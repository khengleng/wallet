import uuid
from datetime import datetime
from decimal import Decimal

from sqlalchemy import DateTime, Integer, Numeric, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import func

from .db import Base


class ProcessedEvent(Base):
    __tablename__ = "processed_events"
    __table_args__ = (UniqueConstraint("event_id", name="uq_processed_event_id"),)

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    event_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    routing_key: Mapped[str] = mapped_column(String(128), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    reference_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    payload: Mapped[dict] = mapped_column(JSONB, default=dict)
    processed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False, index=True
    )


class RiskAlert(Base):
    __tablename__ = "risk_alerts"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    event_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    alert_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    amount: Mapped[Decimal | None] = mapped_column(Numeric(20, 8), nullable=True)
    details_json: Mapped[dict] = mapped_column(JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False, index=True
    )


class DeadLetterEvent(Base):
    __tablename__ = "dead_letter_events"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    event_id: Mapped[str] = mapped_column(String(64), default="", index=True)
    event_type: Mapped[str] = mapped_column(String(64), default="", index=True)
    routing_key: Mapped[str] = mapped_column(String(128), nullable=False)
    payload: Mapped[dict] = mapped_column(JSONB, default=dict)
    headers: Mapped[dict] = mapped_column(JSONB, default=dict)
    error: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(16), default="pending", index=True)
    replay_count: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False, index=True
    )
    last_replayed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
