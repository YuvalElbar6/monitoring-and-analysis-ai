from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import DateTime
from sqlalchemy import Integer
from sqlalchemy import JSON
from sqlalchemy import String
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.orm import Mapped
from sqlalchemy.orm import mapped_column


class Base(DeclarativeBase):
    pass


class UnifiedEventTable(Base):
    __tablename__ = 'unified_events'

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime)
    event_type: Mapped[str] = mapped_column(String)

    # SQLAlchemy handles dict -> JSON automatically here
    details: Mapped[dict[str, Any]] = mapped_column(JSON)
    metadata_fields: Mapped[dict[str, Any]] = mapped_column(JSON)
