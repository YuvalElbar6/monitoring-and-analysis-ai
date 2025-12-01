# models/unified.py
from __future__ import annotations

from datetime import datetime
from typing import Any
from typing import Literal

from pydantic import BaseModel
from pydantic import Field

EventType = Literal['network_flow', 'process', 'service_event']


class UnifiedEvent(BaseModel):
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    type: EventType
    details: dict[str, Any]
    metadata: dict[str, Any] = Field(default_factory=dict)
