# models/unified.py
from __future__ import annotations

from datetime import datetime
from datetime import timezone
from typing import Any
from typing import Literal

from pydantic import BaseModel
from pydantic import Field


EventType = Literal['network_flow', 'process', 'service_event', 'hardware_spike', 'malware_alert']


class UnifiedEvent(BaseModel):
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    type: EventType
    details: dict[str, Any]
    metadata: dict[str, Any] = Field(default_factory=dict)
