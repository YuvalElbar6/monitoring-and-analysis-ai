# models/unified.py
from pydantic import BaseModel, Field
from datetime import datetime
from typing import Literal, Dict, Any

EventType = Literal["network_flow", "process", "service_event"]

class UnifiedEvent(BaseModel):
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    type: EventType
    details: Dict[str, Any]
    metadata: Dict[str, Any] = Field(default_factory=dict)
