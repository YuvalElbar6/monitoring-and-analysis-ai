# models/services.py
from pydantic import BaseModel
from typing import Optional
from datetime import datetime


class ServiceEvent(BaseModel):
    service_name: str
    status: Optional[str] = None
    pid: Optional[int] = None
    description: Optional[str] = None
    event_id: Optional[int] = None
    category: Optional[int] = None
    message: Optional[str] = None
    time_generated: Optional[datetime] = None
    computer_name: Optional[str] = None

    # WINDOWS
    @classmethod
    def from_windows(cls, e):
        raw_inserts = getattr(e, "StringInserts", None)

        if raw_inserts is None:
            message = ""
        elif isinstance(raw_inserts, (list, tuple)):
            message = " ".join(str(x) for x in raw_inserts)
        else:
            message = str(raw_inserts)

        return cls(
            service_name=e.SourceName,
            event_id=e.EventID,
            category=e.EventCategory,
            time_generated=e.TimeGenerated,
            computer_name=e.ComputerName,
            message=message,
        )
    # LINUX
    @classmethod
    def from_linux(cls, entry: dict):
        return cls(
            service_name=entry.get("unit") or entry.get("name"),
            description=entry.get("description"),
            status=entry.get("active_state"),
        )

    # MAC
    @classmethod
    def from_mac(cls, pid: str, status: str, label: str):
        return cls(
            service_name=label,
            pid=None if pid == "-" else int(pid),
            status=status,
        )
