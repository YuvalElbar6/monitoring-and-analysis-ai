# models/process.py
from __future__ import annotations

import psutil
from pydantic import BaseModel
from pydantic import IPvAnyAddress


class ProcessConnection(BaseModel):
    local_address: IPvAnyAddress | None = None
    local_port: int | None = None
    remote_address: IPvAnyAddress | None = None
    remote_port: int | None = None
    status: str | None = None


class ProcessEvent(BaseModel):
    pid: int
    name: str
    cpu_percent: float
    memory_percent: float
    exe: str | None = None
    cmdline: list[str] = []
    username: str | None = None
    connections: list[ProcessConnection] = []

    @classmethod
    def from_psutil(cls, proc: psutil.Process):
        try:
            conns = []
            for c in proc.connections(kind='inet'):
                conns.append(
                    ProcessConnection(
                        local_address=c.laddr.ip if c.laddr else None,
                        local_port=c.laddr.port if c.laddr else None,
                        remote_address=c.raddr.ip if c.raddr else None,
                        remote_port=c.raddr.port if c.raddr else None,
                        status=c.status,
                    ),
                )

            return cls(
                pid=proc.pid,
                name=proc.name(),
                cpu_percent=proc.cpu_percent(interval=None),
                memory_percent=proc.memory_percent(),
                exe=proc.exe() if hasattr(proc, 'exe') else None,
                cmdline=proc.cmdline(),
                username=proc.username(),
                connections=conns,
            )

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return None
