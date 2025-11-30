# models/process.py
from pydantic import BaseModel, IPvAnyAddress
from typing import Optional, List
import psutil

class ProcessConnection(BaseModel):
    local_address: Optional[IPvAnyAddress] = None
    local_port: Optional[int] = None
    remote_address: Optional[IPvAnyAddress] = None
    remote_port: Optional[int] = None
    status: Optional[str] = None


class ProcessEvent(BaseModel):
    pid: int
    name: str
    cpu_percent: float
    memory_percent: float
    exe: Optional[str] = None
    cmdline: List[str] = []
    username: Optional[str] = None
    connections: List[ProcessConnection] = []

    @classmethod
    def from_psutil(cls, proc: psutil.Process):
        try:
            conns = []
            for c in proc.connections(kind="inet"):
                conns.append(ProcessConnection(
                    local_address=c.laddr.ip if c.laddr else None,
                    local_port=c.laddr.port if c.laddr else None,
                    remote_address=c.raddr.ip if c.raddr else None,
                    remote_port=c.raddr.port if c.raddr else None,
                    status=c.status
                ))

            return cls(
                pid=proc.pid,
                name=proc.name(),
                cpu_percent=proc.cpu_percent(interval=None),
                memory_percent=proc.memory_percent(),
                exe=proc.exe() if hasattr(proc, "exe") else None,
                cmdline=proc.cmdline(),
                username=proc.username(),
                connections=conns,
            )

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return None
