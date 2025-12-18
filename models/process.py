from __future__ import annotations

from datetime import datetime
from datetime import timezone
from typing import Any

import psutil
from pydantic import BaseModel
from pydantic import Field
from pydantic import IPvAnyAddress


class ProcessConnection(BaseModel):
    # IPvAnyAddress validates that the string is actually an IP
    local_address: IPvAnyAddress | None = None
    local_port: int | None = None
    remote_address: IPvAnyAddress | None = None
    remote_port: int | None = None
    status: str | None = None


class ProcessEvent(BaseModel):
    pid: int
    name: str
    username: str | None = None
    cpu_percent: float = 0.0
    memory_percent: float = 0.0
    exe: str | None = None
    cmdline: list[str] = Field(default_factory=list)
    connections: list[ProcessConnection] = Field(default_factory=list)

    # CRITICAL: Required by your collector to sync event times
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @classmethod
    def from_psutil(cls, proc) -> ProcessEvent | None:
        """
        Creates a ProcessEvent from a raw psutil process object.
        Returns None if the process is inaccessible (AccessDenied/Zombie).
        """
        # Helper for clean attribute access
        def safe_get(method_name: str, default: Any = None):
            try:
                return getattr(proc, method_name)()
            except (psutil.AccessDenied, psutil.ZombieProcess):
                return default

        try:
            with proc.oneshot():
                # 1. Fetch Basic Info
                name = safe_get('name', 'unknown')
                username = safe_get('username', 'unknown')
                exe = safe_get('exe', None)
                cmdline = safe_get('cmdline', [])

                # 2. Fetch Metrics (handling specific psutil errors)
                try:
                    cpu = proc.cpu_percent(interval=None)
                    mem = proc.memory_percent()
                except (psutil.AccessDenied, psutil.ZombieProcess):
                    cpu, mem = 0.0, 0.0

                # 3. Fetch & Parse Connections
                # We do this manually to split IP/Port for your new ProcessConnection model
                conn_list = []
                try:
                    for c in proc.net_connections(kind='inet'):
                        l_ip, l_port = (c.laddr.ip, c.laddr.port) if c.laddr else (None, None)
                        r_ip, r_port = (c.raddr.ip, c.raddr.port) if c.raddr else (None, None)

                        conn_list.append(
                            ProcessConnection(
                                local_address=l_ip,
                                local_port=l_port,
                                remote_address=r_ip,
                                remote_port=r_port,
                                status=c.status,
                            ),
                        )
                except (psutil.AccessDenied, psutil.ZombieProcess):
                    pass

                return cls(
                    pid=proc.pid,
                    name=name,
                    username=username,
                    exe=exe,
                    cmdline=cmdline,
                    cpu_percent=cpu,
                    memory_percent=mem,
                    connections=conn_list,
                )

        except Exception:
            # If the process vanishes during reading, strictly return None
            return None
