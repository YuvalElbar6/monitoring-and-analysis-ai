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
    def from_psutil(cls, proc) -> ProcessEvent | None:
        try:
            # Use strict contexts to avoid overhead
            with proc.oneshot():
                pinfo = proc.as_dict(
                    attrs=[
                        'pid', 'name', 'username', 'cpu_percent',
                        'memory_percent', 'exe', 'cmdline',
                    ],
                )

                # FIX: Use net_connections() instead of connections()
                # kind='inet' filters for IPv4/IPv6 connections only
                try:
                    conns = proc.net_connections(kind='inet')
                    conn_list = []
                    for c in conns:
                        conn_list.append({
                            'fd': c.fd,
                            'family': str(c.family),
                            'type': str(c.type),
                            'local_address': f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else None,
                            'remote_address': f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else None,
                            'status': c.status,
                        })
                except (PermissionError, psutil.AccessDenied):
                    conn_list = []

                return cls(
                    pid=pinfo['pid'],
                    name=pinfo['name'] or 'unknown',
                    username=pinfo['username'] or 'unknown',
                    cpu_percent=pinfo['cpu_percent'] or 0.0,
                    memory_percent=pinfo['memory_percent'] or 0.0,
                    exe=pinfo['exe'],
                    cmdline=pinfo['cmdline'] or [],
                    connections=conn_list,
                )
        except Exception:
            # Process might have died while reading
            return None
