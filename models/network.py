# models/network.py
from __future__ import annotations

from pydantic import BaseModel
from pydantic import IPvAnyAddress
from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6


class NetworkEvent(BaseModel):
    src: IPvAnyAddress | None = None
    dst: IPvAnyAddress | None = None
    proto: str | None = None
    length: int
    summary: str

    @classmethod
    def from_scapy(cls, pkt, layer):
        return cls(
            src=layer.src if layer else None,
            dst=layer.dst if layer else None,
            proto=layer.name if layer else pkt.name,
            length=len(pkt),
            summary=pkt.summary(),
        )

    @classmethod
    def from_scapy_auto(cls, pkt):
        layer = None
        if IP in pkt:
            layer = pkt[IP]
        elif IPv6 in pkt:
            layer = pkt[IPv6]
        return cls.from_scapy(pkt, layer)
