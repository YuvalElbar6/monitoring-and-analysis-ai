from __future__ import annotations

from dataclasses import dataclass
from dataclasses import field


@dataclass
class SharedState:
    processes: list[dict] = field(default_factory=list)
    network_flows: list[dict] = field(default_factory=list)
    services: list[dict] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)


state = SharedState()
