from typing import List, Dict
from dataclasses import dataclass, field

@dataclass
class SharedState:
    processes: List[Dict] = field(default_factory=list)
    network_flows: List[Dict] = field(default_factory=list)
    services: List[Dict] = field(default_factory=list)
    findings: List[Dict] = field(default_factory=list)

state = SharedState()