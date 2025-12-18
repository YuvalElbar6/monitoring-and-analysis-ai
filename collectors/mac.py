# collectors/mac.py
from __future__ import annotations

import subprocess

import psutil
from scapy.all import conf
from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6

from collectors.base import BaseOSCollector
from models.network import NetworkEvent
from models.process import ProcessEvent
from models.services import ServiceEvent
from models.unified import UnifiedEvent


class MacCollector(BaseOSCollector):
    """
    Collector implementation for MacOS (Darwin).

    Mechanisms:
    - Processes: Uses 'psutil' library.
    - Services: Parses output of 'launchctl list' (Legacy/System Daemons).
    - Network: Uses Scapy with BPF (Berkeley Packet Filter) sockets.
    """

    # ------------------------------
    # PROCESS EVENTS
    # ------------------------------
    def collect_process_events(self):
        """
        Takes a snapshot of all currently running processes on MacOS.

        Returns:
            list[UnifiedEvent]: A list of process events containing PID, Name, CPU, and RAM usage.
        """
        events = []
        for proc in psutil.process_iter(['pid', 'name', 'username']):
            try:
                ev = ProcessEvent.from_psutil(proc)
                if ev is None:
                    continue

                events.append(
                    UnifiedEvent(
                        type='process',
                        details=ev.model_dump(mode='json'),
                        metadata={'os': 'macos', 'collector': 'psutil'},
                    ),
                )
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
            except Exception:
                continue

        return events

    # ------------------------------
    # SERVICE EVENTS (launchd)
    # ------------------------------
    def collect_service_events(self, limit=50):
        """
        Collects current status of LaunchAgents and LaunchDaemons.

        Implementation:
        Parses `launchctl list`. MacOS does not provide JSON output for this,
        so we manually parse the tab-separated columns (PID, Status, Label).

        Args:
            limit (int): Max number of services to process (default 50).

        Returns:
            list[UnifiedEvent]: List of active launchd services.
        """
        events = []
        try:
            # 'launchctl list' output format: PID | Status | Label
            output = subprocess.getoutput('launchctl list')
            lines = output.splitlines()[1:]  # Skip header

            for line in lines[:limit]:
                parts = line.split('\t')
                if len(parts) < 3:
                    continue

                pid_str, status, label = parts[0], parts[1], parts[2]

                sev = ServiceEvent.from_mac(pid_str, status, label)

                events.append(
                    UnifiedEvent(
                        type='service_event',
                        details=sev.model_dump(mode='json'),
                        metadata={'os': 'macos', 'collector': 'launchctl'},
                    ),
                )

        except Exception as e:
            print(f"[MacCollector] launchctl error: {e}")
            return []

        return events

    # ------------------------------
    # NETWORK EVENTS
    # ------------------------------
    def collect_network_events(self):
        """
        Streams network packets in real-time.

        Note:
            Requires ROOT privileges (sudo) to access the network interface via BPF.

        Yields:
            UnifiedEvent: A single captured network packet info.
        """
        try:
            # MacOS uses BPF (Berkeley Packet Filter) under the hood
            s = conf.L3socket(filter='ip or ip6')
        except Exception as e:
            print(f"[Network] Socket Error (Root required?): {e}")
            return

        while True:
            try:
                pkt = s.recv()
                if not pkt:
                    continue

                layer = None
                if IP in pkt:
                    layer = pkt[IP]
                elif IPv6 in pkt:
                    layer = pkt[IPv6]

                ev = NetworkEvent.from_scapy(pkt, layer)

                yield UnifiedEvent(
                    type='network_flow',
                    details=ev.model_dump(mode='json'),
                    metadata={'os': 'macos', 'collector': 'scapy_socket'},
                )

            except Exception as e:
                print(f"[Network] Parse Error: {e}")
