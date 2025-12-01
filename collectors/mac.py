# collectors/mac.py
from __future__ import annotations

import subprocess

import psutil
from scapy.all import sniff
from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6

from collectors.base import BaseOSCollector
from models.network import NetworkEvent
from models.process import ProcessEvent
from models.services import ServiceEvent
from models.unified import UnifiedEvent


class MacCollector(BaseOSCollector):

    # ------------------------------
    # PROCESS EVENTS
    # ------------------------------
    def collect_process_events(self):
        events = []

        for proc in psutil.process_iter():
            try:
                ev = ProcessEvent.from_psutil(proc)
                if ev is None:
                    continue

                events.append(
                    UnifiedEvent(
                        type='process',
                        details=ev.model_dump(),
                        metadata={'os': 'mac', 'collector': 'psutil'},
                    ),
                )

            except Exception:
                continue

        return events

    # ------------------------------
    # SERVICE EVENTS (launchctl)
    # ------------------------------
    def collect_service_events(self):
        events = []

        try:
            raw = subprocess.getoutput('launchctl list')
            lines = raw.splitlines()[1:]  # skip header
        except Exception as e:
            print(f"[MacCollector:service] launchctl error: {e}")
            return []

        for line in lines:
            parts = line.split()
            if len(parts) < 3:
                continue

            pid, status, label = parts[0], parts[1], parts[2]

            sev = ServiceEvent.from_mac(pid, status, label)

            events.append(
                UnifiedEvent(
                    type='service_event',
                    details=sev.model_dump(),
                    metadata={'os': 'mac', 'collector': 'launchctl'},
                ),
            )

        return events

    # ------------------------------
    # NETWORK EVENTS (limit-based)
    # ------------------------------
    def collect_network_events(self, limit=10):
        events = []
        counter = {'count': 0}

        def _callback(pkt):
            # find protocol layer
            layer = None
            if IP in pkt:
                layer = pkt[IP]
            elif IPv6 in pkt:
                layer = pkt[IPv6]

            ev = NetworkEvent.from_scapy(pkt, layer)

            events.append(
                UnifiedEvent(
                    type='network_flow',
                    details=ev.model_dump(),
                    metadata={'os': 'mac', 'collector': 'scapy'},
                ),
            )

            counter['count'] += 1

            # IMPORTANT: return None so Scapy doesn't print anything
            return None

        def _stop(pkt):
            return counter['count'] >= limit

        sniff(
            prn=_callback,
            store=False,
            filter='ip or ip6',
            stop_filter=_stop,
        )

        return events
