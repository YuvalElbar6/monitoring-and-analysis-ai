# collectors/linux.py
from __future__ import annotations

import json
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


class LinuxCollector(BaseOSCollector):

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
                        metadata={'os': 'linux', 'collector': 'psutil'},
                    ),
                )

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

            except Exception as e:
                print(f"[LinuxCollector:process] Unexpected error: {e}")
                continue

        return events

    # ------------------------------
    # SERVICE EVENTS (systemd)
    # ------------------------------
    def collect_service_events(self):
        events = []

        try:
            data = subprocess.getoutput(
                'systemctl list-units --type=service --all --no-pager --output=json',
            )
            entries = json.loads(data)

        except Exception as e:
            print(f"[LinuxCollector:service] systemctl read failed: {e}")
            return []

        for entry in entries:
            sev = ServiceEvent.from_linux(entry)

            events.append(
                UnifiedEvent(
                    type='service_event',
                    details=sev.model_dump(),
                    metadata={'os': 'linux', 'collector': 'systemd'},
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
            # detect IP layer
            layer = None
            if IP in pkt:
                layer = pkt[IP]
            elif IPv6 in pkt:
                layer = pkt[IPv6]

            # build event
            ev = NetworkEvent.from_scapy(pkt, layer)

            events.append(
                UnifiedEvent(
                    type='network_flow',
                    details=ev.model_dump(),
                    metadata={'os': 'linux', 'collector': 'scapy'},
                ),
            )

            counter['count'] += 1

            # IMPORTANT FIX: NEVER return False (Scapy prints it)
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
