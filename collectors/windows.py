# collectors/windows.py
from __future__ import annotations

import psutil
from scapy.all import conf
from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6

from collectors.base import BaseOSCollector
from models.network import NetworkEvent
from models.process import ProcessEvent
from models.services import ServiceEvent
from models.unified import UnifiedEvent


class WindowsCollector(BaseOSCollector):
    """
    Collector implementation for Windows systems.

    Mechanisms:
    - Processes: Uses 'psutil' to snapshot active processes.
    - Services: Uses 'win32evtlog' (imported locally) to read the System Event Log.
    - Network: Uses Scapy 'conf.L3socket' (via Npcap) to capture IP traffic.
    """

    def __init__(self):
        super().__init__()
        # Tracks the last Event Log record we processed to prevent duplicates
        self.last_service_record_number = 0

    # ------------------------------
    # PROCESS EVENTS
    # ------------------------------
    def collect_process_events(self):
        """
        Takes a snapshot of all currently running processes.

        Returns:
            list[UnifiedEvent]: A list of process events containing PID, Name, Username, etc.
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
                        # mode='json' converts objects to safe strings for the DB
                        details=ev.model_dump(mode='json'),
                        metadata={'os': 'windows', 'collector': 'psutil'},
                    ),
                )

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
            except Exception:
                continue

        return events

    # ------------------------------
    # SERVICE EVENTS
    # ------------------------------
    def collect_service_events(self, limit=50):
        """
        Reads the Windows 'System' Event Log for service changes.

        Args:
            limit (int): Maximum number of log entries to read.

        Returns:
            list[UnifiedEvent]: A list of recent service start/stop/error events.
        """
        import win32evtlog

        events = []
        try:
            h = win32evtlog.OpenEventLog(None, 'System')
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            raw_events = win32evtlog.ReadEventLog(h, flags, 0)

            for e in raw_events[:limit]:
                # Dedup logic: Skip events we've already processed
                if e.RecordNumber <= self.last_service_record_number:
                    continue

                # Update watermark
                if e.RecordNumber > self.last_service_record_number:
                    self.last_service_record_number = max(self.last_service_record_number, e.RecordNumber)

                sev = ServiceEvent.from_windows(e)
                events.append(
                    UnifiedEvent(
                        type='service_event',
                        details=sev.model_dump(mode='json'),
                        metadata={'os': 'windows', 'collector': 'event_log'},
                    ),
                )

        except Exception as e:
            print(f"[Services] Access Error: {e}")

        return events

    # ------------------------------
    # NETWORK EVENTS
    # ------------------------------
    def collect_network_events(self):
        """
        Streams network packets using Scapy.

        Note:
            This is a Generator. It yields packets indefinitely.
            Requires Npcap installed and Admin privileges.

        Yields:
            UnifiedEvent: Real-time network flow data.
        """
        try:
            s = conf.L3socket(filter='ip or ip6')
        except Exception as e:
            print(f"[Network] Socket Error: {e}")
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
                    # mode='json' handles IPv4/IPv6 object serialization
                    details=ev.model_dump(mode='json'),
                    metadata={'os': 'windows', 'collector': 'scapy_socket'},
                )

            except Exception as e:
                print(f"[Network] Parse Error: {e}")
