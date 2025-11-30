# collectors/windows.py
import psutil
import win32evtlog
from scapy.all import sniff
from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6

from collectors.base import BaseOSCollector
from models.unified import UnifiedEvent
from models.process import ProcessEvent
from models.services import ServiceEvent
from models.network import NetworkEvent


class WindowsCollector(BaseOSCollector):

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
                        type="process",
                        details=ev.model_dump(),
                        metadata={"os": "windows", "collector": "psutil"}
                    )
                )

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

            except Exception as e:
                print(f"[WindowsCollector:process] Unexpected error: {e}")
                continue

        return events

    # ------------------------------
    # SERVICE EVENTS
    # ------------------------------
    def collect_service_events(self, limit=50):
        events = []

        h = win32evtlog.OpenEventLog(None, "System")
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        raw_events = win32evtlog.ReadEventLog(h, flags, 0)

        for e in raw_events[:limit]:
            sev = ServiceEvent.from_windows(e)

            events.append(
                UnifiedEvent(
                    type="service_event",
                    details=sev.model_dump(),
                    metadata={"os": "windows", "collector": "event_log"}
                )
            )

        return events

    # ------------------------------
    # NETWORK EVENTS (limit-based)
    # ------------------------------
    def collect_network_events(self, limit=10):
        events = []
        counter = {"count": 0}

        def _callback(pkt):
            # detect protocol
            layer = None
            if IP in pkt:
                layer = pkt[IP]
            elif IPv6 in pkt:
                layer = pkt[IPv6]

            ev = NetworkEvent.from_scapy(pkt, layer)

            events.append(
                UnifiedEvent(
                    type="network_flow",
                    details=ev.model_dump(),
                    metadata={"os": "windows", "collector": "scapy"}
                )
            )

            counter["count"] += 1

            return None  # <-- never print anything, avoids False spam


        def _stop(pkt):
            return counter["count"] >= limit


        sniff(
            prn=_callback,
            store=False,
            filter="ip or ip6",
            stop_filter=_stop,
        )

        return events

