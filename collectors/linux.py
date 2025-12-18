# collectors/linux.py
from __future__ import annotations

import json
import subprocess

import psutil
from scapy.all import conf
from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6

from collectors.base import BaseOSCollector
from models.hardware import HardwareEvent
from models.malware import MalwareEvent
from models.network import NetworkEvent
from models.process import ProcessEvent
from models.services import ServiceEvent
from models.unified import UnifiedEvent
# FIX: Use 'conf' to get the correct socket, avoiding import errors


class LinuxCollector(BaseOSCollector):
    """
    Collector implementation for Linux systems.

    Mechanisms:
    - Processes: Uses 'psutil' library (reading /proc filesystem).
    - Services: Parses output of 'systemctl' command in JSON format.
    - Network: Uses Scapy with raw sockets (requires Root/Sudo).
    """

    # ------------------------------
    # PROCESS EVENTS
    # ------------------------------
    def collect_process_events(self):
        """
        Takes a snapshot of all currently running processes.

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
                        metadata={'os': 'linux', 'collector': 'psutil'},
                    ),
                )

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
            except Exception:
                continue

        return events

    # ------------------------------
    # SERVICE EVENTS (systemd)
    # ------------------------------
    def collect_service_events(self, limit=50):
        """
        Collects current status of Systemd units (services).

        Implementation:
        Runs `systemctl list-units --output=json` to get structured data directly
        from the OS service manager.

        Args:
            limit (int): Ignored on Linux (snapshot only), kept for compatibility.

        Returns:
            list[UnifiedEvent]: List of active system services.
        """
        events = []

        try:
            # Gets all services in JSON format
            data = subprocess.getoutput(
                'systemctl list-units --type=service --all --no-pager --output=json',
            )
            try:
                entries = json.loads(data)
            except json.JSONDecodeError:
                return []

        except Exception as e:
            print(f"[LinuxCollector] Systemd error: {e}")
            return []

        for entry in entries:
            sev = ServiceEvent.from_linux(entry)
            events.append(
                UnifiedEvent(
                    type='service_event',
                    details=sev.model_dump(mode='json'),
                    metadata={'os': 'linux', 'collector': 'systemd'},
                ),
            )

        return events

    # ------------------------------
    # NETWORK EVENTS
    # ------------------------------
    def collect_network_events(self):
        """
        Streams network packets in real-time.

        Note:
            This function yields data indefinitely.
            Requires ROOT privileges (sudo) to access the raw network socket.

        Yields:
            UnifiedEvent: A single captured network packet info (Source, Dest, Protocol).
        """
        try:
            # conf.L3socket automatically picks the raw socket for Linux
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
                    metadata={'os': 'linux', 'collector': 'scapy_socket'},
                )

            except Exception as e:
                print(f"[Network] Parse Error: {e}")

    def collect_hardware_events(self, cpu_threshold: float = 40.0, mem_threshold: float = 40.0) -> list[UnifiedEvent]:
        """
        Scans for hardware resource anomalies on Linux.

        Args:
            cpu_threshold (float): CPU percentage triggering an event.
            mem_threshold (float): Memory percentage triggering an event.

        Returns:
            list[UnifiedEvent]: A list of detected resource spikes.
        """
        unified_events = []

        # 1. Use the model's logic to detect spikes
        # This handles the psutil iteration and GPU cross-referencing
        spikes = HardwareEvent.detect_spikes(
            cpu_threshold=cpu_threshold,
            mem_threshold=mem_threshold,
        )

        # 2. Wrap each HardwareEvent into a UnifiedEvent for the SOC
        for spike in spikes:
            unified_events.append(
                UnifiedEvent(
                    type='hardware_spike',
                    # mode='json' converts datetime objects and sub-models to plain dicts
                    details=spike.model_dump(mode='json'),
                    metadata={'os': 'linux', 'collector': 'hardware_pydantic'},
                ),
            )

        return unified_events

    def collect_malware_events(self) -> list[UnifiedEvent]:
        """
        Scans Linux processes for behavioral threats.
        """
        unified_events = []

        detected_threats = MalwareEvent.scan_system_for_threats()

        for threat in detected_threats:
            unified_events.append(
                UnifiedEvent(
                    type='malware_alert',
                    details=threat.model_dump(mode='json'),
                    metadata={
                        'os': 'linux',
                        'collector': 'behavioral_scanner',
                        'kernel': 'generic_linux',  # You could add `os.uname().release` here if you wanted
                    },
                ),
            )

        return unified_events
