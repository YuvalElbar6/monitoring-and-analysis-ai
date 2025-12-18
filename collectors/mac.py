# collectors/mac.py
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

    def collect_hardware_events(self, cpu_threshold: float = 40.0, mem_threshold: float = 40.0) -> list[UnifiedEvent]:
        """
        Scans for hardware resource anomalies on macOS using HardwareEvent model.
        Also enriches with GPU hardware status via system_profiler.
        """
        unified_events = []

        # 1. Use Pydantic Model to detect CPU/RAM spikes
        # This will also try get_gpu_usage (nvidia-smi), which will be skipped on M-series Macs
        spikes = HardwareEvent.detect_spikes(
            cpu_threshold=cpu_threshold,
            mem_threshold=mem_threshold,
        )

        for spike in spikes:
            unified_events.append(
                UnifiedEvent(
                    type='hardware_spike',
                    details=spike.model_dump(mode='json'),
                    metadata={'os': 'macos', 'collector': 'hardware_pydantic'},
                ),
            )

        # 2. Enrich with macOS GPU Static Info (Hardware Health)
        try:
            res = subprocess.check_output(['system_profiler', 'SPDisplaysDataType', '-json'], encoding='utf-8')
            data = json.loads(res)

            if 'SPDisplaysDataType' in data:
                for gpu in data['SPDisplaysDataType']:
                    unified_events.append(
                        UnifiedEvent(
                            type='hardware_info',
                            details={
                                'sub_type': 'GPU_STATUS',
                                'gpu_name': gpu.get('_name', 'Unknown GPU'),
                                'vram': gpu.get('spdisplays_vram', 'Unified'),
                                'vendor': gpu.get('spdisplays_vendor', 'Apple'),
                            },
                            metadata={'os': 'macos', 'collector': 'system_profiler'},
                        ),
                    )
        except Exception as e:
            # Silent fail for enrichment
            print(f"The exception was: {e}")
            pass

        return unified_events

    def collect_malware_events(self) -> list[UnifiedEvent]:
        """
        Scans macOS processes for behavioral threats.
        """
        unified_events = []

        detected_threats = MalwareEvent.scan_system_for_threats()

        for threat in detected_threats:
            unified_events.append(
                UnifiedEvent(
                    type='malware_alert',
                    details=threat.model_dump(mode='json'),
                    metadata={
                        'os': 'macos',
                        'collector': 'behavioral_scanner',
                        'arch': 'arm64',  # Or use platform.machine() to detect M1 vs Intel
                    },
                ),
            )

        return unified_events
