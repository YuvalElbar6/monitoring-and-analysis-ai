from __future__ import annotations

import shutil
import subprocess
from datetime import datetime
from datetime import timezone

import psutil
from pydantic import BaseModel
from pydantic import Field


class HardwareMetrics(BaseModel):
    """Specific utilization metrics for a hardware component."""
    cpu_percent: float = 0.0
    memory_percent: float = 0.0
    gpu_memory_mb: int | None = None
    gpu_load_percent: float | None = None


class HardwareEvent(BaseModel):
    """
    Model for tracking hardware resource spikes and attribution.
    """
    # Type of anomaly (e.g., "RESOURCE_HOG", "GPU_SPIKE")
    sub_type: str

    # Process attribution (The "Who" and "Where")
    pid: int | None = None
    name: str | None = 'system'
    username: str | None = None
    exe: str | None = None

    # The actual numbers
    metrics: HardwareMetrics

    # Metadata for the SOC
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: dict[str, str] = Field(default_factory=dict)

    @classmethod
    def get_gpu_usage(cls, target_pid: int) -> dict[str, int | float]:
        """
        Helper: Tries to find GPU usage for a specific PID using nvidia-smi.
        """
        if shutil.which('nvidia-smi'):
            try:
                # Query PID and memory usage
                cmd = ['nvidia-smi', '--query-compute-apps=pid,used_memory', '--format=csv,noheader,nounits']
                output = subprocess.check_output(cmd, encoding='utf-8', timeout=1)
                for line in output.strip().split('\n'):
                    if not line.strip():
                        continue
                    pid_str, mem_str = line.split(',')
                    if int(pid_str.strip()) == target_pid:
                        return {'gpu_memory_mb': int(mem_str.strip())}
            except Exception:
                pass
        return {}

    @classmethod
    def detect_spikes(cls, cpu_threshold: float = 40.0, mem_threshold: float = 40.0) -> list[HardwareEvent]:
        """
        Scans all processes and returns HardwareEvents for those exceeding thresholds.
        This is the "Hardware" equivalent of your from_psutil method.
        """
        events = []

        for proc in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_percent', 'exe']):
            try:
                # Get metrics
                cpu = proc.info['cpu_percent'] or 0.0
                mem = proc.info['memory_percent'] or 0.0

                if cpu > cpu_threshold or mem > mem_threshold:
                    # Check for GPU usage if it's a heavy process
                    gpu_data = cls.get_gpu_usage(proc.info['pid'])

                    metrics = HardwareMetrics(
                        cpu_percent=cpu,
                        memory_percent=mem,
                        **gpu_data,
                    )

                    events.append(
                        cls(
                            sub_type='RESOURCE_HOG',
                            pid=proc.info['pid'],
                            name=proc.info['name'],
                            username=proc.info['username'],
                            exe=proc.info['exe'],
                            metrics=metrics,
                            metadata={'collector': 'psutil_hardware'},
                        ),
                    )
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        return events
