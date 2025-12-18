# collectors/factory.py
from __future__ import annotations

import platform

from collectors.linux import LinuxCollector
from collectors.mac import MacCollector
from collectors.windows import WindowsCollector


collectors = {
    'windows': WindowsCollector,
    'linux': LinuxCollector,
    'darwin': MacCollector,
}


def get_collector():
    """
    Factory function that detects the host operating system and returns
    the appropriate Security Collector instance.

    This ensures that the 'PCSystemMonitor' can run on Windows, Linux, or macOS
    without changing a single line of code in 'server.py'.

    Returns:
        BaseOSCollector: An initialized collector with Hardware, Network,
                         and Malware monitoring capabilities.

    Raises:
        RuntimeError: If the operating system is not supported (e.g., Solaris, FreeBSD).
    """
    os_name = platform.system().lower()

    result = collectors.get(os_name, None)

    if not result:
        raise RuntimeError(f"Unsupported OS: {os_name}")

    return result()
