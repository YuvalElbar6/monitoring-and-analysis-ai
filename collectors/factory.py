# collectors/factory.py
import platform
from collectors.windows import WindowsCollector
from collectors.linux import LinuxCollector
from collectors.mac import MacCollector


collectors = {
    "windows": WindowsCollector,
    "linux": LinuxCollector,
    "darwin": MacCollector
}

def get_collector():
    os_name = platform.system().lower()

    result = collectors.get(os_name, None)
  
    if not result:
        raise RuntimeError(f"Unsupported OS: {os_name}")
  
    return result()
  