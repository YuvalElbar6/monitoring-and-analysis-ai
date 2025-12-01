# collectors/base.py
from abc import ABC, abstractmethod
from models.unified import UnifiedEvent

class BaseOSCollector(ABC):

    @abstractmethod
    def collect_process_events(self) -> list[UnifiedEvent]:
        pass

    @abstractmethod
    def collect_service_events(self) -> list[UnifiedEvent]:
        pass

    @abstractmethod
    def collect_network_events(self):
        """
        Network events are streaming (sniff), so this may be a generator.
        """
        pass