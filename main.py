from __future__ import annotations

import threading
import time

from collectors.factory import get_collector
from storage.storage_writer import write_event


def run_process_collector(collector, interval=10):
    while True:
        try:
            events = collector.collect_process_events()
            for ev in events:
                write_event(ev)
        except Exception as e:
            print(f"[ProcessCollector] Error: {e}")

        time.sleep(interval)


def run_service_collector(collector, interval=30):
    while True:
        try:
            events = collector.collect_service_events()
            for ev in events:
                write_event(ev)
        except Exception as e:
            print(f"[ServiceCollector] Error: {e}")

        time.sleep(interval)


def run_network_collector(collector):
    try:
        for event in collector.collect_network_events():
            if event:
                write_event(event)
    except Exception as e:
        print(f"[NetworkCollector] Error: {e}")


def main():
    collector = get_collector()
    print(f"Loaded collector for: {collector.__class__.__name__}")

    # THREAD 1: Process monitoring
    t1 = threading.Thread(
        target=run_process_collector,
        args=(collector,),
        daemon=True,
    )

    # THREAD 2: Service monitoring
    t2 = threading.Thread(
        target=run_service_collector,
        args=(collector,),
        daemon=True,
    )

    # THREAD 3: Network monitoring (blocking, so runs in its own thread)
    t3 = threading.Thread(
        target=run_network_collector,
        args=(collector,),
        daemon=True,
    )

    t1.start()
    t2.start()
    t3.start()

    print('Collectors running... Press Ctrl+C to stop.')

    # Keep main thread alive
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print('Shutting down collectors...')


if __name__ == '__main__':
    main()
