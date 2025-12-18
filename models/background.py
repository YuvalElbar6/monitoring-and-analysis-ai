# models/background.py
from __future__ import annotations

import asyncio
import time
import traceback

from collectors.factory import get_collector
from storage.storage_writer import write_event
# 1. Import the Writer function we created earlier
# 2. Import your Collector Factory

# Initialize collector once
collector = get_collector()


async def safe_to_thread(func, *args, **kwargs):
    """
    Helper to run blocking collector functions in a separate thread
    so they don't freeze the Async Server.
    """
    return await asyncio.to_thread(func, *args, **kwargs)


# -----------------------------------------------------
# 1. PROCESS MONITOR LOOP
# -----------------------------------------------------
async def process_monitor_loop():
    print('[Background] Process monitor started.')
    while True:
        try:
            # Run the blocking collection in a thread
            events = await safe_to_thread(collector.collect_process_events)

            # Write events to DB
            if events:
                for ev in events:
                    # Uses the non-blocking queue writer
                    write_event(ev)

        except Exception:
            print('[Background] Process monitor failed:')
            traceback.print_exc()

        except asyncio.CancelledError:
            # SILENT EXIT: Server is shutting down
            print('[Background] Process monitor stopping...')
            return
        # Snapshot every 10 seconds
        await asyncio.sleep(10)


# -----------------------------------------------------
# 2. SERVICE MONITOR LOOP
# -----------------------------------------------------
async def service_monitor_loop():
    print('[Background] Service monitor started.')
    while True:
        try:
            # Fetch services (limit 50 to avoid spam)
            events = await safe_to_thread(collector.collect_service_events, limit=50)

            if events:
                for ev in events:
                    write_event(ev)

        except Exception:
            print('[Background] Service monitor failed:')
            traceback.print_exc()

        except asyncio.CancelledError:
            print('[Background] Service monitor stopping...')
            return

        # Check services every 30 seconds
        await asyncio.sleep(30)


# -----------------------------------------------------
# 3. NETWORK MONITOR LOOP (Streaming)
# -----------------------------------------------------
async def network_monitor_loop():
    print('[Background] Network monitor started.')

    # Network sniffing is a continuous blocking stream,
    # so we wrap the WHOLE thing in a thread.
    def _blocking_sniffer():
        # This loop runs inside a thread, so it can block safely
        while True:
            try:
                # Assuming collect_network_events is a generator (yields packets)
                for event in collector.collect_network_events():
                    if event:
                        write_event(event)
            except Exception as e:
                print(f"[Background] Sniffer crashed: {e}")
                time.sleep(2)  # restart delay

    # Launch the blocking sniffer in a separate thread
    try:
        await safe_to_thread(_blocking_sniffer)

    except asyncio.CancelledError:
        print('[Background] Service monitor stopping...')
        return


# -----------------------------------------------------
# MASTER STARTER
# -----------------------------------------------------
async def start_background_monitors():
    """
    Called by server.py lifespan.
    Starts all loops as asyncio Tasks.
    """
    return [
        asyncio.create_task(process_monitor_loop()),
        asyncio.create_task(service_monitor_loop()),
        asyncio.create_task(network_monitor_loop()),
    ]
