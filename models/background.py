from __future__ import annotations

import asyncio
import threading
import time
import traceback

from collectors.factory import get_collector
from storage.storage_writer import write_event

# Initialize collector once
collector = get_collector()


# -----------------------------------------------------
# 1. PROCESS MONITOR LOOP
# -----------------------------------------------------
async def process_monitor_loop():
    """
    Background task that continuously monitors system processes.
    """
    print('[Background] Process monitor started.')

    while True:
        try:
            # 1. Offload blocking work to thread
            events = await asyncio.to_thread(collector.collect_process_events)

            # 2. Write to DB
            if events:
                for ev in events:
                    write_event(ev)

            # 3. Standard Interval Sleep (10s)
            await asyncio.sleep(10)

        except asyncio.CancelledError:
            print('[Background] Process monitor stopping...')
            return

        except Exception:
            # SAFETY SLEEP: Prevents CPU spikes on error
            print('[Background] Process monitor failed. Retrying in 10s...')
            traceback.print_exc()
            await asyncio.sleep(10)


# -----------------------------------------------------
# 2. SERVICE MONITOR LOOP
# -----------------------------------------------------
async def service_monitor_loop():
    """
    Background task that monitors system services.
    """
    print('[Background] Service monitor started.')

    while True:
        try:
            # 1. Fetch services (limit 50 to avoid spam)
            # Use asyncio.to_thread directly (standard Python 3.9+)
            events = await asyncio.to_thread(collector.collect_service_events, limit=50)

            # 2. Write to DB
            if events:
                for ev in events:
                    write_event(ev)

            # 3. Check services every 30 seconds
            await asyncio.sleep(30)

        except asyncio.CancelledError:
            print('[Background] Service monitor stopping...')
            return

        except Exception:
            # SAFETY SLEEP: Prevents CPU spikes on error
            print('[Background] Service monitor failed. Retrying in 30s...')
            traceback.print_exc()
            await asyncio.sleep(30)


# -----------------------------------------------------
# 3. NETWORK MONITOR LOOP (Streaming)
# -----------------------------------------------------
async def network_monitor_loop():
    """
    Background task that sniffs network packets.
    Uses a DAEMON thread so it doesn't hang the server on exit.
    """
    print('[Background] Network monitor started.')

    def _blocking_sniffer():
        while True:
            try:
                # This blocks until a packet arrives
                for event in collector.collect_network_events():
                    if event:
                        write_event(event)
            except Exception as e:
                print(f"[Background] Sniffer thread error: {e}")
                time.sleep(2)

    # FIX: Use a manual Thread with daemon=True
    # This ensures Python kills it instantly when the server stops.
    sniffer_thread = threading.Thread(target=_blocking_sniffer, daemon=True)
    sniffer_thread.start()

    try:
        # Keep this async task alive to "monitor" the thread
        # We just sleep forever until cancelled
        while True:
            await asyncio.sleep(1)

    except asyncio.CancelledError:
        print('[Background] Network monitor stopping...')
        # We don't need to kill the thread manually;
        # because it is a DAEMON, it will die when the process exits.
        return

    except Exception:
        print('[Background] Network monitor main task crashed.')
        traceback.print_exc()
        await asyncio.sleep(5)


async def hardware_monitor_loop():
    """
    Background task that monitors CPU, RAM, and GPU spikes.
    Polls the system every 15 seconds.
    """
    print('[Background] Hardware monitor started.')
    while True:
        try:
            # Check for spikes using your Pydantic model logic
            # Use asyncio.to_thread because psutil calls can sometimes block
            events = await asyncio.to_thread(collector.collect_hardware_events, 40.0, 40.0)

            if events:
                for ev in events:
                    write_event(ev)

            # Wait 15 seconds before the next check
            await asyncio.sleep(15)

        except asyncio.CancelledError:
            print('[Background] Hardware monitor stopping...')
            return
        except Exception as e:
            print(f"[Background] Hardware monitor error: {e}")
            await asyncio.sleep(15)


async def start_background_monitors():
    """
    Called by server.py lifespan.
    Starts all loops as asyncio Tasks.
    """
    return [
        asyncio.create_task(process_monitor_loop()),
        asyncio.create_task(service_monitor_loop()),
        asyncio.create_task(network_monitor_loop()),
        asyncio.create_task(hardware_monitor_loop()),
    ]
