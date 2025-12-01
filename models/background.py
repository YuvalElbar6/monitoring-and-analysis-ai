from __future__ import annotations

import asyncio
import traceback

from collectors.factory import get_collector
from models.mcp import state

collector = get_collector()


async def safe_call(name, func, *args, **kwargs):
    """Runs blocking functions safely in a thread."""
    try:
        return await asyncio.to_thread(func, *args, **kwargs)
    except Exception:
        print(f"[{name}] Error in background task:")
        traceback.print_exc()
        return None


# -----------------------------------------------------
# PROCESS MONITOR
# -----------------------------------------------------
async def process_monitor_loop():
    while True:
        result = await safe_call('process', collector.collect_process_events)
        if result is not None:
            state.processes = result
        await asyncio.sleep(3)


# -----------------------------------------------------
# NETWORK MONITOR (Scapy requires isolation)
# -----------------------------------------------------
async def network_monitor_loop():
    while True:
        # Scapy must ALWAYS run in a thread
        result = await safe_call('network', collector.collect_network_events, 5)
        if result is not None:
            state.network_flows = result
        await asyncio.sleep(3)


# -----------------------------------------------------
# SERVICE MONITOR (systemd / launchd / Windows SCM)
# -----------------------------------------------------
async def service_monitor_loop():
    while True:
        result = await safe_call('services', collector.collect_service_events)
        if result is not None:
            state.services = result
        await asyncio.sleep(5)


# -----------------------------------------------------
# MASTER TASK STARTER
# -----------------------------------------------------
async def start_background_monitors():
    return [
        asyncio.create_task(process_monitor_loop()),
        asyncio.create_task(network_monitor_loop()),
        asyncio.create_task(service_monitor_loop()),
    ]
