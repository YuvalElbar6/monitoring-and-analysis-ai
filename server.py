# server.py
from __future__ import annotations

import asyncio
import sys
from contextlib import asynccontextmanager

from fastmcp import FastMCP

from analysis import analyze_hardware
from analysis import analyze_network_flow
from analysis import analyze_process
from analysis import analyze_service_event
from models.background import start_background_monitors
from os_env import SERVER_HOST
from os_env import SERVER_PORT
from rag.describer import describe_process_with_rag
from rag.engine import answer_with_rag
from storage.storage_writer import _db_worker


@asynccontextmanager
async def lifespan(app):
    """
    Manages the lifecycle of the application.

    1. Starts the background collectors (Process, Network, Services) on startup.
    2. Ensures they are cancelled and cleaned up gracefully on shutdown.
    3. stops the Database Worker thread safely.
    """

    print('🚀 Starting background collectors...')
    tasks = await start_background_monitors()
    print('🚀 Background collectors started.')

    try:
        yield
    finally:
        print('🛑 Shutting down background collectors...')
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        print('✅ Background collectors stopped cleanly.')

        # Stop the DB worker gracefully
        _db_worker.stop()
        print('✅ Shutdown complete.')


app = FastMCP(
    name='PCSystemMonitor',
    host=SERVER_HOST,
    port=SERVER_PORT,
    lifespan=lifespan,
)


# ------------------------------------------------------
# RESOURCES
# ------------------------------------------------------

@app.resource('data://config')
def get_config():
    """
    Health check resource.
    Returns the current service status and name.
    """
    return {'service': 'PCSystemMonitor', 'status': 'running'}


@app.resource('data://system/processes')
def get_processes():
    """
    Resource that returns the raw list of the most recent processes from the database.
    """
    return _db_worker.get_recent_events('process')


@app.resource('data://system/network_flows')
def get_flows():
    """
    Resource that returns the raw list of recent network traffic flows from the database.
    """
    return _db_worker.get_recent_events('network_flow')


@app.resource('data://system/service_events/{limit}')
def get_service_events(limit: int = 50):
    """
    Resource that returns recent system service logs (Windows Events / Systemd logs).

    Args:
        limit (int): The maximum number of log entries to retrieve. Default is 50.
    """
    return _db_worker.get_recent_events('service_event', limit=limit)


@app.resource('data://system/rag/{query}')
async def rag_query(query: str = ''):
    """
    Resource for direct RAG (Retrieval-Augmented Generation) queries.
    Allows fetching AI-synthesized answers about system state via URL path.
    """
    if not query:
        return {'error': 'Missing query'}
    rag = await answer_with_rag(query)
    return rag.dict()


# ------------------------------------------------------
# TOOLS (ACTIONS)
# ------------------------------------------------------

@app.tool()
def get_testing_ping():
    """
    A simple connectivity test tool.
    Returns 'pong' if the server is reachable and responsive.
    """
    return 'pong'


@app.tool()
async def get_running_processes():
    """
    Tool to fetch a snapshot of currently running processes.
    Useful for listing active applications without performing deep analysis.

    Returns:
        dict: A dictionary containing a list of process objects.
    """
    events = _db_worker.get_recent_events('process')
    return {'processes': events}


@app.tool()
async def get_running_services():
    """
    Tool to fetch recent service status changes or logs.

    Returns:
        dict: A dictionary containing a list of service event objects.
    """
    events = _db_worker.get_recent_events('service_event')
    return {'services': events}


@app.tool()
async def get_network_flows(limit: int = 10):
    """
    Tool to fetch the most recent network packets/flows.

    Args:
        limit (int): Number of flows to return (default: 10).

    Returns:
        dict: A dictionary containing a list of network flow objects.
    """
    flows = _db_worker.get_recent_events('network_flow', limit=limit)

    processed = [analyze_network_flow(f) for f in flows]

    processed.sort(key=lambda x: x.get('risk_score', 0), reverse=True)

    return {
        'analysis': processed[: limit],
        'total_flows': len(processed),
    }


@app.tool()
async def search_findings(query: str):
    """
    Semantic Search Tool.
    Uses RAG to find relevant system events based on natural language queries.

    Example:
        "Show me all connections to IP 8.8.8.8"
        "Find processes that started after midnight"

    Args:
        query (str): The natural language question or search term.
    """
    rag = await answer_with_rag(query)
    return rag.dict()


@app.tool()
async def analyze_processes(args=None):
    """
    Analyzes recent processes for security risks.

    1. Fetches recent process data from the database.
    2. Applies heuristic risk scoring (e.g., high CPU, weird names).
    3. Enriches data with AI descriptions of what the process actually does.

    Returns:
        dict: Sorted list of processes by risk score.
    """
    events = _db_worker.get_recent_events('process')
    results = []

    for raw_event in events:
        base = analyze_process(raw_event)

        # Add RAG description
        desc = await describe_process_with_rag(
            base.get('name', 'unknown'),
            base.get('exe', ''),
            base.get('username', ''),
        )
        base['rag_description'] = desc
        results.append(base)

    results.sort(key=lambda x: x.get('risk_score', 0), reverse=True)

    return {
        'analysis': results,
        'total_processes': len(events),
    }


@app.tool()
async def analyze_network(args=None):
    """
    Analyzes recent network traffic for anomalies.

    1. Fetches recent flows from the database.
    2. detailed risk scoring (e.g., non-standard ports, external IPs).

    Returns:
        dict: Top 10 riskiest network flows found.
    """
    flows = _db_worker.get_recent_events('network_flow')

    processed = [analyze_network_flow(f) for f in flows]
    processed.sort(key=lambda x: x.get('risk_score', 0), reverse=True)

    return {
        'analysis': processed,
        'total_flows': len(processed),
    }


@app.tool()
async def analyze_services(args=None):
    """
    Analyzes recent service logs for errors or security events.

    Returns:
        dict: Top 10 riskiest service events (errors, failures, etc.).
    """
    events = _db_worker.get_recent_events('service_event')
    if not events:
        return {'analysis': [], 'total_events': 0, 'note': 'No service logs found'}

    processed = [analyze_service_event(e) for e in events]
    processed.sort(key=lambda x: x.get('risk_score', 0), reverse=True)

    return {
        'analysis': processed,
        'total_events': len(processed),
    }


@app.tool()
async def analyze_hardware_spikes(limit: int = 15, **kwargs):
    """
    Analyzes recent hardware resource spikes (CPU, RAM, GPU).
    Identifies 'heavy' processes and calculates risk scores based on resource abuse.

    Args:
        limit (int): Number of spikes to analyze.
    """
    events = _db_worker.get_recent_events('hardware_spike', limit=limit)
    if not events:
        return {'analysis': [], 'total_spikes': 0, 'status': 'Normal'}

    processed = [analyze_hardware(e) for e in events]
    # Sort by the risk score calculated in analysis.py
    processed.sort(key=lambda x: x.get('risk_score', 0), reverse=True)

    return {
        'analysis': processed,
        'total_spikes': len(events),
    }


@app.tool()
async def analyze_all(args=None):
    """
    Master Analysis Tool.
    Performs a full security sweep of the system.

    Combines analysis from:
    - Processes (Top 10 risks)
    - Network Traffic (Top 10 risks)
    - Service Logs (Top 10 risks)

    Returns:
        dict: A comprehensive security report.
    """

    pevents = _db_worker.get_recent_events('process')
    nevents = _db_worker.get_recent_events('network_flow')
    sevents = _db_worker.get_recent_events('service_event')
    hevents = _db_worker.get_recent_events('hardware_spike')

    # 2. Analyze everything using our analysis engine
    process_results = [analyze_process(e) for e in pevents]
    network_results = [analyze_network_flow(e) for e in nevents]
    service_results = [analyze_service_event(e) for e in sevents]
    hardware_results = [analyze_hardware(e) for e in hevents]

    # 3. Sort by risk
    for res_list in [process_results, network_results, service_results, hardware_results]:
        res_list.sort(key=lambda x: x.get('risk_score', 0), reverse=True)
    return {
        'process_analysis': process_results,
        'network_analysis': network_results,
        'service_analysis': service_results,
        'hardware_analysis': hardware_results,
    }


if __name__ == '__main__':
    print(f"[INFO] MCP running on {SERVER_HOST}:{SERVER_PORT}", file=sys.stderr)
    try:
        app.run(transport='streamable-http')
    except KeyboardInterrupt:
        print('\n[INFO] Server stopping...', file=sys.stderr)
    except Exception as e:
        print(f"\n[ERROR] Server crashed: {e}", file=sys.stderr)
