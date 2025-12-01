# server.py
from __future__ import annotations

import asyncio
import sys
from contextlib import asynccontextmanager

from fastmcp import FastMCP

from analysis import analyze_network_flow
from analysis import analyze_process
from analysis import analyze_service_event
from collectors.factory import get_collector
from models.background import start_background_monitors
from os_env import SERVER_HOST
from os_env import SERVER_PORT
from rag.describer import describe_process_with_rag
from rag.engine import answer_with_rag
from vt_check import scan_file_rag_intel


collector = get_collector()


@asynccontextmanager
async def lifespan(app):
    print('🚀 Starting background collectors...')
    tasks = await start_background_monitors()

    print('🚀 Background collectors started.')

    try:
        yield  # FastMCP runs normally here
    finally:
        print('🛑 Shutting down background collectors...')

        # cancel all tasks
        for t in tasks:
            t.cancel()

        # wait until all tasks die
        await asyncio.gather(*tasks, return_exceptions=True)

        print('✅ Background collectors stopped cleanly.')


app = FastMCP(
    name='PCSystemMonitor',
    host=SERVER_HOST,
    port=SERVER_PORT,
    lifespan=lifespan,
)


# ------------------------------------------------------
# RESOURCES (CORRECT, NO TEMPLATE ERRORS)
# ------------------------------------------------------

@app.resource('data://config')
def get_config():
    return {'service': 'PCSystemMonitor', 'status': 'running'}


@app.resource('data://system/processes')
def get_processes():
    events = collector.collect_process_events()
    return [e.model_dump() for e in events]


@app.resource('data://system/network_flows')
def get_flows():
    events = collector.collect_network_events()
    return [e.model_dump() for e in events]


@app.resource('data://system/service_events/{limit}}')
def get_service_events(limit=50):
    events = collector.collect_service_events(limit=limit)
    return [e.model_dump() for e in events]


@app.resource('data://system/rag/{query}')
async def rag_query(query: str = ''):
    if not query:
        return {'error': 'Missing query'}
    rag = await answer_with_rag(query)
    return rag.dict()


# ------------------------------------------------------
# TOOLS (ACTIONS)
# ------------------------------------------------------

@app.tool()
def get_testing_ping():
    return 'pong'


@app.tool()
async def get_running_processes():
    events = collector.collect_process_events()
    return {'processes': [e.model_dump() for e in events]}


@app.tool()
async def get_running_services():
    events = collector.collect_service_events()
    return {'services': [e.model_dump() for e in events]}


@app.tool()
async def get_network_flows(limit=5):
    events = collector.collect_network_events(limit=limit)
    return {'flows': [e.model_dump() for e in events]}


@app.tool()
async def search_findings(query: str):
    rag = await answer_with_rag(query)
    return rag.dict()


@app.tool()
async def threat_lookup(args):
    entity = args.get('entity')
    result = await scan_file_rag_intel(entity)
    return result.__dict__


@app.tool()
async def analyze_processes(args=None):
    events = collector.collect_process_events()
    results = []

    for e in events:
        raw = e.model_dump()
        base = analyze_process(raw)  # existing scoring logic

        # Add RAG description
        desc = await describe_process_with_rag(
            base['name'],
            base['exe'],
            base['username'],
        )

        base['rag_description'] = desc
        results.append(base)

    results.sort(key=lambda x: x['risk_score'], reverse=True)

    return {
        'analysis': results,
        'total_processes': len(events),
    }


@app.tool()
async def analyze_network(args=None):
    """
    Analyze recent captured network traffic.
    """
    flows = collector.collect_network_events(limit=50)
    processed = [analyze_network_flow(f.model_dump()) for f in flows]

    processed.sort(key=lambda x: x['risk_score'], reverse=True)
    top_results = processed[:10]

    return {
        'analysis': top_results,
        'total_flows': len(processed),
    }


@app.tool()
async def analyze_services(args=None):
    """
    Analyze recent Windows service logs.
    If running on Linux/Mac, returns empty list.
    """
    try:
        events = collector.collect_service_events(limit=50)
    except Exception:
        return {'analysis': [], 'total_events': 0, 'note': 'Service logs not supported on this OS'}

    processed = [analyze_service_event(e.model_dump()) for e in events]

    processed.sort(key=lambda x: x['risk_score'], reverse=True)
    top_results = processed[:10]

    return {
        'analysis': top_results,
        'total_events': len(processed),
    }


@app.tool()
async def analyze_all(args=None):
    """
    Master system analysis combining:
    - processes
    - network flows
    - service logs (if available)
    """

    # ---- Processes ----
    pevents = collector.collect_process_events()
    process_results = [
        analyze_process(e.model_dump()) for e in pevents
    ]
    process_results.sort(key=lambda x: x['risk_score'], reverse=True)
    process_top = process_results[:10]

    # ---- Network ----
    nevents = collector.collect_network_events(limit=50)
    network_results = [
        analyze_network_flow(e.model_dump()) for e in nevents
    ]
    network_results.sort(key=lambda x: x['risk_score'], reverse=True)
    network_top = network_results[:10]

    # ---- Services (optional, Windows only) ----
    try:
        sevents = collector.collect_service_events(limit=50)
        service_results = [
            analyze_service_event(e.model_dump()) for e in sevents
        ]
        service_results.sort(key=lambda x: x['risk_score'], reverse=True)
        service_top = service_results[:10]
    except Exception as e:
        print(f"An exception {e} has occurd")
        service_top = []

    return {
        'process_analysis': process_top,
        'network_analysis': network_top,
        'service_analysis': service_top,
    }


# ------------------------------------------------------
# RUN SERVER
# ------------------------------------------------------

if __name__ == '__main__':
    print(
        f"[INFO] MCP running on {SERVER_HOST}:{SERVER_PORT}", file=sys.stderr,
    )
    app.run(transport='streamable-http')
