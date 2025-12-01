# server.py
import sys
from fastmcp import FastMCP
from models.mcp import MCPNetworkQuery, MCPRAGQuery
from collectors.factory import get_collector
from rag.engine import answer_with_rag
from os_env import SERVER_HOST, SERVER_PORT

collector = get_collector()

app = FastMCP(
    name="PCSystemMonitor",
    host=SERVER_HOST,
    port=SERVER_PORT
)

# ------------------------------------------------------
# RESOURCES (CORRECT, NO TEMPLATE ERRORS)
# ------------------------------------------------------

@app.resource("data://config")
def get_config():
    return {"service": "PCSystemMonitor", "status": "running"}


@app.resource("data://system/processes")
def get_processes():
    events = collector.collect_process_events()
    return [e.model_dump() for e in events]


@app.resource("data://system/network_flows")
def get_flows():
    events = collector.collect_network_events()
    return [e.model_dump() for e in events]


@app.resource("data://system/service_events/{limit}}")
def get_service_events(limit  = 50):
    events = collector.collect_service_events(limit=limit)
    return [e.model_dump() for e in events]


@app.resource("data://system/rag/{query}")
async def rag_query(query: str = ""):
    if not query:
        return {"error": "Missing query"}
    rag = await answer_with_rag(query)
    return rag.dict()


# ------------------------------------------------------
# TOOLS (ACTIONS)
# ------------------------------------------------------

@app.tool()
def get_testing_ping():
    return "pong"


@app.tool()
async def get_running_processes():
    events = collector.collect_process_events()
    return {"processes": [e.model_dump() for e in events]}


@app.tool()
async def get_network_flows(limit=5):
    events = collector.collect_network_events(limit=limit)
    return {"flows": [e.model_dump() for e in events]}


@app.tool()
async def search_findings(query: str):
    rag = await answer_with_rag(query)
    return rag.dict()


# ------------------------------------------------------
# RUN SERVER
# ------------------------------------------------------

if __name__ == "__main__":
    print(f"[INFO] MCP running on {SERVER_HOST}:{SERVER_PORT}", file=sys.stderr)
    app.run(transport="streamable-http")
