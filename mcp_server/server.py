from typing import Any, Dict
from fastmcp import FastMCP
from models.mcp import (
    MCPNetworkQuery, MCPEventTypeQuery, MCPProcessList,
    MCPNetworkFlowList, MCPServiceEventList,
    MCPRAGQuery, MCPRAGResponse

)

from collectors.factory import get_collector

from rag.engine import rag_search


# Initialize MCP App
app = FastMCP(
    name="PCSystemMonitor",
    host="127.0.0.1",
    port=8080)


# Create collector (Windows/Linux/macOS auto-detect)
collector = get_collector()


@app.tool()
def ping() -> str:
    """Test that the MCP server is alive."""
    return "pong"

@app.tool()
async def get_network_flows(query: MCPNetworkQuery) -> Dict[str, Any]:
    """
    Retrieve network traffic flows collected recently.
    """
    events = collector.collect_network_events(
        limit=50  # Or compute based on query.duration_minutes
    )

    return MCPNetworkFlowList(flows=[e.model_dump() for e in events]).model_dump()


@app.tool()
async def get_running_processes() -> Dict[str, Any]:
    events = collector.collect_process_events()

    return MCPProcessList(processes=[e.model_dump() for e in events]).model_dump()


@app.tool()
async def search_findings(query: MCPRAGQuery) -> MCPRAGResponse:
    results = rag_search(query.query)

    return MCPRAGResponse(results=results)