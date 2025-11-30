# mcp_models.py
from pydantic import BaseModel
from typing import List, Optional, Dict, Any


class MCPNetworkQuery(BaseModel):
    duration_minutes: int = 5


class MCPEventTypeQuery(BaseModel):
    event_type: str = "all"


class MCPProcessList(BaseModel):
    processes: List[Dict[str, Any]]


class MCPNetworkFlowList(BaseModel):
    flows: List[Dict[str, Any]]


class MCPServiceEventList(BaseModel):
    service_events: List[Dict[str, Any]]


class MCPRAGQuery(BaseModel):
    query: str


class MCPRAGResponse(BaseModel):
    results: List[str]
