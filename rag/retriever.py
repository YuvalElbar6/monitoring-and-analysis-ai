from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any
from rag.vector_store import vector_store


# ------------------------------
# BASIC RETRIEVER
# ------------------------------
def retrieve(query: str, limit: int = 5):
    """
    Retrieve the most semantically similar documents.
    """
    try:
        return vector_store.similarity_search(query, k=limit)
    except Exception as e:
        print("[RAG RETRIEVER ERROR]", e)
        return []


# ------------------------------
# FILTERED RETRIEVER (BY EVENT TYPE)
# ------------------------------
def retrieve_filtered(query: str, type_filter: str, limit: int = 5):
    """
    Retrieve documents filtered by event type (process, network_flow, service_event...).
    """
    try:
        return vector_store.similarity_search(
            query,
            k=limit,
            filter={"type": type_filter}
        )
    except Exception as e:
        print("[RAG RETRIEVER FILTER ERROR]", e)
        return []


# ------------------------------
# TIME-BASED RETRIEVER
# ------------------------------
def retrieve_recent(query: str, minutes: int = 5, limit: int = 5):
    """
    Retrieve only documents created within the last X minutes.
    """
    try:
        since = datetime.utcnow() - timedelta(minutes=minutes)
        return vector_store.similarity_search(
            query,
            k=limit,
            filter={
                "timestamp": {
                    "$gte": since.isoformat()
                }
            }
        )
    except Exception as e:
        print("[RAG RETRIEVER RECENT ERROR]", e)
        return []


# ------------------------------
# MULTI-CRITERIA RETRIEVER
# ------------------------------
def retrieve_advanced(
    query: str,
    limit: int = 10,
    types: Optional[List[str]] = None,
    since_minutes: Optional[int] = None,
    metadata: Optional[Dict[str, Any]] = None
):
    """
    Most powerful retrieval function.
    Supports:
    - event type filtering
    - timestamp filtering
    - arbitrary metadata filters
    """
    try:
        flt = metadata.copy() if metadata else {}

        if types:
            flt["type"] = {"$in": types}

        if since_minutes:
            since = datetime.utcnow() - timedelta(minutes=since_minutes)
            flt["timestamp"] = {"$gte": since.isoformat()}

        return vector_store.similarity_search(
            query,
            k=limit,
            filter=flt if flt else None
        )

    except Exception as e:
        print("[RAG ADVANCED RETRIEVER ERROR]", e)
        return []
