# rag/retriever.py
"""
RAG Retrieval Engine
====================

This module handles searching the Vector Database for historical system events.
It supports:
- Semantic Search: Finding events based on meaning (e.g., "suspicious network activity").
- Filtering: Narrowing results by event type (process vs network) or time.
- Advanced Querying: Combining metadata and time constraints.
"""
from __future__ import annotations

from datetime import datetime
from datetime import timedelta
from datetime import timezone
from typing import Any

from rag.vector_store import vector_store


# ------------------------------
# BASIC RETRIEVER
# ------------------------------
def retrieve(query: str, limit: int = 5) -> list[Any]:
    """
    Basic Semantic Search.
    Retrieves the most semantically similar documents to the query string.

    Args:
        query (str): The natural language search query.
        limit (int): Max number of documents to return.

    Returns:
        List[Document]: A list of LangChain Document objects.
    """
    try:
        return vector_store.similarity_search(query, k=limit)
    except Exception as e:
        print(f'[RAG RETRIEVER ERROR] {e}')
        return []


# ------------------------------
# FILTERED RETRIEVER (BY EVENT TYPE)
# ------------------------------
def retrieve_filtered(query: str, type_filter: str, limit: int = 5) -> list[Any]:
    """
    Retrieve documents filtered by event type.

    Args:
        query (str): Search query.
        type_filter (str): One of 'process', 'network_flow', 'service_event'.
        limit (int): Max results.
    """
    try:
        return vector_store.similarity_search(
            query,
            k=limit,
            filter={'type': type_filter},
        )
    except Exception as e:
        print(f'[RAG RETRIEVER FILTER ERROR] {e}')
        return []


# ------------------------------
# TIME-BASED RETRIEVER
# ------------------------------
def retrieve_recent(query: str, minutes: int = 5, limit: int = 5) -> list[Any]:
    """
    Retrieve only documents created within the last X minutes.

    Note: Requires the vector store to support '$gte' operator for metadata.
    """
    try:
        # FIX: Use timezone-aware UTC time
        since = datetime.now(timezone.utc) - timedelta(minutes=minutes)

        return vector_store.similarity_search(
            query,
            k=limit,
            filter={
                'timestamp': {
                    '$gte': since.isoformat(),
                },
            },
        )
    except Exception as e:
        print(f'[RAG RETRIEVER RECENT ERROR] {e}')
        return []


# ------------------------------
# MULTI-CRITERIA RETRIEVER
# ------------------------------
def retrieve_advanced(
    query: str,
    limit: int = 10,
    types: list[str] | None = None,
    since_minutes: int | None = None,
    metadata: dict[str, Any] | None = None,
) -> list[Any]:
    """
    Advanced Retrieval function combining multiple filters.

    Args:
        query (str): The search text.
        limit (int): Max results.
        types (list[str]): List of event types to include (e.g. ['process', 'network_flow']).
        since_minutes (int): Lookback window in minutes.
        metadata (dict): Additional key-value pairs to filter by.

    Returns:
        List[Document]: Matching documents.
    """
    try:
        flt = metadata.copy() if metadata else {}

        # Add Type Filter (using $in operator if supported by backend)
        if types:
            flt['type'] = {'$in': types}

        # Add Time Filter
        if since_minutes:
            since = datetime.now(timezone.utc) - timedelta(minutes=since_minutes)
            flt['timestamp'] = {'$gte': since.isoformat()}

        return vector_store.similarity_search(
            query,
            k=limit,
            filter=flt if flt else None,
        )

    except Exception as e:
        print(f'[RAG ADVANCED RETRIEVER ERROR] {e}')
        return []
