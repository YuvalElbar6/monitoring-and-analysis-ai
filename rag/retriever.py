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
