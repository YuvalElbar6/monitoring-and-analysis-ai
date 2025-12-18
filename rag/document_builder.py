# rag/document_builder.py
"""
Document Builder for RAG
========================

This module is responsible for converting structured system events into
unstructured text documents suitable for semantic search.

It bridges the gap between the structured data (UnifiedEvent objects)
and the Vector Database (ChromaDB), ensuring data is formatted correctly
for embedding.
"""
from __future__ import annotations

from typing import Any

from models.unified import UnifiedEvent


def event_to_document(event: UnifiedEvent) -> dict[str, Any]:
    """
    Converts a UnifiedEvent into a format suitable for the Vector Store (ChromaDB).

    This function performs three key tasks:
    1. Text Construction: Flattens the event details into a human-readable string for the LLM.
    2. ID Generation: Creates a deterministic, unique ID to prevent duplicates.
    3. Metadata Formatting: Ensures metadata is flat and compatible with the vector store.

    Args:
        event (UnifiedEvent): The system event object.

    Returns:
        dict: A dictionary containing 'id', 'text', and 'metadata'.
    """

    # ---------------------------------------------------------
    # 1. BUILD READABLE TEXT (For the AI to "read")
    # ---------------------------------------------------------
    lines = [
        f"Event Type: {event.type}",
        f"Timestamp: {event.timestamp.isoformat()}",
    ]

    # Flatten specific details for better semantic search context
    if isinstance(event.details, dict):
        for k, v in event.details.items():
            lines.append(f"{k}: {v}")
    else:
        lines.append(f"Details: {event.details}")

    # Add metadata to the text body so the AI knows about it too
    if event.metadata:
        lines.append('Metadata:')
        for k, v in event.metadata.items():
            lines.append(f"  {k}: {v}")

    text = '\n'.join(lines)

    # ---------------------------------------------------------
    # 2. GENERATE UNIQUE ID
    # ---------------------------------------------------------
    # We combine Type + Timestamp + Hash of content to ensure uniqueness.
    # This prevents overwriting events that happen in the same microsecond.
    content_hash = hash(text) & 0xffffffff  # Limit hash size
    uid = f"{event.type}_{event.timestamp.timestamp()}_{content_hash}"

    # ---------------------------------------------------------
    # 3. FORMAT METADATA (For database filtering)
    # ---------------------------------------------------------
    # ChromaDB requires metadata values to be str, int, float, or bool.
    # We convert complex types to strings to prevent crashes.
    safe_metadata = {
        'type': str(event.type),
        'timestamp': event.timestamp.isoformat(),
    }

    if event.metadata:
        for k, v in event.metadata.items():
            # Convert lists/dicts to string representation for safety
            if isinstance(v, (list, dict)):
                safe_metadata[k] = str(v)
            else:
                safe_metadata[k] = v

    return {
        'id': uid,
        'text': text,
        'metadata': safe_metadata,
    }
