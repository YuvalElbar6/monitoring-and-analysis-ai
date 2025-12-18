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

import uuid
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
    if isinstance(event.details, dict):
        for k, v in event.details.items():
            lines.append(f"{k}: {v}")
    else:
        lines.append(f"Details: {event.details}")

    if event.metadata:
        lines.append('Metadata:')
        for k, v in event.metadata.items():
            lines.append(f"  {k}: {v}")

    text = '\n'.join(lines)

    # --- THE FIX ---
    # Old way: Timestamp + Hash (Collides on identical repeating packets)
    # New way: Timestamp + Hash + Random Short UUID
    content_hash = hash(text) & 0xffffffff
    random_suffix = uuid.uuid4().hex[:8]  # Adds randomness

    uid = f"{event.type}_{event.timestamp.timestamp()}_{content_hash}_{random_suffix}"

    # ... (Rest of function remains the same) ...

    safe_metadata = {
        'type': str(event.type),
        'timestamp': event.timestamp.isoformat(),
    }
    if event.metadata:
        for k, v in event.metadata.items():
            if isinstance(v, (list, dict)):
                safe_metadata[k] = str(v)
            else:
                safe_metadata[k] = v

    return {
        'id': uid,
        'text': text,
        'metadata': safe_metadata,
    }
