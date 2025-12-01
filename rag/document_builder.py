from __future__ import annotations

from typing import Any

from models.unified import UnifiedEvent


def event_to_document(event: UnifiedEvent) -> dict[str, Any]:
    """
    Convert a UnifiedEvent into a clean and LLM-friendly Chroma document.
    """

    # ------- Build human-readable text chunk for RAG -------
    lines = [
        f"Event Type: {event.type}",
        f"Timestamp: {event.timestamp.isoformat()}",
    ]

    # DETAILS (flatten for readability)
    if isinstance(event.details, dict):
        for k, v in event.details.items():
            lines.append(f"{k}: {v}")
    else:
        lines.append(f"Details: {event.details}")

    # METADATA
    if event.metadata:
        lines.append('\nMetadata:')
        for k, v in event.metadata.items():
            lines.append(f"  {k}: {v}")

    # Final text chunk
    text = '\n'.join(lines)

    # -------- Unique ID (type + ISO time + hash of details) --------
    uid = f"{event.type}-{event.timestamp.isoformat()}"

    # Optional: enforce uniqueness
    # uid = f"{uid}-{hash(text) & 0xfffffff}"

    # -------- Chroma Document --------
    return {
        'id': uid,
        'text': text,
        'metadata': {
            'type': event.type,
            'timestamp': event.timestamp.isoformat(),
            **(event.metadata or {}),
        },
    }
