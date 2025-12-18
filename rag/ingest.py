from __future__ import annotations

from typing import Any

from models.unified import UnifiedEvent
from rag.document_builder import event_to_document
from rag.vector_store import vector_store


def ingest_event(event: UnifiedEvent | dict[str, Any]) -> bool:
    """
    Ingest a single UnifiedEvent into the vector store.

    Args:
        event (UnifiedEvent | dict): The event data to store.
                                     Accepts raw dicts to support JSON-serialized inputs.

    Returns:
        bool: True if added successfully, False if skipped (e.g. missing data).
    """
    try:
        # Compatibility: Convert dict back to UnifiedEvent if needed
        # This ensures downstream functions always get the object they expect.
        if isinstance(event, dict):
            try:
                event = UnifiedEvent(**event)
            except Exception:
                # If validation fails, we can't process it safely
                return False

        doc = event_to_document(event)

        # Validation: Skip if missing critical fields
        if not doc.get('text') or not doc.get('id'):
            return False

        vector_store.add_texts(
            texts=[doc['text']],
            metadatas=[doc['metadata']],
            ids=[doc['id']],
        )
        return True

    except Exception as e:
        print(f"[RAG INGEST ERROR] Failed to ingest event: {e}")
        return False


def ingest_events(events: list[UnifiedEvent]) -> dict[str, int]:
    """
    Batch-ingest events into the vector store.
    Using batches is significantly faster than adding events one by one.

    Args:
        events (List[UnifiedEvent]): List of events to process.

    Returns:
        dict: Stats for debugging: {"ingested": X, "skipped": Y}
    """
    stats = {'ingested': 0, 'skipped': 0}

    if not events:
        return stats

    docs = []

    # 1. Prepare Documents
    for event in events:
        try:
            # Handle mixed types in batch
            if isinstance(event, dict):
                event = UnifiedEvent(**event)

            doc = event_to_document(event)

            if not doc.get('text') or not doc.get('id'):
                stats['skipped'] += 1
                continue

            docs.append(doc)

        except Exception:
            # Skip malformed events without crashing the whole batch
            stats['skipped'] += 1

    if not docs:
        return stats

    # 2. Extract Batch Fields
    texts = [d['text'] for d in docs]
    metas = [d['metadata'] for d in docs]
    ids = [d['id'] for d in docs]

    # 3. Bulk Insert
    try:
        vector_store.add_texts(
            texts=texts,
            metadatas=metas,
            ids=ids,
        )
        stats['ingested'] += len(docs)

    except Exception as e:
        print(f'[RAG INGEST ERROR] Batch ingestion failed: {e}')
        # In a real production system, you might retry here

    return stats
