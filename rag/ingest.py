from __future__ import annotations

from models.unified import UnifiedEvent
from rag.document_builder import event_to_document
from rag.vector_store import vector_store


def ingest_event(event: UnifiedEvent) -> bool:
    """
    Ingest a single UnifiedEvent into the vector store.
    Returns True if added, False if skipped.
    """

    try:
        doc = event_to_document(event)

        # Skip if missing required fields
        if not doc['text'] or not doc['id']:
            return False

        vector_store.add_texts(
            texts=[doc['text']],
            metadatas=[doc['metadata']],
            ids=[doc['id']],
        )
        return True

    except Exception as e:
        print(f"[INGEST ERROR] Failed to ingest event {event}: {e}")
        return False


def ingest_events(events: list[UnifiedEvent]) -> dict:
    """
    Batch-ingest events into vector store.
    Returns stats for debug: {"ingested": X, "skipped": Y}
    """

    stats = {'ingested': 0, 'skipped': 0}

    if not events:
        return stats

    docs = []
    for event in events:
        try:
            doc = event_to_document(event)

            if not doc['text'] or not doc['id']:
                stats['skipped'] += 1
                continue

            docs.append(doc)

        except Exception:
            stats['skipped'] += 1

    if not docs:
        return stats

    # Extract fields
    texts = [d['text'] for d in docs]
    metas = [d['metadata'] for d in docs]
    ids = [d['id'] for d in docs]

    try:
        vector_store.add_texts(
            texts=texts,
            metadatas=metas,
            ids=ids,
        )
        stats['ingested'] += len(docs)

    except Exception as e:
        print('[INGEST ERROR] Batch ingestion failed:', e)

    return stats
