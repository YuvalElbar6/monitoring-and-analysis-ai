from __future__ import annotations

import queue
import threading
import time

from sqlalchemy import create_engine
from sqlalchemy import select
from sqlalchemy.orm import Session

from rag.ingest import ingest_events
from storage.schema import Base
from storage.schema import UnifiedEventTable


class DatabaseWorker:
    def __init__(self, db_url='sqlite:///system_monitor.db'):
        self.queue = queue.Queue()
        self.running = True

        # 1. Setup pure SQLAlchemy Engine
        self.engine = create_engine(db_url, echo=False)

        # 2. Create tables
        Base.metadata.create_all(self.engine)

        self.thread = threading.Thread(target=self._worker_loop, daemon=True)
        self.thread.start()

    def add_event(self, event):
        # Accepts the Pydantic model
        self.queue.put(event)

    def _worker_loop(self):
        rag_batch = []
        batch = []
        last_flush = time.time()
        print('[Storage] Worker loop started.')

        while self.running:
            try:
                # Get Pydantic object
                pydantic_event = self.queue.get(timeout=1.0)

                # --- MAPPING LAYER ---
                # Convert Pydantic (App Data) -> SQLAlchemy (DB Row)
                db_row = UnifiedEventTable(
                    timestamp=pydantic_event.timestamp,
                    event_type=pydantic_event.type,
                    details=pydantic_event.details,
                    metadata_fields=pydantic_event.metadata,
                )

                batch.append(db_row)

                rag_batch.append(pydantic_event)

            except queue.Empty:
                pass

            if len(batch) >= 50 or (batch and time.time() - last_flush > 3):

                self._save_batch(batch)
                try:
                    stats = ingest_events(rag_batch)
                    # Optional: Print stats only if something was actually ingested
                    if stats['ingested'] > 0:
                        print(f"[RAG] Synced {stats['ingested']} events.")
                except Exception as e:
                    print(f"[RAG Sync Error] {e}")

                # 3. Reset
                batch = []
                rag_batch = []
                last_flush = time.time()

    def get_recent_events(self, event_type: str, limit: int = 50):
        """
        Reads the latest events from the DB.
        Instant access. No waiting for traffic.
        """
        try:
            with Session(self.engine) as session:
                stmt = (
                    select(UnifiedEventTable)
                    .where(UnifiedEventTable.event_type == event_type)
                    .order_by(UnifiedEventTable.timestamp.desc())
                    .limit(limit)
                )
                rows = session.scalars(stmt).all()

                # Convert DB Objects back to clean Dictionaries for the API
                return [
                    {
                        'timestamp': row.timestamp.isoformat(),
                        **row.details,           # The JSON data (src, dst, etc)
                        **row.metadata_fields,    # OS info
                    }
                    for row in rows
                ]
        except Exception as e:
            print(f"[DB Read Error] {e}")
            return []

    def _save_batch(self, batch):
        try:
            with Session(self.engine) as session:
                session.add_all(batch)  # slightly faster than loop
                session.commit()
        except Exception as e:
            print(f"[DB Error] {e}")
