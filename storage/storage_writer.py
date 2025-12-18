# storage/storage_writer.py
from __future__ import annotations

from storage.database import DatabaseWorker

# Initialize worker ONCE.
# This creates the file 'system_monitor.db' automatically.
_db_worker = DatabaseWorker()


def write_event(event):
    """
    Non-blocking save.
    """
    if event:
        _db_worker.add_event(event)
