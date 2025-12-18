# rag/vector_store.py
from __future__ import annotations

import os
from typing import Any

from os_env import CHROMA_DIR
from rag.embeddings import get_embeddings


def _get_chroma_class() -> Any:
    """
    Safely imports the Chroma class, handling different LangChain versions.
    """
    try:
        from langchain_chroma import Chroma
        return Chroma
    except ImportError:
        try:
            from langchain_community.vectorstores import Chroma
            return Chroma
        except ImportError:
            raise ImportError(
                'Could not import Chroma. '
                'Please install it via `pip install langchain-chroma` or `pip install langchain-community`.',
            )


def _initialize_store():
    """
    Sets up the Vector Database with the correct embedding model and directory.
    Returns the configured VectorStore object.
    """
    # 1. Ensure persistence directory exists
    try:
        os.makedirs(CHROMA_DIR, exist_ok=True)
    except Exception as e:
        print(f"[VectorStore] Warning: Could not create directory {CHROMA_DIR}: {e}")

    # 2. Get the specific class (based on installed packages)
    ChromaClass = _get_chroma_class()

    # 3. Initialize the store
    # We use a fixed collection name so data persists correctly.
    store = ChromaClass(
        collection_name='system_events',
        embedding_function=get_embeddings(),
        persist_directory=CHROMA_DIR,
    )

    return store

# --- EXPORTS ---


# Initialize the singleton instance
# This is what other modules (ingestion.py, retriever.py) will import.
vector_store = _initialize_store()

# Create a standard retriever interface for the Agents
retriever = vector_store.as_retriever(search_kwargs={'k': 5})
