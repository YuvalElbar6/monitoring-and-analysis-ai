from __future__ import annotations

from langchain_community.embeddings import OllamaEmbeddings


def get_embeddings():
    return OllamaEmbeddings(model='nomic-embed-text')
