from __future__ import annotations

from helper.json_helper import extract_json
from rag.engine import call_ollama
from rag.retriever import retrieve


async def describe_process_with_rag(process_name: str, exe: str, username: str):
    """
    Uses RAG to describe the process based on retrieved system evidence.
    Falls back to a simple description if no documents match.
    """

    query = f"What is the process '{process_name}' running as {exe}?"

    docs = retrieve(query, limit=5)
    context = '\n\n---\n\n'.join([d.page_content for d in docs])

    prompt = f"""
You are a process description engine.

Context about system activity:
{context}

Describe the process "{process_name}" in simple terms.

Mention:
- what this program usually does
- whether it is built-in, third-party, or unknown
- why it might appear on a computer
- whether its behavior is normal based on the context

If context is empty or irrelevant:
- give a generic description (e.g., "Windows system process", "A browser", etc.)

Your description must be 1-3 sentences.
    """

    result = await call_ollama(prompt)
    return extract_json(result)['description']
