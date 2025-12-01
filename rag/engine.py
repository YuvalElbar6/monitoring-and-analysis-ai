from typing import List, Dict, Any
import httpx
from rag.retriever import retrieve
from os_env import BASE_OLLAMA_URL


class RAGResponse:
    def __init__(self, answer: str, citations: List[str]):
        self.answer = answer
        self.citations = citations

    def dict(self) -> Dict[str, Any]:
        return {
            "answer": self.answer,
            "citations": self.citations,
        }


# ---------------------------------------------------------
# LLM CALL (Ollama)
# ---------------------------------------------------------

async def call_ollama(prompt: str, model: str = "mistral:latest") -> str:
    url = f"{BASE_OLLAMA_URL}/api/chat"

    payload = {
        "model": model,
        "messages": [
            {"role": "user", "content": prompt}
        ],
        "stream": False,
    }

    async with httpx.AsyncClient() as client:
        resp = await client.post(url, json=payload)
        resp.raise_for_status()

        data = resp.json()

        # Ollama sometimes returns message or messages list
        if "message" in data:
            return data["message"]["content"]

        if "messages" in data:
            return data["messages"][-1]["content"]

        raise RuntimeError("Unexpected Ollama response format")


# ---------------------------------------------------------
# RAG PIPELINE
# ---------------------------------------------------------

async def answer_with_rag(query: str) -> RAGResponse:
    # 1. Retrieve relevant documents
    docs = retrieve(query)

    # Extract content + IDs
    pages = [d.page_content for d in docs]
    doc_ids = [d.metadata.get("id", f"doc-{i}") for i, d in enumerate(docs)]

    # 2. Build text context
    context = ""
    for i, (text, doc_id) in enumerate(zip(pages, doc_ids)):
        context += f"\n[Document {i+1} | ID: {doc_id}]\n{text}\n---\n"

    # 3. Build forensic prompt
    prompt = f"""
You are a forensic analysis AI.
Use ONLY the context provided. Do NOT hallucinate.

Context:
{context}

Question: {query}

You MUST return JSON in the following format:

{{
  "answer": "<final conclusion>",
  "citations": ["<document-id-1>", "<document-id-2>"]
}}

Rules:
- "citations" MUST be document IDs from the context.
- If answer cannot be found, answer "Not found".
- Do NOT cite anything not explicitly in the context.
"""

    # 4. Call the LLM
    raw_answer = await call_ollama(prompt)

    # 5. Best effort JSON extraction
    try:
        import json
        data = json.loads(raw_answer)
        answer = data.get("answer", raw_answer)
        citations = data.get("citations", [])
    except Exception:
        # Fallback if model returns plain text
        answer = raw_answer
        citations = doc_ids

    return RAGResponse(answer=answer, citations=citations)
