from __future__ import annotations

import httpx

from helper.json_helper import extract_json
from os_env import BASE_OLLAMA_URL
from rag.model import RAGResponse
from rag.retriever import retrieve


async def call_ollama(prompt: str, model: str = 'gemma3:4b') -> str:
    """
    Robustly sends a prompt to Ollama.
    Includes timeouts, error handling, and flexible response parsing.
    """
    url = f"{BASE_OLLAMA_URL}/api/chat"

    payload = {
        'model': model,
        'messages': [{'role': 'user', 'content': prompt}],
        'stream': False,
    }

    async with httpx.AsyncClient() as client:
        try:
            # 1. increased timeout for complex reasoning
            resp = await client.post(url, json=payload, timeout=60.0)
            resp.raise_for_status()

            data = resp.json()

            # 2. Flexible Parsing (Handles potential API variations)
            if 'message' in data:
                return data['message']['content']

            if 'messages' in data:
                return data['messages'][-1]['content']

            return str(data)  # Fallback if structure is weird

        except httpx.HTTPStatusError as e:
            print(f"[Ollama HTTP Error] {e.response.status_code}: {e.response.text}")
            return "Error: I couldn't reach my AI brain."

        except Exception as e:
            print(f"[Ollama Connection Error] {e}")
            return 'Error: Connection to AI failed.'


# ---------------------------------------------------------
# RAG PIPELINE
# ---------------------------------------------------------

async def answer_with_rag(query: str) -> RAGResponse:
    """
    Answers a question using RAG, strictly returning JSON with citations.
    """

    # 1. Retrieve relevant documents
    docs = retrieve(query, limit=5)

    if not docs:
        return RAGResponse(answer='No relevant system events found in the database.', citations=[])

    # 2. Build Context with Explicit IDs
    # We assign IDs so the LLM can reference them accurately.
    pages = [d.page_content for d in docs]
    doc_ids = [d.metadata.get('id', f"doc-{i}") for i, d in enumerate(docs)]

    context = ''
    for i, (text, doc_id) in enumerate(zip(pages, doc_ids)):
        context += f"\n[Document {i+1} | ID: {doc_id}]\n{text}\n---\n"

    # 3. Build Forensic Prompt (Negative Constraints applied)
    prompt = f"""
You are a forensic analysis AI.
Use ONLY the context provided below. Do NOT hallucinate.

Context:
{context}

Question: {query}

Instructions:
1. Analyze the context to answer the question.
2. If the answer is not in the context, say "Not found".
3. Cite the exact Document IDs you used.

OUTPUT FORMAT:
Return ONLY a raw JSON object.
Do NOT use Markdown formatting (no ```json blocks).
Do NOT include conversational filler.

Expected JSON Structure:
{{
  "answer": "The user ran calc.exe at 14:00...",
  "citations": ["network_flow_123...", "process_456..."]
}}
"""

    # 4. Call LLM
    raw_answer = await call_ollama(prompt)

    # 5. Robust Extraction
    data = extract_json(raw_answer)

    if data and 'answer' in data:
        return RAGResponse(
            answer=data['answer'],
            citations=data.get('citations', []),
        )

    # 6. Fallback (If LLM ignores JSON instructions)
    # We return the raw text, but clean it up slightly
    clean_text = raw_answer.replace('```json', '').replace('```', '').strip()
    return RAGResponse(answer=clean_text, citations=[])
