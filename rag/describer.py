# rag/describer.py
from __future__ import annotations

from helper.json_helper import extract_json
from rag.engine import call_ollama
from rag.retriever import retrieve_filtered  # <--- Use filtered retrieval


async def describe_process_with_rag(process_name: str, exe: str, username: str) -> str:
    """
    Uses RAG to describe the process based on retrieved system evidence.
    Robustly handles cases where LLM returns plain text instead of JSON.
    """

    query = f"process '{process_name}' running from {exe}"

    # 1. Retrieve Context (FILTERED)
    # We only look for 'process' events so network packets don't confuse the AI.
    try:
        docs = retrieve_filtered(query, type_filter='process', limit=3)
        context = '\n\n---\n\n'.join([d.page_content for d in docs])
    except Exception:
        context = ''

    prompt = f"""
You are a security analyst.

Context about past system activity:
{context}

Task: Describe the process "{process_name}" (running as "{username}") in 1-3 sentences.

Requirements:
- Explain what this program usually does.
- Mention if it is built-in, third-party, or unknown.
- State if the context shows valid or suspicious behavior.
- If context is empty, give a generic definition of the process name.

OUTPUT FORMAT:
Return ONLY a raw JSON object.
Do NOT use Markdown formatting (no ```json blocks).
Do NOT add conversational text (no "Here is the response").

Example Output:
{{
    "description": "Notepad.exe is a built-in Windows text editor. It is generally benign."
}}
"""

    try:
        # 3. Call LLM
        result_text = await call_ollama(prompt)

        # 4. Try to parse JSON
        data = extract_json(result_text)

        # 5. Fallback Logic
        # If the LLM replied with plain text (e.g., "Powershell is a tool..."),
        # extract_json might return empty. We just return the raw text in that case.
        if not data or 'description' not in data:
            clean_text = result_text.strip()
            # If it wrapped it in code blocks blindly, strip them
            if clean_text.startswith('```'):
                clean_text = clean_text.strip('`json \n')
            return clean_text

        return data['description']

    except Exception as e:
        print(f"[RAG Describer] Error: {e}")
        return f"Process {process_name} detected (Analysis unavailable)."
