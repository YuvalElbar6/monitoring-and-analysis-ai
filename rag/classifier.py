# rag/describer.py
from __future__ import annotations

import json
from typing import Any

from mcp import ClientSession  # Import this for type hinting

from helper.json_helper import extract_json
from helper.trimmer_helper import trim_result_to_limit
from rag.engine import call_ollama
from rag.retriever import retrieve


async def classify_query_with_rag(user_query: str) -> dict[str, Any]:
    """
    Uses RAG to decide which MCP tool to call.
    Strictly enforces JSON output to prevent parsing errors.
    """

    # 1. Retrieve Context
    try:
        docs = retrieve(user_query, limit=3)
        context = '\n\n---\n\n'.join(d.page_content for d in docs)
    except Exception:
        context = 'No relevant historical context found.'

    # 2. Build Decision Prompt (Negative Constraints Applied)
    prompt = f"""
You are a cybersecurity tool classifier.

Your responsibilities:
- Read the context retrieved by RAG
- Understand the user's intention
- Select EXACTLY ONE tool from the list below
- Produce VALID JSON ONLY

Context:
{context}

User query: "{user_query}"

Available MCP tools:
1) get_running_processes (Args: {{}})
2) get_network_flows (Args: {{ "limit": <int 1-5> }})
3) search_findings (Args: {{ "query": "<string>" }})
4) analyze_processes (Args: {{}})
5) analyze_network (Args: {{}})
6) analyze_services (Args: {{}})
7) analyze_all (Args: {{}})
8) analyze_hardware_spikes (Args: {{"limit": <int 1 - 20>}})
9) analyze_malware (Args: {{"limit": <int 1 - 20>}})
10) none (Args: {{}})

OUTPUT RULES:
1. Return ONLY the raw JSON object.
2. Do NOT use Markdown formatting (no ```json blocks).
3. Do NOT include conversational text (no "Here is the JSON").

Example Output:
{{
  "tool": "get_network_flows",
  "arguments": {{ "limit": 5 }}
}}
"""

    # 3. Get LLM Decision
    # (Renamed from ollama_chat to match your likely import, change back if needed)
    raw_response = await call_ollama(prompt)

    # 4. Parse & Validate using robust helper
    try:
        data = extract_json(raw_response)

        # Validation: Ensure it has the minimum required fields
        if not data or 'tool' not in data:
            print(f"[Classifier] Warning: Invalid JSON structure. Response: {raw_response[:50]}...")
            return {'tool': 'none', 'arguments': {}}

    except Exception as e:
        print(f"[Classifier] JSON Extraction failed: {e}")
        return {'tool': 'none', 'arguments': {}}

    # 5. Safety Clamp for Network Flows
    # Prevents overloading the context window with too many logs
    if data.get('tool') == 'get_network_flows':
        args = data.get('arguments', {})
        limit = args.get('limit', 5)
        try:
            limit = int(limit)
        except (ValueError, TypeError):
            limit = 5

        # Force limit between 1 and 5
        args['limit'] = max(1, min(5, limit))
        data['arguments'] = args

    return data


async def agent_step(client: ClientSession, user_query: str) -> dict[str, str] | None:
    """
    Executes a single reasoning step in the agent loop.

    Steps:
    1. **Decide:** Calls `classify_query_with_rag` to pick a tool.
    2. **Act:** Sends the request to the MCP Server to execute the tool.
    3. **Analyze:** Feeds the raw tool output + user query back to the LLM for a summary.

    Args:
        user_query (str): The user's input.

    Returns:
        Optional[Dict[str, str]]: A dictionary containing the 'final' human-readable answer,
        or None if an error occurred.
    """
    # Step 1: Decide
    decision = await classify_query_with_rag(user_query)
    tool = decision.get('tool')
    args = decision.get('arguments', {})

    print(f"DEBUG: Agent selected tool -> {tool}")

    # Handle case where no tool is needed or found
    if tool == 'none' or not tool:
        response = await call_ollama(f"User asked: {user_query}. I cannot find a specific tool for this.")
        return {'final': response}

    # Step 2: Act (Call Tool)
    try:
        # Note: We rely on the caller's 'async with client' context being active
        result = await client.call_tool(tool, args)
    except Exception as e:
        return {'final': f"Error executing tool '{tool}': {e}"}

    # Extract Data from Result
    # FastMCP results typically store data in 'content' or 'data' attributes
    tool_output = getattr(result, 'content', None) or getattr(result, 'data', None)

    if not tool_output:
        return {'final': 'The tool executed successfully but returned no data.'}

    print('DEBUG: Received tool output. Analyzing...')

    # Trim large datasets to fit into the LLM's context window
    trimmed_output = trim_result_to_limit(tool_output, 1)

    # Step 3: Analyze (Final Answer)
    final_prompt = f"""
You are a cybersecurity analyst.

User query: "{user_query}"
Tool used: {tool}
Arguments: {args}

Tool output Data:
{json.dumps(trimmed_output, indent=2, default=str)}

Based on the data above, provide a concise, human-readable answer to the user.
Highlight any risks or anomalies found.
IMPORTANT:
- ANSWER IN ENGLISH ONLY.
- Do not use any other language.
"""

    analysis = await call_ollama(final_prompt)
    return {'final': analysis}
