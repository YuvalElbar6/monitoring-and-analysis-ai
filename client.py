# client.py
"""
MCP Agent Client
================

This module serves as the "Brain" of the System Intelligence Platform.
It connects to the central MCP Server to execute monitoring tools and uses
a local Large Language Model (Ollama) to reason about the results.

Key Components:
- **RAG Classifier:** Determines which tool to use based on user queries and historical context.
- **MCP Client:** Connects to the server via Streamable HTTP to execute tools.
- **Agent Loop:** Manages the cycle of Thinking -> Acting -> Analyzing.
"""
from __future__ import annotations

import asyncio
import json
from typing import Any

import httpx
from fastmcp.client import Client
from fastmcp.client.transports import StreamableHttpTransport

from helper.json_helper import extract_json
from helper.trimmer_helper import trim_result_to_limit
from os_env import BASE_OLLAMA_URL
from os_env import MCP_SERVER_URL
from rag.retriever import retrieve
# Internal helpers


# ---------------------------------------------------------
# CONFIGURATION & CLIENT SETUP
# ---------------------------------------------------------

# Establish connection config for the MCP Server
transport = StreamableHttpTransport(
    url=MCP_SERVER_URL,
)

client = Client(transport=transport)


# ---------------------------------------------------------
# OLLAMA INTERFACE
# ---------------------------------------------------------

async def ollama_chat(prompt: str, model: str = 'gemma3:4b') -> str:
    """
    Sends a text prompt to the local Ollama instance and returns the generated response.

    Args:
        prompt (str): The instructions or query for the LLM.
        model (str, optional): The model tag to use. Defaults to 'gemma3:4b'.

    Returns:
        str: The content of the LLM's response.

    Raises:
        httpx.HTTPStatusError: If the Ollama server returns a 4xx/5xx error.
    """
    url = f"{BASE_OLLAMA_URL}/api/chat"
    payload = {
        'model': model,
        'messages': [{'role': 'user', 'content': prompt}],
        'stream': False,
    }

    async with httpx.AsyncClient() as c:
        try:
            # We use a 60s timeout to allow the LLM time to "think" on complex queries
            resp = await c.post(url, json=payload, timeout=60.0)
            resp.raise_for_status()
            return resp.json()['message']['content']
        except Exception as e:
            print(f"[Ollama Error] Could not connect to AI: {e}")
            return 'I encountered an error trying to think about that.'


# ---------------------------------------------------------
# RAG CLASSIFICATION LOGIC
# ---------------------------------------------------------

async def classify_query_with_rag(user_query: str) -> dict[str, Any]:
    """
    Uses RAG (Retrieval-Augmented Generation) to decide which MCP tool
    is best suited for the user's request.

    Process:
    1. Retrieval: Fetches relevant historical context from the Vector DB.
    2. Prompting: Constructs a prompt with the user query, context, and valid tool schemas.
    3. JSON Parsing: Forces the LLM to output structured JSON defining the tool and arguments.

    Args:
        user_query (str): The natural language query from the user.

    Returns:
        Dict[str, Any]: A dictionary containing:
            - 'tool' (str): The name of the tool to call (e.g., 'get_network_flows').
            - 'arguments' (dict): A dictionary of arguments for that tool.
    """
    # 1. Retrieve Context
    try:
        docs = retrieve(user_query)
        context = '\n\n---\n\n'.join(d.page_content for d in docs)
    except Exception:
        context = 'No relevant historical context found.'

    # 2. Build Decision Prompt
    prompt = f"""
You are a cybersecurity tool classifier.

Your responsibilities:
- Read the context retrieved by RAG
- Understand the user's intention
- Select EXACTLY ONE tool from the list below
- Produce VALID JSON ONLY
- Follow every argument schema exactly
- If a tool has a limit parameter, it MUST be an integer between 1 and 5

====================
Context:
{context}
====================

User query: "{user_query}"

Available MCP tools and their argument schemas:

1) get_running_processes
   Arguments: {{}}

2) get_network_flows
   Arguments: {{ "limit": <integer 1-5>, "duration_minutes": <integer or null> }}

3) search_findings
   Arguments: {{ "query": "<string>" }}

4) analyze_processes
   Arguments: {{}}

5) analyze_network
   Arguments: {{}}

6) analyze_services
   Arguments: {{}}

7) analyze_all
   Arguments: {{}}

8) none
   Arguments: {{}}

Output Rules:
- ALWAYS return valid JSON
- NEVER return explanations
- If unsure, use "none"

Return ONLY the JSON dictionary.
"""

    # 3. Get LLM Decision
    raw_response = await ollama_chat(prompt)

    # 4. Parse & Validate
    try:
        data = extract_json(raw_response)
    except Exception as e:
        print(f"[Classifier] JSON Extraction failed: {e}")
        return {'tool': 'none', 'arguments': {}}

    # Safety Clamp: Ensure 'limit' is never too high to prevent overloading the prompt
    if data.get('tool') == 'get_network_flows':
        args = data.get('arguments', {})
        limit = args.get('limit', 5)
        try:
            limit = int(limit)
        except (ValueError, TypeError):
            limit = 5
        args['limit'] = max(1, min(5, limit))
        data['arguments'] = args

    return data


# ---------------------------------------------------------
# AGENT EXECUTION LOOP
# ---------------------------------------------------------

async def agent_step(user_query: str) -> dict[str, str] | None:
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
        response = await ollama_chat(f"User asked: {user_query}. I cannot find a specific tool for this.")
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
"""

    analysis = await ollama_chat(final_prompt)
    return {'final': analysis}


# ---------------------------------------------------------
# HELPER FUNCTIONS
# ---------------------------------------------------------

def pretty_print_tools(tools: list[Any]):
    """
    Prints a formatted, readable list of available MCP tools to the console.

    Args:
        tools (List[Any]): A list of tool objects returned by `client.list_tools()`.
    """
    print('\n🛠️  Available MCP Tools:\n')

    for t in tools:
        name = t.name
        desc = t.description or '(no description)'
        schema = getattr(t, 'inputSchema', {}) or {}

        print(f"• {name}")
        print(f"    Description: {desc}")

        props = schema.get('properties', {})
        if not props:
            print('    Arguments: None\n')
            continue

        print('    Arguments:')
        for arg_name, info in props.items():
            typ = info.get('type', 'object')
            default = info.get('default')
            print(f"      - {arg_name} ({typ})", end='')
            if default is not None:
                print(f" [default: {default}]")
            print()
        print()


# ---------------------------------------------------------
# MAIN ENTRY POINT
# ---------------------------------------------------------

async def run_agent():
    """
    The main interactive CLI loop.

    - Connects to the MCP Server.
    - Lists available tools.
    - Enters a REPL (Read-Eval-Print Loop) for user queries.
    """
    print('🔌 Connecting to MCP server...')

    # Initial connection to list capabilities
    async with client:
        try:
            tools = await client.list_tools()
            pretty_print_tools(tools)
        except Exception as e:
            print(f"❌ Could not connect to MCP Server at {MCP_SERVER_URL}")
            print(f"   Error: {e}")
            return

    print("✅ Agent ready. Type your query below (or '/exit' to quit).")

    while True:
        try:
            user_input = input('\n>>> ').strip()
        except (EOFError, KeyboardInterrupt):
            break

        if not user_input or user_input.lower() == '/exit':
            break

        print('⏳ Thinking...')

        # Re-connect for the specific transaction
        # (FastMCP HTTP transport is stateless, so we connect per request)
        async with client:
            result_dict = await agent_step(user_input)

        if not result_dict:
            print('⚠️  No response generated.')
            continue

        # result_dict is a Python dictionary, NOT a JSON string.
        final_answer = result_dict.get('final')

        if final_answer:
            print(f"\n🤖 Agent Report:\n{'-'*60}\n{final_answer}\n{'-'*60}")
        else:
            print(f"\n⚠️  Debug Output: {result_dict}")


if __name__ == '__main__':
    try:
        asyncio.run(run_agent())
    except KeyboardInterrupt:
        print('\n👋 Goodbye!')
