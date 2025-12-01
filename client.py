# client.py
import asyncio
import json
import httpx
from fastmcp.client import Client
from fastmcp.client.transports import StreamableHttpTransport

from helper.trimmer import trim_result_to_limit
from os_env import MCP_SERVER_URL, BASE_OLLAMA_URL
from rag.retriever import retrieve


# ---------------------------------------------------------
# MCP CLIENT (STREAMABLE HTTP)
# ---------------------------------------------------------

transport = StreamableHttpTransport(
    url=MCP_SERVER_URL,       # Example: "http://127.0.0.1:8080/mcp"
)

client = Client(transport=transport)


# ---------------------------------------------------------
# OLLAMA CHAT (your existing RAG/agent brain)
# ---------------------------------------------------------

async def ollama_chat(prompt: str, model="mistral:latest"):
    url = f"{BASE_OLLAMA_URL}/api/chat"
    payload = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "stream": False
    }
    async with httpx.AsyncClient() as c:
        resp = await c.post(url, json=payload)
        resp.raise_for_status()
        return resp.json()["message"]["content"]


# ---------------------------------------------------------
# AGENT LOGIC
# ---------------------------------------------------------
async def classify_query_with_rag(user_query: str):
    """
    Use RAG + Mistral to determine which MCP tool to call.
    Ensures:
    - Valid JSON output
    - Valid argument schemas per tool
    - limit field always <= 5
    """
    # -------- Retrieve context -------
    docs = retrieve(user_query)
    context = "\n\n---\n\n".join(d.page_content for d in docs)

    # -------- Classification Prompt --------
    prompt  = f"""
You are a cybersecurity tool classifier.

Your responsibilities:
- Read the context retrieved by RAG
- Understand the user's intention
- Select EXACTLY ONE tool from the list below
- Produce VALID JSON ONLY
- Follow every argument schema exactly
- If a tool has a limit parameter, it MUST be an integer between 1 and 5
- If the tool requires no arguments, you MUST return an empty object

====================
Context:
{context}
====================

User query: "{user_query}"

Available MCP tools and their argument schemas
(you MUST follow these schemas exactly):

1) get_running_processes  
   Arguments MUST be:
   {{}}

2) get_network_flows  
   Arguments MUST be:
   {{
      "limit": <integer between 1 and 5>,
      "duration_minutes": <integer or null>
   }}

3) search_findings  
   Arguments MUST be:
   {{
      "query": "<string>"
   }}

4) analyze_processes  
   Arguments MUST be:
   {{}}

5) analyze_network  
   Arguments MUST be:
   {{}}

6) analyze_services  
   Arguments MUST be:
   {{}}

7) analyze_all  
   Arguments MUST be:
   {{}}

8) none  
   Arguments MUST be:
   {{}}

====================

Output Rules:
- ALWAYS return valid JSON
- NEVER return explanations or text outside the JSON
- NEVER add fields that are not listed
- NEVER omit required fields
- If you are not confident which tool to use, return:
  {{
     "tool": "none",
     "arguments": {{}}
  }}

Return ONLY the JSON dictionary.
"""


    # -------- Call Ollama -------
    raw = await ollama_chat(prompt)

    # -------- JSON parse & cleanup --------
    import json
    try:
        data = json.loads(raw)
    except:
        return {"tool": "none", "arguments": {}}

    # Safety clamp: ensure limit ≤ 5
    if data.get("tool") == "get_network_flows":
        args = data.get("arguments", {})
        limit = args.get("limit", 5)
        args["limit"] = max(1, min(5, int(limit)))
        data["arguments"] = args

    return data


async def agent_step(user_query: str):

    # 1. RAG classification
    decision = await classify_query_with_rag(user_query)
    tool = decision.get("tool")
    args = decision.get("arguments", {})

    # 2. If RAG says "none", just ask the LLM
    if tool == "none":
        return {
            "final": await ollama_chat(
                f"User asked: {user_query} but no tool matched."
            )
        }

    # 3. Execute tool
    result = await client.call_tool(tool, args)
    print("Gotten the wanted result")

    if not result or not result.data:
        print("Gotten no data")
        return None
    
    trimmed = trim_result_to_limit(result.data, 1)
    print("Trimmed the data")
    print(user_query, trimmed)
    # 4. Give tool result to LLM for final answer
    final_prompt = f"""
You are a cybersecurity analyst.

User query:
{user_query}

Tool used: {tool}
Arguments: {args}

Tool output:
{json.dumps(trimmed, indent=2)}

Provide a final human-readable answer.
"""

    analysis = await ollama_chat(final_prompt)

    return {"final": analysis}

# ---------------------------------------------------------
# MAIN LOOP
# ---------------------------------------------------------

async def run_agent():
    print("🔌 Connecting to MCP server...")

    async with client:
        print("Available tools:", await client.list_tools())
    print()

    while True:
        user = input(">>> ").strip()
        if user == "/exit":
            break
        
        print("Trying to run")
    
        async with client:
            final = await agent_step(user)

        if not final:
            print("Couldn't find final!")
        try:
            print(json.loads(final)["final"])
        except:
            print(final)


if __name__ == "__main__":
    asyncio.run(run_agent())
