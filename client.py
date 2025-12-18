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
from typing import Any

from fastmcp.client import Client
from fastmcp.client.transports import StreamableHttpTransport

from os_env import MCP_SERVER_URL
from rag.classifier import agent_step


# ---------------------------------------------------------
# CONFIGURATION & CLIENT SETUP
# ---------------------------------------------------------

# Establish connection config for the MCP Server
transport = StreamableHttpTransport(
    url=MCP_SERVER_URL,
)

client = Client(transport=transport)


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
            result_dict = await agent_step(client, user_input)

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
