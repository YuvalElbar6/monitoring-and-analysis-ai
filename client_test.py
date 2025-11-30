import asyncio
from fastmcp.client import Client
from fastmcp.client.transports import FastMCPTransport

# Import your actual server instance
from mcp_server.server import app


async def main():
    # Create a client bound directly to your in-process FastMCP server
    transport = FastMCPTransport(mcp=app)

    async with Client(transport=transport) as mcp:
        print("\n--- LIST TOOLS ---")
        tools = await mcp.list_tools()
        for t in tools:
            print(" •", t.name)

        print("\n--- PING ---")
        res = await mcp.call_tool("ping", {})
        print("Ping:", res)

        print("\n--- GET PROCESSES ---")
        res = await mcp.call_tool("get_running_processes", {})
        print("Process count:", len(res.data["processes"]))

        print("\n--- GET NETWORK FLOWS ---")
        res = await mcp.call_tool(
            "get_network_flows",
            {"query": {"duration_minutes": 1}}
        )
        print("Flows:", len(res.data["flows"]))

        print("\n--- RAG SEARCH ---")
        res = await mcp.call_tool(
            "search_findings",
            {"query": {"query": "login failure"}}
        )
        print("RAG results:", res.data["results"])

    print("\nClient closed.")


if __name__ == "__main__":
    asyncio.run(main())
