from mcp_server.server import app

if __name__ == "__main__":
    print("Starting MCP server on localhost:8000 ...")
    app.run(transport="http")