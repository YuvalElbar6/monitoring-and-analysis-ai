from dotenv import load_dotenv
import os

load_dotenv()

EVENTS_DIR = os.getenv("EVENTS_DIR", "./events")
OUTPUT_FILE_NAME = os.getenv("OUTPUT_FILE_NAME", "network.jsonl")
CHROMA_DIR = os.getenv("CHROMA_DIR", "./vector_db")
BASE_OLLAMA_URL = os.getenv("OLLAMA_BASE_URL","http://127.0.0.1:11434/v1")
SERVER_HOST = os.getenv("SEVER_HOST","127.0.0.1")
SERVER_PORT = os.getenv("SERVER_PORT", 8080)
MCP_SERVER_URL = f"http://{SERVER_HOST}:{SERVER_PORT}/mcp"