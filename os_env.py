from __future__ import annotations

import os

from dotenv import load_dotenv

load_dotenv()

EVENTS_DIR = os.getenv('EVENTS_DIR', './events')
OUTPUT_FILE_NAME = os.getenv('OUTPUT_FILE_NAME', 'network.jsonl')
CHROMA_DIR = os.getenv('CHROMA_DIR', './vector_db')
BASE_OLLAMA_URL = os.getenv('OLLAMA_BASE_URL', 'http://127.0.0.1:11434')
SERVER_HOST = os.getenv('SEVER_HOST', '127.0.0.1')
SERVER_PORT = os.getenv('SERVER_PORT', 8080)
# No API key required — just a URL
MB_URL = os.getenv(
    'MB_URL',
    'https://mb-api.abuse.ch/api/v1/',
)


URLHAUS_URL = os.getenv(
    'URLHAUS_URL',
    'https://urlhaus-api.abuse.ch/v1/',
)


# ----------------------------------------------------
# AbuseIPDB API key (optional)
# ----------------------------------------------------
ABUSEIPDB_KEY = os.getenv('ABUSEIPDB_KEY', None)

# ----------------------------------------------------
# VirusTotal API key (optional)
# ----------------------------------------------------
VT_API_KEY = os.getenv('VT_API_KEY', None)

MCP_SERVER_URL = f"http://{SERVER_HOST}:{SERVER_PORT}/mcp"
