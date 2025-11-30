from dotenv import load_dotenv
import os

load_dotenv()

EVENTS_DIR = os.getenv("EVENTS_DIR", "./events")
OUTPUT_FILE_NAME = os.getenv("OUTPUT_FILE_NAME", "network.jsonl")
CHROMA_DIR = os.getenv("CHROMA_DIR", "./vector_db")
BASE_OLLAMA_URL = os.getenv("OLLAMA_BASE_URL","http://127.0.0.1:11434")