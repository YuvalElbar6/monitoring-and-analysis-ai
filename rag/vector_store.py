# rag/vector_store.py
from langchain_community.vectorstores import Chroma
from langchain_text_splitters import RecursiveCharacterTextSplitter
from os_env import CHROMA_DIR
from rag.embeddings import get_embeddings

# Create embedder
embeddings = get_embeddings()

# Initialize DB (or load if exists)
vector_store = Chroma(
    embedding_function=embeddings,
    persist_directory=CHROMA_DIR
)

# Retriever for queries (used by agents + MCP)
retriever = vector_store.as_retriever(search_kwargs={"k": 5})


def add_documents(text_list: list[str]):
    splitter = RecursiveCharacterTextSplitter(chunk_size=500)
    chunks = splitter.split_text("\n".join(text_list))

    vector_store.add_texts(chunks)
    vector_store.persist()
