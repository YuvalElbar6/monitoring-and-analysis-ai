from typing import List
from pydantic_ai import Agent, ModelRetry, RunContext
from pydantic_ai.providers.ollama import OllamaProvider
from os_env import BASE_OLLAMA_URL
from rag.vector_store import retriever


class RAGResponse(ModelRetry):
    answer: str
    citations: List[str]


rag_agent = Agent(
    model="ollama:mistral",
    model_settings=OllamaProvider(
        base_url=BASE_OLLAMA_URL
    ),
    output_type=RAGResponse,
    system_prompt=[
        "You are a forensic analysis AI.",
        "Use retrieved logs, network flows, and processes.",
        "Always cite your evidence."
    ],
)


@rag_agent.system_prompt
def system_prompt(ctx):
    return (
        "You are a forensic analysis AI. "
        "You answer questions based only on the retrieved security logs. "
        "Always cite the events you used."
    )


@rag_agent.tool
def retrieve_context(ctx: RunContext, query: str) -> List[str]:
    docs = retriever.invoke(query)
    return [d.page_content for d in docs]

def rag_search(query: str) -> List[str]:
    """
    Raw RAG search without reasoning.
    Returns the raw document chunks.
    """
    docs = retriever.invoke(query)
    return [d.page_content for d in docs]

def answer_with_rag(query: str) -> RAGResponse:
    return rag_agent.run(
        f"Analyze this query using retrieval: {query}"
    )