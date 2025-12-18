from __future__ import annotations

from typing import Any


class RAGResponse:
    def __init__(self, answer: str, citations: list[str]):
        self.answer = answer
        self.citations = citations

    def dict(self) -> dict[str, Any]:
        return {
            'answer': self.answer,
            'citations': self.citations,
        }
