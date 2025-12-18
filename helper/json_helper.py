# helper/json_helper.py
from __future__ import annotations

import json
import re
from typing import Any


def extract_json(text: str) -> dict[str, Any]:
    """
    Robustly extracts a JSON object from a string, handling Markdown code blocks
    and conversational text from LLMs.
    """
    if not text:
        return {}

    # 1. Try strict parsing first (fastest)
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # 2. Regex Search: Find content between the first '{' and the last '}'
    # re.DOTALL ensures '.' matches newlines inside the JSON
    match = re.search(r'(\{.*\})', text, re.DOTALL)

    if match:
        json_candidate = match.group(1)
        try:
            return json.loads(json_candidate)
        except json.JSONDecodeError:
            # If parsing fails (e.g., bad escaping), log it but don't crash
            # print(f"[JSON Helper] Regex found candidate but parsing failed: {json_candidate[:50]}...")
            pass

    # 3. Fallback: Return empty if nothing valid is found
    return {}
