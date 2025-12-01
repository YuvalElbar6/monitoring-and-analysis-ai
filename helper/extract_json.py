import json


def extract_json(raw: str):
    raw = raw.strip()

    # Remove ```json ... ``` OR ``` ... ```
    if raw.startswith("```"):
        raw = raw.strip("`")
        # Remove json tag if present
        raw = raw.replace("json", "", 1).strip()

    return json.loads(raw)