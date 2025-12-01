def trim_result_to_limit(data, limit=5):
    """
    Recursively trims ANY structure (dict, list, tuple, Pydantic models)
    so that ALL lists are trimmed to at most `limit` items.
    Returns a NEW safe structure.
    """

    # primitive (str, int, etc.)
    if isinstance(data, (str, int, float, bool)) or data is None:
        return data

    # handle pydantic model
    if hasattr(data, "model_dump"):
        return trim_result_to_limit(data.model_dump(), limit)

    # handle dict-like object
    if hasattr(data, "dict"):
        return trim_result_to_limit(data.dict(), limit)

    # handle list
    if isinstance(data, list):
        return [trim_result_to_limit(item, limit) for item in data[:limit]]

    # handle tuple
    if isinstance(data, tuple):
        return tuple(trim_result_to_limit(item, limit) for item in data[:limit])

    # handle dict
    if isinstance(data, dict):
        return {
            key: trim_result_to_limit(value, limit)
            for key, value in data.items()
        }

    # fallback
    try:
        return str(data)
    except:
        return "<unserializable>"
