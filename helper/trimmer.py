def trim_result_to_limit(data, limit=1):
    """
    Safely trims MCP tool outputs:
    - list → first N elements
    - dict → recursively trims lists inside
    - nested dicts → handled recursively
    - primitives → returned unchanged
    """

    if data is None:
        return None

    try:
        limit = int(limit)
    except:
        limit = 1

    limit = max(1, min(5, limit))

    # Case 1: data is a list
    if isinstance(data, list):
        return [trim_result_to_limit(x, limit) for x in data[:limit]]

    # Case 2: data is a dictionary
    if isinstance(data, dict):
        trimmed = {}
        for key, val in data.items():
            if isinstance(val, list):
                trimmed[key] = [trim_result_to_limit(x, limit) for x in val[:limit]]
            elif isinstance(val, dict):
                trimmed[key] = trim_result_to_limit(val, limit)
            else:
                trimmed[key] = val  # primitive
        return trimmed

    # Case 3: primitive (int, str, float, None, etc.)
    return data
