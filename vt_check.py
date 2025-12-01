import asyncio
import httpx
import hashlib
from os_env import MB_URL, VT_API_KEY, URLHAUS_URL, ABUSEIPDB_KEY
from rag.engine import answer_with_rag


# ----------------------------------------------------
# Utility: SHA256 hashing
# ----------------------------------------------------
def calc_sha256(file_path: str) -> str | None:
    try:
        with open(file_path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except:
        return None


# ----------------------------------------------------
# MalwareBazaar lookup (no API key required)
# ----------------------------------------------------
async def lookup_malwarebazaar(sha256: str):
    payload = {"query": "get_info", "hash": sha256}

    async with httpx.AsyncClient() as client:
        resp = await client.post(MB_URL, data=payload)
        if resp.status_code != 200:
            return {"found": False}

        data = resp.json()
        if data.get("query_status") != "ok":
            return {"found": False}

        info = data["data"][0]
        return {
            "found": True,
            "signature": info.get("signature"),
            "file_type": info.get("file_type"),
            "tags": info.get("tags", [])
        }


# ----------------------------------------------------
# VirusTotal lookup (optional)
# ----------------------------------------------------
async def lookup_virustotal(sha256: str):
    if not VT_API_KEY:
        return {"found": False, "reason": "missing_api_key"}

    headers = {"x-apikey": VT_API_KEY}

    async with httpx.AsyncClient() as client:
        resp = await client.get(f"https://www.virustotal.com/api/v3/files/{sha256}", headers=headers)

        if resp.status_code == 404:
            return {"found": False}

        data = resp.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]

        return {
            "found": True,
            "malicious": stats["malicious"],
            "suspicious": stats["suspicious"],
            "harmless": stats["harmless"]
        }


# ----------------------------------------------------
# URLHaus (malicious URLs/domains)
# ----------------------------------------------------
async def lookup_urlhaus(sha256: str):
    async with httpx.AsyncClient() as client:
        resp = await client.post(URLHAUS_URL + "payload/", data={"sha256_hash": sha256})

        if resp.status_code != 200:
            return {"found": False}

        data = resp.json()
        if data.get("query_status") != "ok":
            return {"found": False}

        return {
            "found": True,
            "urls": [x["url"] for x in data.get("payloads", [])]
        }


# ----------------------------------------------------
# Main function: full threat-intel scan
# ----------------------------------------------------
async def scan_file_rag_intel(file_path: str):
    sha256 = calc_sha256(file_path)
    if not sha256:
        return {"error": "Cannot read file"}

    # Perform all lookups in parallel (non-blocking)
    mb, vt, uh = await asyncio.gather(
        lookup_malwarebazaar(sha256),
        lookup_virustotal(sha256),
        lookup_urlhaus(sha256)
    )

    # Combine raw intel
    combined = {
        "sha256": sha256,
        "malwarebazaar": mb,
        "virustotal": vt,
        "urlhaus": uh,
    }

    # Generate human summary using RAG
    rag_query = f"""
File hash: {sha256}
MalwareBazaar: {mb}
VirusTotal: {vt}
URLHaus: {uh}

Explain:
1. Whether the file is likely malicious
2. Why
3. What the threat might be
4. What actions a normal user should take
"""

    explanation = await answer_with_rag(rag_query)

    return {
        "intel": combined,
        "explanation": explanation.answer
    }
