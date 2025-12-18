# analysis.py
"""
Cross-Platform Security Analysis Engine
=======================================

This module contains the core logic for evaluating security risks in:
1. System Processes (e.g., CPU abuse, suspicious paths)
2. Network Flows (e.g., data exfiltration, bad protocols)
3. Service Events (e.g., crashes, critical errors)

It is designed to be pure Python, self-contained, and safe for any OS (Windows/Linux/Mac).
"""
from __future__ import annotations

import json
from typing import Any

# ============================================================
# HELPERS
# ============================================================


def normalize_str(x: Any) -> str:
    """Safely converts any input to a string, handling NoneTypes."""
    if x is None:
        return ''
    try:
        return str(x)
    except Exception as e:
        print(f"Error normalizing string: {e}")
        return ''


def safe_get(d: dict, key: str, default=None):
    """Safely retrieves a value from a dictionary."""
    return d.get(key, default) if isinstance(d, dict) else default


def _parse_input(data: dict[str, Any] | str) -> dict[str, Any]:
    """
    Internal Helper: Ensures input is a Dictionary.
    If input is a JSON string (from server.py), it parses it.
    """
    if isinstance(data, str):
        try:
            return json.loads(data)
        except json.JSONDecodeError:
            print('[Analysis] Error: Could not decode JSON string.')
            return {}
    return data if isinstance(data, dict) else {}


# ============================================================
# PROCESS ANALYZER (CROSS PLATFORM)
# ============================================================

ROOTS = ['root', 'system', 'nt authority\\system']


def analyze_process(proc: dict[str, Any] | str) -> dict[str, Any]:
    """
    Evaluates a running process for potential security risks.

    Checks for:
    - Executables running from temporary folders (often malware).
    - Processes with no executable path (hidden/kernel threads).
    - High CPU/Memory usage (crypto miners, runaway processes).
    - Unexpected network connections.

    Args:
        proc (dict | str): The raw process event data.

    Returns:
        dict: Analysis result containing 'risk_score' (0-10) and 'reasons'.
    """
    # Normalize input (Handle JSON string if needed)
    proc = _parse_input(proc)

    score = 0
    reasons = []

    exe = normalize_str(proc.get('exe'))
    name = normalize_str(proc.get('name'))
    username = normalize_str(proc.get('username'))
    connections = proc.get('connections', [])

    # -----------------------------
    # 1. Executable Path Analysis
    # -----------------------------

    if not exe:
        score += 2
        reasons.append('Process has no executable path (often hidden or kernel thread).')
    else:
        # Suspicious temp-like dirs (cross-platform)
        suspicious_roots = ['tmp', 'private', 'cache', 'shm', 'var/tmp', 'appdata\\local\\temp']

        lower_exe = exe.lower()
        if any(part in lower_exe for part in suspicious_roots):
            score += 2
            reasons.append(f"Executable located in suspicious directory: {exe}")

        # Path too long (Buffer overflow attempts or obfuscation)
        if len(exe) > 260:
            score += 1
            reasons.append('Executable path unusually long, may indicate obfuscation.')

    # -----------------------------
    # 2. CPU / Memory Abuse
    # -----------------------------
    cpu = proc.get('cpu_percent', 0)
    mem = proc.get('memory_percent', 0)

    if cpu > 50:
        score += 2
        reasons.append('High CPU usage (potential mining/loop).')
    elif cpu > 20:
        score += 1
        reasons.append('Elevated CPU usage.')

    if mem > 20:
        score += 2
        reasons.append('High memory usage.')
    elif mem > 10:
        score += 1
        reasons.append('Elevated memory usage.')

    # -----------------------------
    # 3. Suspicious User Context
    # -----------------------------
    if username and username.lower() in ROOTS:
        if cpu > 10 or mem > 10:
            score += 2
            reasons.append('Privileged system process with unusual resource usage.')

    # -----------------------------
    # 4. Network Connections
    # -----------------------------
    if isinstance(connections, list):
        for conn in connections:
            remote = conn.get('remote_address')
            status = normalize_str(conn.get('status')).lower()

            if remote and status not in ['established', 'listen', 'none', '']:
                score += 1
                reasons.append(f"Unexpected remote connection state: {status} -> {remote}")

    return {
        'name': name,
        'exe': exe,
        'username': username,
        'risk_score': score,
        'reasons': reasons,
    }


# ============================================================
# NETWORK FLOW ANALYZER
# ============================================================

def analyze_network_flow(flow: dict[str, Any] | str) -> dict[str, Any]:
    """
    Evaluates network packets for anomalies.

    Checks for:
    - Unusually large packets (potential exfiltration).
    - Dangerous protocols (ICMP tunneling, Raw sockets).
    - Connections to non-private (public) IP addresses.

    Args:
        flow (dict | str): The raw network event.

    Returns:
        dict: Risk assessment with score and reasons.
    """
    flow = _parse_input(flow) or {}

    score = 0
    reasons = []

    # Handle different IP key names if they vary
    src = flow.get('src') or flow.get('src_ip')
    dst = flow.get('dst') or flow.get('dst_ip')

    # Check length/size
    size = flow.get('length', 0) or flow.get('packet_size', 0)

    protocol = normalize_str(flow.get('proto', '') or flow.get('protocol', '')).lower()
    summary = normalize_str(flow.get('summary', ''))

    # Suspicious large packets
    if size > 2000:
        score += 1
        reasons.append(f"Unusually large packet size: {size} bytes")

    # Dangerous protocols
    bad_protocols = ['icmp', 'raw', 'gre']
    if protocol in bad_protocols:
        score += 1
        reasons.append(f"Suspicious protocol detected: {protocol}")

    # Public IP communication check (Simple heuristic)
    # Assumes 192.168.x.x, 10.x.x.x, 172.16-31.x.x are private.
    if dst:
        dst_str = str(dst)
        is_private = (
            dst_str.startswith('10.') or
            dst_str.startswith('192.168.') or
            dst_str.startswith('127.') or
            dst_str.startswith('fe80:')
        )
        if not is_private and dst_str != '255.255.255.255':
            score += 1
            reasons.append(f"Connection to external/public IP: {dst}")

    return {
        'src': src,
        'dst': dst,
        'protocol': protocol,
        'size': size,
        'summary': summary,
        'risk_score': score,
        'reasons': reasons,
    }


# ============================================================
# SERVICE EVENT ANALYZER
# ============================================================

def analyze_service_event(event: dict[str, Any] | str) -> dict[str, Any]:
    """
    Evaluates system logs and service changes.

    Checks for:
    - Critical error levels.
    - Known Windows Event IDs for service crashes (7031, 7034).
    """
    event = _parse_input(event)

    score = 0
    reasons = []

    service_name = event.get('service_name') or event.get('name')
    event_id = event.get('event_id')
    level = normalize_str(event.get('level', 'info')).lower()

    if level in ['error', 'critical', 'fatal']:
        score += 2
        reasons.append(f"Service generated a {level} event.")

    # Windows-specific but safe (ignored if missing)
    if str(event_id) in ['7034', '7031']:
        score += 1
        reasons.append(f"Service crashed unexpectedly (Event ID {event_id}).")

    return {
        'service': service_name,
        'event_id': event_id,
        'risk_score': score,
        'reasons': reasons,
    }


# ============================================================
# BATCH ANALYSIS HELPERS
# ============================================================

def analyze_processes(process_list: list[Any]) -> list[dict[str, Any]]:
    """Batch processes multiple process events."""
    return [analyze_process(p) for p in process_list]


def analyze_network_flows(flow_list: list[Any]) -> list[dict[str, Any]]:
    """Batch processes multiple network events."""
    return [analyze_network_flow(f) for f in flow_list]


def analyze_service_events(event_list: list[Any]) -> list[dict[str, Any]]:
    """Batch processes multiple service events."""
    return [analyze_service_event(e) for e in event_list]


# ============================================================
# UNIVERSAL ENTRYPOINT
# ============================================================

EVENT_TO_TYPE = {
    'process': analyze_process,
    'network_flow': analyze_network_flow,
    'service_event':  analyze_service_event,
}


def analyze_event(event: dict[str, Any] | str) -> dict[str, Any]:
    """
    Universal Router: Auto-detects the event type and runs the correct analyzer.

    Args:
        event: The event data (Dict or JSON string).

    Returns:
        dict: The analysis result.
    """
    event = _parse_input(event)
    etype = event.get('type') or event.get('event_type')

    if etype in EVENT_TO_TYPE:

        return EVENT_TO_TYPE[etype](event)

    return {
        'risk_score': 0,
        'reasons': ['Unknown event type, no analysis performed.'],
    }
