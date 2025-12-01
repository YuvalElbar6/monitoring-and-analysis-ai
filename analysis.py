# analysis_engine.py
"""
Cross-platform security analysis engine for processes,
network flows, and service events.

This file is completely self-contained and safe for:
- Windows
- Linux
- macOS
- Containers / WSL / Pods
"""
from __future__ import annotations

from typing import Any


# ============================================================
# HELPERS
# ============================================================

def normalize_str(x: Any) -> str:
    if not x:
        return ''
    try:
        return str(x)
    except Exception as e:
        print(f"Couldn't parse the reason is: {e}")
        return ''


def safe_get(d: dict, key: str, default=None):
    return d.get(key, default) if isinstance(d, dict) else default


# ============================================================
# PROCESS ANALYZER (CROSS PLATFORM)
# ============================================================

ROOTS = ['root', 'system', 'nt authority\\system']


def analyze_process(proc: dict[str, Any]) -> dict[str, Any]:
    """
    Takes a single UnifiedEvent 'process' dict and evaluates risk.
    """

    score = 0
    reasons = []

    details = proc.get('details', {})
    exe = normalize_str(details.get('exe'))
    name = normalize_str(details.get('name'))
    username = normalize_str(details.get('username'))
    connections = details.get('connections', [])

    # -----------------------------
    # 1. Executable Path Analysis
    # -----------------------------

    if not exe:
        score += 2
        reasons.append(
            'Process has no executable path (often hidden or kernel thread).',
        )
    else:
        # Suspicious temp-like dirs (cross-platform)
        suspicious_roots = ['tmp', 'private', 'cache', 'shm', 'var/tmp']

        lower_exe = exe.lower()
        if any(part in lower_exe for part in suspicious_roots):
            score += 2
            reasons.append(
                f"Executable located in suspicious directory: {exe}",
            )

        # Path too long
        if len(exe) > 260:
            score += 1
            reasons.append(
                'Executable path unusually long, may indicate obfuscation.',
            )

    # -----------------------------
    # 2. CPU / Memory Abuse
    # -----------------------------
    cpu = details.get('cpu_percent', 0)
    mem = details.get('memory_percent', 0)

    if cpu > 50:
        score += 2
        reasons.append('High CPU usage.')
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
            reasons.append(
                'Privileged system process with unusual resource usage.',
            )

    # -----------------------------
    # 4. Network Connections
    # -----------------------------
    if isinstance(connections, list):
        for conn in connections:
            remote = conn.get('remote_address')
            status = conn.get('status', '').lower()

            if remote and status not in ['established', 'listen']:
                score += 1
                reasons.append(f"Unexpected remote connection: {remote}")

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

def analyze_network_flow(flow: dict[str, Any]) -> dict[str, Any]:
    details = flow.get('details', {})

    score = 0
    reasons = []

    src = details.get('src_ip')
    dst = details.get('dst_ip')
    size = details.get('packet_size', 0)
    protocol = normalize_str(details.get('protocol', '')).lower()

    # Suspicious large packets
    if size > 2000:
        score += 1
        reasons.append('Unusually large packet.')

    # Dangerous protocols
    bad_protocols = ['icmp', 'raw', 'gre']
    if protocol in bad_protocols:
        score += 1
        reasons.append(f"Suspicious protocol detected: {protocol}")

    # Public IP communication
    if dst and not (dst.startswith('10.') or dst.startswith('192.168.')):
        score += 1
        reasons.append(f"Connection to external IP: {dst}")

    return {
        'src': src,
        'dst': dst,
        'protocol': protocol,
        'size': size,
        'risk_score': score,
        'reasons': reasons,
    }


# ============================================================
# SERVICE EVENT ANALYZER
# ============================================================

def analyze_service_event(event: dict[str, Any]) -> dict[str, Any]:
    details = event.get('details', {})

    score = 0
    reasons = []

    service_name = details.get('service_name')
    event_id = details.get('event_id')
    level = normalize_str(details.get('level', 'info')).lower()

    if level in ['error', 'critical']:
        score += 2
        reasons.append('Service generated a critical error event.')

    # Windows-specific but safe (ignored if missing)
    if str(event_id) in ['7034', '7031']:
        score += 1
        reasons.append('Service crashed unexpectedly.')

    return {
        'service': service_name,
        'event_id': event_id,
        'risk_score': score,
        'reasons': reasons,
    }


# ============================================================
# BATCH ANALYSIS HELPERS
# ============================================================

def analyze_processes(process_list: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [analyze_process(p) for p in process_list]


def analyze_network_flows(flow_list: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [analyze_network_flow(f) for f in flow_list]


def analyze_service_events(event_list: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [analyze_service_event(e) for e in event_list]


# ============================================================
# UNIVERSAL ENTRYPOINT
# ============================================================

def analyze_event(event: dict[str, Any]) -> dict[str, Any]:
    """
    Auto-detect type and run correct analyzer.
    """

    etype = event.get('type')

    if etype == 'process':
        return analyze_process(event)

    if etype == 'network_flow':
        return analyze_network_flow(event)

    if etype == 'service_event':
        return analyze_service_event(event)

    return {
        'risk_score': 0,
        'reasons': ['Unknown event type, no analysis performed.'],
    }
