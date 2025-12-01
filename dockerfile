# -----------------------------
# MCP SERVER BASE IMAGE
# -----------------------------
    FROM python:3.12-slim AS base

    # -----------------------------
    # System dependencies needed for:
    # - scapy (pcap)
    # - psutil
    # - subprocess tools
    # -----------------------------
    RUN apt-get update && apt-get install -y \
        libpcap0.8 \
        libpcap0.8-dev \
        tcpdump \
        iproute2 \
        gcc \
        g++ \
        make \
        && rm -rf /var/lib/apt/lists/*

    # -----------------------------
    # Copy server files
    # -----------------------------
    WORKDIR /app
    COPY . /app

    # -----------------------------
    # Install Python dependencies
    # -----------------------------
    RUN pip install --no-cache-dir -r requirements.txt

    # -----------------------------
    # Expose MCP HTTP port
    # -----------------------------
    EXPOSE 8000

    # -----------------------------
    # ENTRYPOINT
    # -----------------------------
    CMD ["python", "server.py"]
