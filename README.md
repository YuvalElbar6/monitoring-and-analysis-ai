# 📡 PC System Monitor – MCP Cybersecurity Agent

> A cross-platform cybersecurity monitoring and analysis MCP server with local LLM intelligence

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![Docker](https://img.shields.io/badge/docker-ready-brightgreen.svg)](https://www.docker.com/)

## 🎯 Overview

Your own personal SOC (Security Operations Center) agent, running locally, offline, and platform-agnostic.

This project combines real-time system monitoring with AI-powered threat analysis to create a comprehensive cybersecurity solution that runs entirely on your machine.

### Built With

- **FastMCP** - Tool-calling server framework
- **Ollama + Gemma 3** (4B / 9B / 27B) - Local LLM brain
- **ChromaDB** - RAG vector store
- **Python AsyncIO** - Safe background task scheduling
- **Scapy & psutil** - Cross-platform system monitoring

---

## ✨ Features

### 🔍 Live OS Monitoring (Cross-Platform)

Background collectors automatically gather system data every few seconds:

- **Running processes** - Monitor all active processes with detailed metadata
- **Active network flows** - Track network connections and traffic patterns
- **System services** - Watch system daemons and services
- **System information** - CPU, RAM, disk usage, kernel info, and more

**Supported Operating Systems:**
- ✅ Windows
- ✅ macOS  
- ✅ Linux

Each OS has its own optimized collector class for native system calls.

### 🛡️ Cybersecurity Tooling (MCP Tools)

Your MCP server exposes these powerful tools:

| Tool | Description |
|------|-------------|
| `get_running_processes` | Returns trimmed list of live process events |
| `get_network_flows` | Returns live network activity (safe Scapy wrapper) |
| `get_services` | System services and daemons |
| `analyze_processes` | Malware heuristics for running processes |
| `analyze_network` | Network threat analysis and anomaly detection |
| `analyze_services` | System service anomaly detection |
| `analyze_all` | Full combined system security assessment |

### 🧠 Local LLM Cyber Analyst

Gemma-3 (via Ollama) transforms raw system data into actionable intelligence:

- **Summaries** - Clear, concise overviews of system state
- **Suspicious indicators** - Flagged anomalies and potential threats
- **Risk scoring** - Quantified threat levels for prioritization
- **Recommended actions** - Specific remediation steps
- **Human-readable reports** - Professional cybersecurity assessments

### 📙 RAG-Enhanced Tool Classifier

Smart query processing pipeline:

1. Retrieves relevant context from ChromaDB
2. Feeds context + user query to Gemma
3. Gemma intelligently selects which tool to execute
4. JSON output is extracted and validated
5. Limit fields are safely clamped (1–5)
6. Tool executes with proper parameters
7. Gemma generates the final analysis

### 🪵 Background Task Safety

All collectors run with production-grade safety:

- ✅ `asyncio.to_thread()` for safe concurrent execution
- ✅ Exception wrappers prevent crashes
- ✅ Full cancellation support
- ✅ OS-sensitive isolation (Windows modules not imported on Linux)
- ✅ No race conditions
- ✅ Silent Scapy exception handling

---

## 🏗️ Project Structure

```
.
├── server.py                 # FastMCP server entrypoint
├── collectors/
│   ├── base.py               # Base collector interface
│   ├── linux.py              # Linux collector (psutil + scapy + systemd)
│   ├── mac.py                # macOS collector
│   ├── windows.py            # Windows collector
│   └── factory.py            # Auto-selects the right collector per OS
├── helper/
│   ├── trimmer.py            # Safe dict/list trimmer
│   └── extract_json.py       # JSON extractor for Gemma output
├── analysis/
│   ├── process_analyzer.py   # Threat scoring for processes
│   ├── network_analyzer.py   # Threat scoring for network flows
│   └── service_analyzer.py   # Threat scoring for services
├── rag/
│   ├── retriever.py          # ChromaDB retriever
│   └── embedder.py           # Embedding model loader
├── models/
│   ├── mcp.py                # Shared state for collectors
│   ├── unified.py            # Unified Event Model
│   ├── process.py            # Process data models
│   ├── network.py            # Network data models
│   └── services.py           # Service data models
├── client.py                 # CLI agent client
├── Dockerfile                # MCP server Docker build
├── docker-compose.yml        # Full stack orchestration
└── README.md                 # This file
```

---

## 🚀 Getting Started

### Prerequisites

- **Docker & Docker Compose** (recommended)
- OR **Python 3.12+** for local installation
- **8GB+ RAM** (for running Gemma models)
- **Administrator/root privileges** (for some system monitoring features)

### Option 1: Docker (Recommended)

#### 1. Clone the repository

```bash
git clone https://github.com/<your-username>/mcp-cyber-agent
cd mcp-cyber-agent
```

#### 2. Start the full stack

```bash
docker compose up --build
```

This launches:
- **ollama** → Your LLM backend (port 11434)
- **chroma** → Vector DB for RAG (port 8000)
- **mcp_server** → Your FastMCP cyber agent (port 8001)
- **openwebui** → Optional web UI (port 3000)

#### 3. Verify services

MCP server will be available at:
```
http://localhost:8001/mcp
```

#### 4. Pull Gemma model

```bash
docker exec -it ollama ollama pull gemma2:9b
```

### Option 2: Local Installation

#### 1. Clone and install dependencies

```bash
git clone https://github.com/<your-username>/mcp-cyber-agent
cd mcp-cyber-agent
pip install -r requirements.txt
```

#### 2. Start Ollama separately

```bash
# Install Ollama from https://ollama.ai
ollama serve
ollama pull gemma2:9b
```

#### 3. Start ChromaDB

```bash
docker run -d -p 8000:8000 chromadb/chroma
```

#### 4. Run the MCP server

```bash
python server.py
```

---

## 💻 Usage

### Using the CLI Client

Run the interactive agent client:

```bash
python client.py
```

### Example Queries

```
>>> show me suspicious activity
>>> analyze all running processes
>>> check recent network usage
>>> search for credential theft
>>> what services are running?
>>> identify unusual network connections
```

The agent automatically:
1. Uses RAG to understand your query
2. Classifies and selects the appropriate tool
3. Executes the tool with optimal parameters
4. Returns a comprehensive cybersecurity analysis

### Example Output

```
Summary:
A suspicious background process was detected. It has no executable path 
and is running as SYSTEM.

Findings:
- Process: System
- User: NT AUTHORITY\SYSTEM
- Risk Score: 2
- Indicators: hidden or kernel thread

Recommended Actions:
- Validate parent process
- Check for kernel driver tampering
- Review recent event logs for unusual activity
- Consider running integrity checks on system files
```

---

## 🔧 Configuration

### Environment Variables

Create a `.env` file in the project root:

```env
# Ollama Configuration
OLLAMA_HOST=http://localhost:11434
OLLAMA_MODEL=gemma2:9b

# ChromaDB Configuration
CHROMA_HOST=localhost
CHROMA_PORT=8000

# MCP Server Configuration
MCP_PORT=8001
LOG_LEVEL=INFO

# Collector Configuration
COLLECTOR_INTERVAL=5  # seconds between collections
MAX_EVENTS=1000       # max events to store in memory
```

### Customizing Analysis Rules

Edit the analyzer files to adjust threat detection logic:

- `analysis/process_analyzer.py` - Process threat heuristics
- `analysis/network_analyzer.py` - Network threat patterns
- `analysis/service_analyzer.py` - Service anomaly detection

---

## 🧪 Testing
TODO
---

## 🖥️ Tech Stack

| Component | Technology |
|-----------|-----------|
| **Language** | Python 3.12+ |
| **MCP Framework** | FastMCP |
| **Async Runtime** | AsyncIO |
| **System Monitoring** | psutil, Scapy |
| **LLM Backend** | Ollama |
| **LLM Model** | Gemma 3 (4B/9B/27B) |
| **Vector DB** | ChromaDB |
| **Embeddings** | sentence-transformers |
| **Containerization** | Docker & Docker Compose |

---

## 🔐 Security & Privacy

- ✅ **100% Local** - All analysis occurs on your machine
- ✅ **No Cloud Services** - No external API calls required
- ✅ **No Telemetry** - Zero data collection or tracking
- ✅ **No File Uploads** - Your data never leaves your system
- ✅ **Open Source** - Fully auditable codebase
- ✅ **Offline Capable** - Works without internet connection

---

## 🐛 Troubleshooting

### Scapy Permission Errors

On Linux/macOS, Scapy requires root privileges:

```bash
sudo python server.py
# OR
sudo docker compose up
```

### Ollama Connection Failed

Ensure Ollama is running:

```bash
# Check if Ollama is running
curl http://localhost:11434/api/tags

# If not, start it
ollama serve
```

### High Memory Usage

Gemma models require significant RAM. Consider using smaller models:

```bash
ollama pull gemma2:4b  # Smaller, faster model
```

### ChromaDB Connection Issues

Restart the ChromaDB container:

```bash
docker restart chroma
```

---

## 🗺️ Roadmap

- [ ] Web UI dashboard for visualizing threats
- [ ] Custom alert rules and notifications
- [ ] Historical trend analysis
- [ ] Integration with SIEM systems
- [ ] Support for additional LLM models (Llama, Mistral)
- [ ] Plugin system for custom analyzers
- [ ] Export reports to PDF/JSON
- [ ] Real-time alerting via webhooks

---

## ❤️ Contributing

Contributions are welcome! Here's how you can help:

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/amazing-feature`)
3. **Commit** your changes (`git commit -m 'Add amazing feature'`)
4. **Push** to the branch (`git push origin feature/amazing-feature`)
5. **Open** a Pull Request

### Areas for Contribution

- New threat detection analyzers
- Additional OS-specific collectors
- Performance optimizations
- Documentation improvements
- Bug fixes and testing

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- FastMCP team for the excellent MCP framework
- Ollama for making local LLMs accessible
- Gemma team at Google for the powerful models
- ChromaDB for the vector database
- The open-source security community

---

## 📧 Contact

For questions, issues, or suggestions:

- **Issues**: [GitHub Issues](https://github.com/<your-username>/mcp-cyber-agent/issues)
- **Discussions**: [GitHub Discussions](https://github.com/<your-username>/mcp-cyber-agent/discussions)

---

<div align="center">

**⭐ Star this repo if you find it useful! ⭐**

Made with ❤️ by the community

</div>
