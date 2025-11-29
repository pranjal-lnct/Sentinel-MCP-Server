# Sentinel MCP Server

**Sentinel** is a robust, enterprise-grade Security MCP (Model Context Protocol) Server designed for reliability, compliance, and easy integration with IDEs like VS Code and Antigravity.

## 🛡️ Features

- **Robust Execution**: Automatic retries for Docker commands, graceful timeout handling, and custom error reporting.
- **Compliance Ready**: Built-in support for **CIS Benchmark** scanning via Trivy.
- **Structured Logging**: All logs are output in JSON format for easy parsing and monitoring.
- **Dockerized Tools**: Runs all security tools in isolated Docker containers—no local tool installation required.

## 🧰 Included Tools

| Tool | Function | Docker Image |
| :--- | :--- | :--- |
| **Semgrep** | SAST (Static Analysis) | `returntocorp/semgrep` (Rules: OWASP Top 10, CWE Top 25, Security Audit) |
| **Trivy** | SCA & Compliance | `aquasec/trivy` |
| **Grype** | SCA (Vulnerability Scanning) | `anchore/grype` |
| **Gitleaks** | Secret Scanning | `zricethezav/gitleaks` |
| **OWASP ZAP** | DAST (Web Scanning) | `owasp/zap2docker-stable` |
| **ClamAV** | Malware Scanning | `clamav/clamav` |
| **Schemathesis** | API Fuzzing | `schemathesis/schemathesis:stable` |
| **EOL Scanner** | Runtime/Framework EOL Checks | *Built-in (endoflife.date API)* |
| **Crypto Scanner** | SSL/TLS Compliance | `drwetter/testssl.sh` |
| **AI Threat Modeler** | STRIDE Analysis | *Built-in (LLM Powered)* |

## 🚀 Getting Started

### Prerequisites
- **Docker**: Must be installed and running.
- **Python**: Version 3.13 or higher.

### Installation

1.  **Clone the repository** (if applicable) or navigate to the project directory:
    ```bash
    cd sentinel-mcp-server
    ```

2.  **Create a virtual environment**:
    ```bash
    python3 -m venv .venv
    source .venv/bin/activate
    ```

3.  **Install dependencies**:
    ```bash
    pip install .
    ```

### Running the Server

To start the MCP server manually (for testing):
```bash
mcp run python src/sentinel/server.py
```

### Manual Scanning (CLI)

You can also scan any project directory directly from the terminal using the included utility script:

```bash
# Scan a specific project directory
python3 scan_project.py /path/to/your/project

# Run only specific scans (e.g., secrets)
python3 scan_project.py /path/to/your/project --type secrets
```

## 💻 IDE Configuration

### VS Code

To use Sentinel with the **MCP Servers** extension in VS Code, add the following to your MCP settings file (typically `~/Library/Application Support/Code/User/globalStorage/mcp-servers.json`):

```json
{
  "mcpServers": {
    "sentinel": {
      "command": "/Users/pranjalsharma/Documents/SourceCode/appsec/sentinel-mcp-server/.venv/bin/python3",
      "args": [
        "/Users/pranjalsharma/Documents/SourceCode/appsec/sentinel-mcp-server/src/sentinel/server.py"
      ],
      "env": {
        "SENTINEL_LOG_LEVEL": "INFO"
      }
    }
  }
}
```
*Replace `/ABSOLUTE/PATH/TO/...` with the actual full path to your project directory.*

## ⚙️ Configuration

You can configure Sentinel using environment variables:

| Variable | Description | Default |
| :--- | :--- | :--- |
| `SENTINEL_LOG_LEVEL` | Logging level (DEBUG, INFO, WARN, ERROR) | `INFO` |
| `SENTINEL_DOCKER_TIMEOUT` | Timeout for Docker commands in seconds | `600` |
| `SENTINEL_SEMGREP_IMAGE` | Custom Docker image for Semgrep | `returntocorp/semgrep` |
| `SENTINEL_TRIVY_IMAGE` | Custom Docker image for Trivy | `aquasec/trivy` |
| `SENTINEL_GRYPE_IMAGE` | Custom Docker image for Grype | `anchore/grype` |
| `SENTINEL_TESTSSL_IMAGE` | Custom Docker image for testssl.sh | `drwetter/testssl.sh` |
| `SENTINEL_SCHEMATHESIS_IMAGE` | Custom Docker image for Schemathesis | `schemathesis/schemathesis:stable` |
| `SENTINEL_LLM_API_KEY` | API Key for AI Threat Modeling (e.g., OpenAI) | `None` (Falls back to heuristic) |
| `SENTINEL_LLM_MODEL` | LLM Model to use | `gpt-4o` |

## 🏗️ Project Structure

```text
src/sentinel/
├── core/           # Core logic (logging, exceptions, config)
├── services/       # Business logic (scanners, compliance)
├── tools/          # Tool execution (Docker runner)
└── server.py       # Main MCP entry point
```
