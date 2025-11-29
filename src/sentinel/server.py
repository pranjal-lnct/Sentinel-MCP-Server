#!/usr/bin/env python3
from mcp.server.fastmcp import FastMCP
from sentinel.services.scanner import ScannerService
from sentinel.services.compliance import ComplianceService
from sentinel.services.threat_modeling import ThreatModelingService
from sentinel.services.eol import EolService
from sentinel.core.logger import configure_logger, get_logger
from sentinel.core.exceptions import SentinelError

# Configure logging
configure_logger()
logger = get_logger("sentinel.server")

# Initialize FastMCP server
mcp = FastMCP("sentinel-agent")

# Initialize Services
scanner = ScannerService()
compliance = ComplianceService()
threat_modeler = ThreatModelingService()
eol_service = EolService()

@mcp.tool()
async def run_sast_scan(target_path: str) -> str:
    """Run SAST scan using Semgrep."""
    try:
        result = await scanner.run_sast(target_path)
        return json.dumps(result)
    except Exception as e:
        logger.error("tool_execution_failed", tool="sast", error=str(e))
        return json.dumps({"error": str(e)})

@mcp.tool()
async def run_sca_scan(target_path: str) -> str:
    """Run SCA scan using Trivy and Grype (Unified)."""
    try:
        result = await scanner.run_sca(target_path)
        return json.dumps(result)
    except Exception as e:
        logger.error("tool_execution_failed", tool="sca", error=str(e))
        return json.dumps({"error": str(e)})

@mcp.tool()
async def run_secret_scan(target_path: str) -> str:
    """Run Secret scan using Gitleaks."""
    try:
        result = await scanner.run_secrets(target_path)
        return json.dumps(result)
    except Exception as e:
        logger.error("tool_execution_failed", tool="secrets", error=str(e))
        return json.dumps({"error": str(e)})

@mcp.tool()
async def run_dast_scan(target_url: str) -> str:
    """Run DAST scan using OWASP ZAP."""
    try:
        result = await scanner.run_dast(target_url)
        return json.dumps(result)
    except Exception as e:
        logger.error("tool_execution_failed", tool="dast", error=str(e))
        return json.dumps({"error": str(e)})

@mcp.tool()
async def run_malware_scan(target_path: str) -> str:
    """Run Malware scan using ClamAV."""
    try:
        result = await scanner.run_malware(target_path)
        return json.dumps(result)
    except Exception as e:
        logger.error("tool_execution_failed", tool="malware", error=str(e))
        return json.dumps({"error": str(e)})

@mcp.tool()
async def run_cis_compliance_scan(target_path: str) -> str:
    """Run CIS Benchmark scan using Trivy."""
    try:
        result = await compliance.run_cis_scan(target_path)
        return json.dumps(result)
    except Exception as e:
        logger.error("tool_execution_failed", tool="cis", error=str(e))
        return json.dumps({"error": str(e)})

@mcp.tool()
async def run_api_fuzzing(schema_url: str) -> str:
    """Run API Fuzzing using Schemathesis."""
    try:
        result = await scanner.run_api_fuzzing(schema_url)
        return json.dumps(result)
    except Exception as e:
        logger.error("tool_execution_failed", tool="api_fuzzing", error=str(e))
        return json.dumps({"error": str(e)})

@mcp.tool()
async def run_threat_modeling(target_path: str, project_description: str = "") -> str:
    """Generate a STRIDE Threat Model (AI-Powered) based on code context."""
    try:
        result = await threat_modeler.generate_stride_report(target_path, project_description)
        return json.dumps(result)
    except Exception as e:
        logger.error("tool_execution_failed", tool="threat_modeling", error=str(e))
        return json.dumps({"error": str(e)})

@mcp.tool()
async def run_eol_scan(target_path: str) -> str:
    """Check for End-of-Life (EOL) runtimes and frameworks."""
    try:
        result = await eol_service.check_eol(target_path)
        return json.dumps(result)
    except Exception as e:
        logger.error("tool_execution_failed", tool="eol", error=str(e))
        return json.dumps({"error": str(e)})

@mcp.tool()
async def run_crypto_scan(target_url: str) -> str:
    """Run SSL/TLS Compliance Scan (testssl.sh)."""
    try:
        result = await scanner.run_crypto_scan(target_url)
        return json.dumps(result)
    except Exception as e:
        logger.error("tool_execution_failed", tool="crypto", error=str(e))
        return json.dumps({"error": str(e)})

import json

if __name__ == "__main__":
    mcp.run()
