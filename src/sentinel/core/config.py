import os
from dataclasses import dataclass

@dataclass
class SentinelConfig:
    """Configuration for Sentinel MCP Server."""
    
    # Docker Images
    SEMGREP_IMAGE: str = os.getenv("SENTINEL_SEMGREP_IMAGE", "returntocorp/semgrep")
    TRIVY_IMAGE = os.getenv("SENTINEL_TRIVY_IMAGE", "aquasec/trivy")
    GRYPE_IMAGE = os.getenv("SENTINEL_GRYPE_IMAGE", "anchore/grype")
    GITLEAKS_IMAGE = os.getenv("SENTINEL_GITLEAKS_IMAGE", "zricethezav/gitleaks")
    ZAP_IMAGE: str = os.getenv("SENTINEL_ZAP_IMAGE", "owasp/zap2docker-stable")
    CLAMAV_IMAGE: str = os.getenv("SENTINEL_CLAMAV_IMAGE", "clamav/clamav")
    TESTSSL_IMAGE: str = os.getenv("SENTINEL_TESTSSL_IMAGE", "drwetter/testssl.sh")
    SCHEMATHESIS_IMAGE: str = os.getenv("SENTINEL_SCHEMATHESIS_IMAGE", "schemathesis/schemathesis:stable")
    
    # Settings
    LOG_LEVEL: str = os.getenv("SENTINEL_LOG_LEVEL", "INFO")
    DOCKER_TIMEOUT: int = int(os.getenv("SENTINEL_DOCKER_TIMEOUT", "600")) # 10 minutes

config = SentinelConfig()
