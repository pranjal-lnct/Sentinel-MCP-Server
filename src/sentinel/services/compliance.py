import json
from sentinel.tools.docker_runner import DockerRunner
from sentinel.core.config import config
from sentinel.core.logger import get_logger

logger = get_logger("sentinel.services.compliance")

class ComplianceService:
    """Handles compliance scanning (e.g., CIS Benchmarks)."""

    async def run_cis_scan(self, target_path: str) -> dict:
        """
        Runs a CIS Benchmark scan using Trivy.
        Note: This typically applies to IaC (Terraform, Dockerfiles, K8s).
        """
        logger.info("starting_cis_scan", target=target_path)
        
        # Trivy compliance scan
        # trivy fs --compliance cis --format json /src
        cmd = [
            "docker", "run", "--rm",
            "-v", f"{target_path}:/src",
            config.TRIVY_IMAGE,
            "fs", "--compliance", "aws-cis-1.4", "--format", "json", "--quiet", "/src"
        ]
        
        output = await DockerRunner.run_command(cmd)
        try:
            return json.loads(output)
        except json.JSONDecodeError:
            logger.error("cis_json_parse_error", output=output[:200])
            return {"error": "Failed to parse Compliance output", "raw": output}
