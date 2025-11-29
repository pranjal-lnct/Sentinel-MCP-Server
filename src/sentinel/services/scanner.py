import json
import os
import tempfile
from sentinel.tools.docker_runner import DockerRunner
from sentinel.core.config import config
from sentinel.core.logger import get_logger
from sentinel.core.exceptions import ToolExecutionError

logger = get_logger("sentinel.services.scanner")

class ScannerService:
    """Orchestrates security scans using Dockerized tools."""

    async def run_sast(self, target_path: str) -> dict:
        """Runs Semgrep SAST scan."""
        logger.info("starting_sast_scan", target=target_path)
        cmd = [
            "docker", "run", "--rm",
            "-v", f"{target_path}:/src",
            config.SEMGREP_IMAGE,
            "semgrep", "scan", 
            "--config=p/owasp-top-ten", 
            "--config=p/cwe-top-25", 
            "--config=p/security-audit",
            "--json", "/src"
        ]
        output = await DockerRunner.run_command(cmd)
        try:
            return json.loads(output)
        except json.JSONDecodeError:
            logger.error("sast_json_parse_error", output=output[:200])
            return {"error": "Failed to parse Semgrep output", "raw": output}

    async def run_sca(self, target_path: str) -> dict:
        """Runs Trivy SCA scan."""
        logger.info("starting_sca_scan", target=target_path)
        cmd = [
            "docker", "run", "--rm",
            "-v", f"{target_path}:/src",
            config.TRIVY_IMAGE,
            "fs", "--format", "json", "/src"
        ]
        output = await DockerRunner.run_command(cmd)
        try:
            return json.loads(output)
        except json.JSONDecodeError:
            logger.error("sca_json_parse_error", output=output[:200])
            return {"error": "Failed to parse Trivy output", "raw": output}

    async def run_secrets(self, target_path: str) -> dict:
        """Runs Gitleaks secret scan."""
        logger.info("starting_secret_scan", target=target_path)
        cmd = [
            "docker", "run", "--rm",
            "-v", f"{target_path}:/src",
            config.GITLEAKS_IMAGE,
            "detect", "--source", "/src", "--no-git", "--report-format", "json", "--report-path", "/dev/stdout"
        ]
        output = await DockerRunner.run_command(cmd)
        try:
            return json.loads(output) if output else []
        except json.JSONDecodeError:
            logger.error("secrets_json_parse_error", output=output[:200])
            return {"error": "Failed to parse Gitleaks output", "raw": output}

    async def run_dast(self, target_url: str) -> dict:
        """Runs OWASP ZAP Baseline Scan."""
        logger.info("starting_dast_scan", target=target_url)
        with tempfile.TemporaryDirectory() as tmp_dir:
            report_file = "zap_report.json"
            cmd = [
                "docker", "run", "--rm",
                "-v", f"{tmp_dir}:/zap/wrk/:rw",
                "-t", config.ZAP_IMAGE,
                "zap-baseline.py", "-t", target_url, "-J", report_file
            ]
            await DockerRunner.run_command(cmd)
            
            report_path = os.path.join(tmp_dir, report_file)
            if os.path.exists(report_path):
                with open(report_path, 'r') as f:
                    return json.load(f)
            else:
                return {"error": "ZAP scan completed but report not found."}

    async def run_malware(self, target_path: str) -> dict:
        """Runs ClamAV scan."""
        logger.info("starting_malware_scan", target=target_path)
        cmd = [
            "docker", "run", "--rm",
            "-v", f"{target_path}:/scandir",
            config.CLAMAV_IMAGE,
            "clamscan", "-r", "/scandir"
        ]
        output = await DockerRunner.run_command(cmd)
        
        # Parse ClamAV output
        infected_files = []
        for line in output.splitlines():
            if " FOUND" in line:
                parts = line.split(":")
                if len(parts) >= 2:
                    infected_files.append({"file": parts[0].strip(), "threat": parts[1].strip()})
        
        return {"infected_files": infected_files, "raw_output": output}

    async def run_api_fuzzing(self, schema_url: str) -> dict:
        """
        Runs API Fuzzing using Schemathesis.
        Target: OpenAPI/Swagger Schema URL (or file path).
        """
        logger.info("starting_api_fuzzing", target=schema_url)
        
        # Note: If schema_url is a local file, we need to mount it.
        # For simplicity, assuming URL or mounted path for now.
        # If it's a file path, we mount the parent dir.
        
        docker_args = ["docker", "run", "--rm"]
        target_arg = schema_url
        
        if os.path.exists(schema_url):
            abs_path = os.path.abspath(schema_url)
            parent_dir = os.path.dirname(abs_path)
            filename = os.path.basename(abs_path)
            docker_args.extend(["-v", f"{parent_dir}:/schema"])
            target_arg = f"/schema/{filename}"
        
        # Run schemathesis run --report=json
        cmd = docker_args + [
            config.SCHEMATHESIS_IMAGE,
            "run", target_arg,
            "--url", "http://localhost:8000",
            "--checks", "all"
        ]
        
        # Schemathesis outputs JSON report to stdout if configured, but usually it prints CLI UI.
        # We'll use a simple run for now and capture stdout. 
        # Better integration: use --junit-xml or similar if JSON isn't easily streamable to stdout without file.
        # Schemathesis 'run' outputs text by default. We can try to parse or just return raw.
        
        output = await DockerRunner.run_command(cmd)
        return {"raw_output": output}
