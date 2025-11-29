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
            "--config=p/cryptography",
            "--json", "/src"
        ]
        output = await DockerRunner.run_command(cmd)
        try:
            return json.loads(output)
        except json.JSONDecodeError:
            logger.error("sast_json_parse_error", output=output[:200])
            return {"error": "Failed to parse Semgrep output", "raw": output}

    async def run_sca(self, target_path: str) -> dict:
        """Runs SCA scan using Trivy and Grype, with deduplication."""
        logger.info("starting_sca_scan", target=target_path)
        
        # Run Trivy
        trivy_cmd = [
            "docker", "run", "--rm",
            "-v", f"{target_path}:/src",
            config.TRIVY_IMAGE,
            "fs", "--format", "json", "/src"
        ]
        trivy_output = await DockerRunner.run_command(trivy_cmd)
        trivy_results = self._normalize_trivy(trivy_output)
        
        # Run Grype
        grype_results = await self.run_grype(target_path)
        
        # Deduplicate
        combined_findings = self._deduplicate_findings(trivy_results, grype_results)
        
        return {
            "summary": f"Scanned with Trivy and Grype. Found {len(combined_findings)} unique vulnerabilities.",
            "results": combined_findings,
            "sources": {
                "trivy_count": len(trivy_results),
                "grype_count": len(grype_results)
            }
        }

    async def run_grype(self, target_path: str) -> list:
        """Runs Grype SCA scan."""
        logger.info("starting_grype_scan", target=target_path)
        cmd = [
            "docker", "run", "--rm",
            "-v", f"{target_path}:/src",
            config.GRYPE_IMAGE,
            "dir:/src", "-o", "json"
        ]
        output = await DockerRunner.run_command(cmd)
        return self._normalize_grype(output)

    def _normalize_trivy(self, raw_output: str) -> list:
        """Normalizes Trivy JSON output."""
        findings = []
        try:
            data = json.loads(raw_output)
            if "Results" in data:
                for result in data["Results"]:
                    for vuln in result.get("Vulnerabilities", []):
                        findings.append({
                            "id": vuln.get("VulnerabilityID"),
                            "pkg": vuln.get("PkgName"),
                            "severity": vuln.get("Severity"),
                            "description": vuln.get("Description"),
                            "source": "trivy"
                        })
        except json.JSONDecodeError:
            logger.error("trivy_json_parse_error")
        return findings

    def _normalize_grype(self, raw_output: str) -> list:
        """Normalizes Grype JSON output."""
        findings = []
        try:
            data = json.loads(raw_output)
            if "matches" in data:
                for match in data["matches"]:
                    vuln = match.get("vulnerability", {})
                    artifact = match.get("artifact", {})
                    findings.append({
                        "id": vuln.get("id"),
                        "pkg": artifact.get("name"),
                        "severity": vuln.get("severity"),
                        "description": vuln.get("description"),
                        "source": "grype"
                    })
        except json.JSONDecodeError:
            logger.error("grype_json_parse_error")
        return findings

    def _deduplicate_findings(self, list1: list, list2: list) -> list:
        """Deduplicates findings based on ID and Package Name."""
        unique_map = {}
        
        for item in list1 + list2:
            key = (item.get("id"), item.get("pkg"))
            if key not in unique_map:
                unique_map[key] = item
            else:
                # Merge sources if needed, or just keep first
                existing = unique_map[key]
                if existing["source"] != item["source"]:
                    existing["source"] = "both"
        
        return list(unique_map.values())

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

    async def run_crypto_scan(self, target_url: str) -> dict:
        """
        Runs SSL/TLS Compliance Scan using testssl.sh.
        Target: URL (e.g., https://example.com)
        """
        logger.info("starting_crypto_scan", target=target_url)
        
        # testssl.sh outputs JSON file
        with tempfile.TemporaryDirectory() as tmp_dir:
            report_file = "testssl_report.json"
            cmd = [
                "docker", "run", "--rm",
                "-v", f"{tmp_dir}:/data",
                config.TESTSSL_IMAGE,
                "--jsonfile", f"/data/{report_file}",
                "--quiet", "--warnings", "off",
                target_url
            ]
            
            # testssl.sh often returns non-zero exit codes for findings, so we catch errors
            try:
                await DockerRunner.run_command(cmd)
            except ToolExecutionError as e:
                # Check if report exists, if so, it's likely just findings
                pass
            
            report_path = os.path.join(tmp_dir, report_file)
            if os.path.exists(report_path):
                try:
                    with open(report_path, 'r') as f:
                        # testssl.sh JSON output is sometimes a list of objects
                        data = json.load(f)
                        
                        # Filter for high severity issues
                        findings = []
                        for item in data:
                            severity = item.get("severity", "INFO")
                            if severity in ["HIGH", "CRITICAL", "MEDIUM"]:
                                findings.append({
                                    "id": item.get("id"),
                                    "severity": severity,
                                    "finding": item.get("finding"),
                                    "cve": item.get("cve")
                                })
                        
                        return {
                            "summary": f"Crypto Scan Complete. Found {len(findings)} issues.",
                            "findings": findings,
                            "raw_report_path": "Available in temp dir (not persisted)" 
                        }
                except json.JSONDecodeError:
                    return {"error": "Failed to parse testssl.sh output"}
            else:
                return {"error": "Crypto scan failed to generate report."}

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
