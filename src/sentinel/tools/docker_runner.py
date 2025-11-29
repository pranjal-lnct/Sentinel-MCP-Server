import asyncio
import shutil
import json
from typing import List, Optional
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
from sentinel.core.exceptions import ToolExecutionError, ConfigError
from sentinel.core.logger import get_logger
from sentinel.core.config import config

logger = get_logger("sentinel.tools.docker")

class DockerRunner:
    """Handles execution of Docker commands with robustness features."""

    @staticmethod
    def check_docker():
        """Checks if Docker is available."""
        if not shutil.which("docker"):
            raise ConfigError("Docker executable not found in PATH.")

    @staticmethod
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        retry=retry_if_exception_type(ToolExecutionError)
    )
    async def run_command(cmd: List[str], cwd: str = ".") -> str:
        """
        Runs a Docker command with retries and timeout.
        
        Args:
            cmd: The command list (e.g. ["docker", "run", ...])
            cwd: Current working directory
            
        Returns:
            Stdout output as string.
            
        Raises:
            ToolExecutionError: If command fails or times out.
        """
        DockerRunner.check_docker()
        
        cmd_str = " ".join(cmd)
        logger.info("executing_docker_command", command=cmd_str)
        
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=cwd
            )
            
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(), 
                    timeout=config.DOCKER_TIMEOUT
                )
            except asyncio.TimeoutError:
                process.kill()
                raise ToolExecutionError(f"Docker command timed out after {config.DOCKER_TIMEOUT}s", details={"command": cmd_str})

            stdout_decoded = stdout.decode().strip()
            stderr_decoded = stderr.decode().strip()
            
            # Note: Many security tools return non-zero exit codes for findings.
            # We log stderr but don't raise exception solely on exit code unless it's a runtime error.
            if stderr_decoded:
                logger.warning("docker_stderr", stderr=stderr_decoded)

            return stdout_decoded

        except Exception as e:
            logger.error("docker_execution_failed", error=str(e), command=cmd_str)
            raise ToolExecutionError(f"Failed to execute Docker command: {str(e)}", details={"original_error": str(e)})
