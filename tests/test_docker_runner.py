import unittest
from unittest.mock import MagicMock, patch, AsyncMock
import sys
import os
import asyncio
from tenacity import RetryError

# Add src to path
sys.path.append(os.path.join(os.getcwd(), "sentinel-mcp-server", "src"))

from sentinel.tools.docker_runner import DockerRunner
from sentinel.core.exceptions import ToolExecutionError

class TestDockerRunner(unittest.IsolatedAsyncioTestCase):
    
    @patch("sentinel.tools.docker_runner.shutil.which")
    @patch("asyncio.create_subprocess_exec")
    async def test_run_command_success(self, mock_exec, mock_which):
        mock_which.return_value = "/usr/bin/docker"
        mock_process = AsyncMock()
        mock_process.communicate.return_value = (b"success", b"")
        mock_exec.return_value = mock_process
        
        result = await DockerRunner.run_command(["docker", "info"])
        self.assertEqual(result, "success")

    @patch("sentinel.tools.docker_runner.shutil.which")
    @patch("asyncio.create_subprocess_exec")
    async def test_run_command_failure_retry(self, mock_exec, mock_which):
        mock_which.return_value = "/usr/bin/docker"
        
        # Simulate failure then success
        mock_process_fail = AsyncMock()
        mock_process_fail.communicate.side_effect = Exception("Connection refused")
        
        mock_process_success = AsyncMock()
        mock_process_success.communicate.return_value = (b"success_after_retry", b"")
        
        mock_exec.side_effect = [mock_process_fail, mock_process_success]
        
        # Should succeed eventually
        result = await DockerRunner.run_command(["docker", "info"])
        self.assertEqual(result, "success_after_retry")
        self.assertEqual(mock_exec.call_count, 2)

if __name__ == "__main__":
    unittest.main()
