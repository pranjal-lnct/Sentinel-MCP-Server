import unittest
import os
import json
import tempfile
from unittest.mock import MagicMock, patch, AsyncMock
from sentinel.services.scanner import ScannerService

class TestCryptoScanner(unittest.IsolatedAsyncioTestCase):
    
    async def test_crypto_scan_parsing(self):
        """
        Test parsing of testssl.sh JSON output.
        """
        scanner = ScannerService()
        
        # Mock DockerRunner to avoid actual Docker execution
        # We simulate writing a report file
        with patch("sentinel.services.scanner.DockerRunner.run_command", new_callable=AsyncMock) as mock_run:
            
            # We need to intercept the temp dir usage to write our mock report
            # Since we can't easily patch the context manager's yielded value from here without complex mocking,
            # we will rely on the fact that the code looks for the file.
            # Actually, we can just test the parsing logic if we extract it, but let's try to mock the file system or 
            # just trust the integration test if we had one.
            
            # Alternative: We can't easily mock the file creation inside the method without refactoring.
            # Let's create a temporary file and mock the tempfile.TemporaryDirectory to return a known dir.
            
            with tempfile.TemporaryDirectory() as mock_tmp_dir:
                with patch("tempfile.TemporaryDirectory", return_value=MagicMock(__enter__=lambda x: mock_tmp_dir, __exit__=lambda *args: None)):
                    
                    # Create a dummy report
                    report_data = [
                        {
                            "id": "SSLv3",
                            "severity": "CRITICAL",
                            "finding": "SSLv3 is enabled",
                            "cve": "CVE-POODLE"
                        },
                        {
                            "id": "TLS1.2",
                            "severity": "INFO",
                            "finding": "TLS 1.2 enabled",
                            "cve": ""
                        }
                    ]
                    
                    with open(os.path.join(mock_tmp_dir, "testssl_report.json"), "w") as f:
                        json.dump(report_data, f)
                    
                    result = await scanner.run_crypto_scan("https://example.com")
                    
                    self.assertIn("findings", result)
                    findings = result["findings"]
                    self.assertEqual(len(findings), 1, "Should only report High/Critical/Medium")
                    self.assertEqual(findings[0]["id"], "SSLv3")
                    self.assertEqual(findings[0]["severity"], "CRITICAL")

if __name__ == "__main__":
    unittest.main()
