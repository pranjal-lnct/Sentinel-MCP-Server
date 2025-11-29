import unittest
import os
import shutil
import tempfile
from sentinel.services.eol import EolService

class TestEolService(unittest.IsolatedAsyncioTestCase):
    
    def setUp(self):
        self.eol = EolService()
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def test_detect_python_version_file(self):
        with open(os.path.join(self.test_dir, ".python-version"), "w") as f:
            f.write("3.9.1")
        
        versions = self.eol._detect_versions(self.test_dir)
        self.assertEqual(versions.get("python"), "3.9")

    def test_detect_python_runtime_txt(self):
        with open(os.path.join(self.test_dir, "runtime.txt"), "w") as f:
            f.write("python-3.8.12")
        
        versions = self.eol._detect_versions(self.test_dir)
        self.assertEqual(versions.get("python"), "3.8")

    def test_detect_node_nvmrc(self):
        with open(os.path.join(self.test_dir, ".nvmrc"), "w") as f:
            f.write("v14.17.0")
        
        versions = self.eol._detect_versions(self.test_dir)
        self.assertEqual(versions.get("nodejs"), "14.17")

    async def test_check_eol_integration(self):
        """
        Integration test hitting the actual API.
        We use a known EOL version (Python 2.7) and a known Active version (Python 3.12).
        """
        print("\nRunning EOL Integration Test...")
        
        # Create a Python 2.7 marker (EOL)
        with open(os.path.join(self.test_dir, ".python-version"), "w") as f:
            f.write("2.7.18")
            
        result = await self.eol.check_eol(self.test_dir)
        
        self.assertIn("findings", result)
        findings = result["findings"]
        
        # Python 2.7 is definitely EOL
        eol_finding = next((f for f in findings if f["product"] == "python" and f["cycle"] == "2.7"), None)
        self.assertIsNotNone(eol_finding, "Should detect Python 2.7 as EOL")
        self.assertEqual(eol_finding["status"], "EOL")
        print("Successfully detected Python 2.7 EOL.")

if __name__ == "__main__":
    unittest.main()
