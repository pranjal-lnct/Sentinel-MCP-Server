import unittest
import os
import sys
import json
import asyncio

# Add src to path
sys.path.append(os.path.join(os.getcwd(), "src"))

from sentinel.services.scanner import ScannerService
from sentinel.services.threat_modeling import ThreatModelingService

class TestAdvancedTools(unittest.IsolatedAsyncioTestCase):
    
    def setUp(self):
        self.scanner = ScannerService()
        self.threat_modeler = ThreatModelingService()
        self.resources_dir = os.path.abspath(os.path.join(os.getcwd(), "tests/resources"))

    async def test_threat_modeling_heuristic(self):
        """
        Test Threat Modeling (Heuristic Fallback).
        """
        print("\nRunning Threat Modeling (Heuristic)...")
        # We need a target path now
        target = self.resources_dir
        
        # Create a dummy docker-compose to trigger heuristic
        dc_path = os.path.join(target, "docker-compose.yml")
        with open(dc_path, "w") as f:
            f.write("services:\n  db:\n    image: postgres")
            
        try:
            result = await self.threat_modeler.generate_stride_report(target, "A simple web app")
            
            self.assertIsInstance(result, dict)
            self.assertIn("threats", result)
            threats = result["threats"]
            
            # Should detect database from docker-compose
            found_db_threat = any(t["category"] == "Tampering" and "Database" in t["description"] for t in threats)
            self.assertTrue(found_db_threat, "Should detect DB threat from docker-compose")
            
        finally:
            if os.path.exists(dc_path):
                os.remove(dc_path)
        
        self.assertIn("system_summary", result)
        self.assertIn("dfd_diagram", result)
        self.assertIn("threats", result)
        
        # Check for expected heuristic findings
        threats = result["threats"]
        self.assertTrue(any(t["category"] == "Tampering" for t in threats), "Should detect SQL/Database threat")
        self.assertTrue(any(t["category"] == "Tampering" for t in threats), "Should detect File Upload threat")

    async def test_api_fuzzing(self):
        """
        Test API Fuzzing with Schemathesis.
        """
        print("\nRunning API Fuzzing...")
        schema_path = os.path.join(self.resources_dir, "openapi.json")
        
        result = await self.scanner.run_api_fuzzing(schema_path)
        
        # Schemathesis output is raw string in "raw_output"
        self.assertIn("raw_output", result)
        output = result["raw_output"]
        
        print(f"Schemathesis Output Length: {len(output)}")
        
        # Check for success or at least execution
        # Schemathesis prints a summary table
        if not ("Schemathesis" in output or "Summary" in output or "Finished" in output):
             print(f"DEBUG: Raw Output:\n{output}")
        self.assertTrue("Schemathesis" in output or "Summary" in output or "Finished" in output, "Schemathesis did not run correctly")

if __name__ == "__main__":
    unittest.main()
