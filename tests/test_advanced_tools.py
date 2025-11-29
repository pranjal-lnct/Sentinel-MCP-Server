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
        description = "A web application with a SQL database and file upload feature."
        
        # Ensure API key is unset to force heuristic
        if "SENTINEL_LLM_API_KEY" in os.environ:
            del os.environ["SENTINEL_LLM_API_KEY"]
            
        result = await self.threat_modeler.generate_stride_report(description)
        
        print(f"Result: {json.dumps(result, indent=2)}")
        
        self.assertIn("system_summary", result)
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
