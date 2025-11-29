import os
import json
import re
import httpx
from datetime import date
from sentinel.core.logger import get_logger

logger = get_logger("sentinel.services.eol")

class EolService:
    """
    Checks for End-of-Life (EOL) status of runtimes and frameworks 
    using the endoflife.date API.
    """
    
    API_BASE = "https://endoflife.date/api"

    async def check_eol(self, target_path: str) -> dict:
        """
        Scans the target directory for version files and checks EOL status.
        """
        logger.info("starting_eol_scan", target=target_path)
        findings = []
        
        # Detect technologies
        tech_versions = self._detect_versions(target_path)
        
        async with httpx.AsyncClient() as client:
            for product, version in tech_versions.items():
                status = await self._query_eol_api(client, product, version)
                if status:
                    findings.append(status)
        
        return {
            "summary": f"Checked {len(tech_versions)} technologies. Found {len(findings)} EOL/Upcoming EOL issues.",
            "findings": findings,
            "detected_versions": tech_versions
        }

    def _detect_versions(self, target_path: str) -> dict:
        """
        Heuristically detects versions of supported products.
        Returns dict: { 'product_cycle': 'version' }
        """
        versions = {}
        
        # Python
        py_ver = self._detect_python_version(target_path)
        if py_ver:
            versions["python"] = py_ver
            
        # Node.js
        node_ver = self._detect_node_version(target_path)
        if node_ver:
            versions["nodejs"] = node_ver
            
        # TODO: Add more detectors (Django, React, etc.)
        
        return versions

    def _detect_python_version(self, path: str) -> str:
        # Check .python-version
        p = os.path.join(path, ".python-version")
        if os.path.exists(p):
            with open(p) as f:
                return self._clean_version(f.read())
        
        # Check runtime.txt
        p = os.path.join(path, "runtime.txt")
        if os.path.exists(p):
            with open(p) as f:
                content = f.read().lower()
                if "python-" in content:
                    return self._clean_version(content.replace("python-", ""))
        
        return None

    def _detect_node_version(self, path: str) -> str:
        # Check .nvmrc
        p = os.path.join(path, ".nvmrc")
        if os.path.exists(p):
            with open(p) as f:
                return self._clean_version(f.read())
        
        # Check package.json engines
        p = os.path.join(path, "package.json")
        if os.path.exists(p):
            try:
                with open(p) as f:
                    data = json.load(f)
                    eng = data.get("engines", {}).get("node")
                    if eng:
                        return self._clean_version(eng)
            except:
                pass
        return None

    def _clean_version(self, version_str: str) -> str:
        """Extracts major.minor from version string."""
        # Remove v prefix, whitespace
        v = version_str.strip().lstrip("v")
        # Regex to grab X.Y
        match = re.match(r"(\d+\.\d+)", v)
        if match:
            return match.group(1)
        # If just major version (e.g. "14"), return it
        match = re.match(r"(\d+)", v)
        if match:
            return match.group(1)
        return v

    async def _query_eol_api(self, client, product: str, cycle: str) -> dict:
        """
        Queries endoflife.date for a specific cycle.
        """
        try:
            # We need to find the matching cycle in the product's all-cycles list
            # because the API is /api/{product}/{cycle}.json
            # But sometimes cycle is "3.9" and we have "3.9.1".
            
            # Strategy: Get all cycles, find the one that matches our version
            resp = await client.get(f"{self.API_BASE}/{product}.json")
            if resp.status_code != 200:
                logger.warning("eol_api_failed", product=product, status=resp.status_code)
                return None
                
            cycles = resp.json()
            
            matched_cycle = None
            for c in cycles:
                # Simple prefix match: if detected "3.9" matches cycle "3.9"
                if cycle.startswith(c["cycle"]) or c["cycle"].startswith(cycle):
                    matched_cycle = c
                    break
            
            if not matched_cycle:
                return None
                
            eol_date = matched_cycle.get("eol")
            today = date.today().isoformat()
            
            is_eol = False
            if isinstance(eol_date, str) and eol_date < today:
                is_eol = True
                
            if is_eol:
                return {
                    "product": product,
                    "cycle": matched_cycle["cycle"],
                    "detected_version": cycle,
                    "eol_date": eol_date,
                    "status": "EOL",
                    "message": f"{product} {matched_cycle['cycle']} is End-of-Life since {eol_date}. Upgrade immediately.",
                    "lts": matched_cycle.get("lts", False)
                }
            
            # Check if EOL is soon (within 90 days)
            # (Skipping complex date math for now, just returning EOLs)
            
            return None

        except Exception as e:
            logger.error("eol_check_error", error=str(e))
            return None
