import asyncio
import argparse
import sys
import os
import json

# Add src to path
sys.path.append(os.path.join(os.getcwd(), "src"))

from sentinel.services.scanner import ScannerService
from sentinel.core.logger import configure_logger

# Configure logging
configure_logger()

async def scan(target_path: str, scan_type: str):
    scanner = ScannerService()
    target_path = os.path.abspath(target_path)
    
    if not os.path.exists(target_path):
        print(f"Error: Target path '{target_path}' does not exist.")
        return

    print(f"\n=== Scanning Target: {target_path} ===\n")
    
    results = {}

    # SAST
    if scan_type in ["all", "sast"]:
        print("--- Running SAST (Semgrep) ---")
        results["sast"] = await scanner.run_sast(target_path)
        print(f"Findings: {len(results['sast'].get('results', []))}")

    # Secrets
    if scan_type in ["all", "secrets"]:
        print("\n--- Running Secret Scan (Gitleaks) ---")
        res = await scanner.run_secrets(target_path)
        results["secrets"] = res
        count = len(res) if isinstance(res, list) else 0
        print(f"Findings: {count}")

    # SCA
    if scan_type in ["all", "sca"]:
        print("\n--- Running SCA (Trivy) ---")
        res = await scanner.run_sca(target_path)
        results["sca"] = res
        # Simple count for Trivy
        count = 0
        if "Results" in res:
            for r in res["Results"]:
                count += len(r.get("Vulnerabilities", []))
        print(f"Findings: {count}")

    # Malware
    if scan_type in ["all", "malware"]:
        print("\n--- Running Malware Scan (ClamAV) ---")
        res = await scanner.run_malware(target_path)
        results["malware"] = res
        print(f"Infected Files: {len(res.get('infected_files', []))}")

    # Save report
    report_file = "scan_report.json"
    with open(report_file, "w") as f:
        json.dump(results, f, indent=2)
    
    print(f"\n=== Scan Completed. Report saved to {report_file} ===")

def main():
    parser = argparse.ArgumentParser(description="Sentinel CLI Scanner")
    parser.add_argument("path", help="Path to the project directory to scan")
    parser.add_argument("--type", choices=["all", "sast", "sca", "secrets", "malware"], default="all", help="Type of scan to run")
    
    args = parser.parse_args()
    
    asyncio.run(scan(args.path, args.type))

if __name__ == "__main__":
    main()
