import os
import json
import httpx
from sentinel.core.logger import get_logger
from sentinel.core.exceptions import ConfigError

logger = get_logger("sentinel.services.threat_modeling")

class ThreatModelingService:
    """
    AI-Powered Threat Modeling Service (STRIDE).
    """
    
    def __init__(self):
        self.api_key = os.getenv("SENTINEL_LLM_API_KEY")
        self.model = os.getenv("SENTINEL_LLM_MODEL", "gpt-4o")
        self.api_base = os.getenv("SENTINEL_LLM_API_BASE", "https://api.openai.com/v1")

    async def generate_stride_report(self, project_description: str) -> dict:
        """
        Generates a STRIDE threat model based on the project description.
        """
        logger.info("generating_threat_model")
        
        if not self.api_key:
            logger.warning("no_llm_api_key", message="Falling back to heuristic analysis")
            return self._heuristic_analysis(project_description)
            
        try:
            prompt = f"""
            Perform a STRIDE threat modeling analysis on the following system description.
            Return the output strictly as a JSON object with the following structure:
            {{
                "system_summary": "...",
                "threats": [
                    {{
                        "category": "Spoofing",
                        "description": "...",
                        "mitigation": "..."
                    }}
                ]
            }}
            
            System Description:
            {project_description}
            """
            
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{self.api_base}/chat/completions",
                    headers={"Authorization": f"Bearer {self.api_key}"},
                    json={
                        "model": self.model,
                        "messages": [{"role": "user", "content": prompt}],
                        "temperature": 0.7
                    },
                    timeout=60.0
                )
                response.raise_for_status()
                result = response.json()
                content = result["choices"][0]["message"]["content"]
                
                # Strip markdown code blocks if present
                if content.startswith("```json"):
                    content = content[7:-3]
                elif content.startswith("```"):
                    content = content[3:-3]
                    
                return json.loads(content.strip())

        except Exception as e:
            logger.error("llm_generation_failed", error=str(e))
            return {
                "error": f"Failed to generate threat model: {str(e)}",
                "fallback": self._heuristic_analysis(project_description)
            }

    def _heuristic_analysis(self, description: str) -> dict:
        """
        Simple keyword-based fallback analysis.
        """
        threats = []
        desc_lower = description.lower()
        
        if "database" in desc_lower or "sql" in desc_lower:
            threats.append({
                "category": "Tampering",
                "description": "Potential SQL Injection or data tampering in database.",
                "mitigation": "Use parameterized queries and input validation."
            })
            
        if "login" in desc_lower or "auth" in desc_lower:
            threats.append({
                "category": "Spoofing",
                "description": "Risk of user impersonation or weak authentication.",
                "mitigation": "Implement MFA and strong session management."
            })
            
        if "upload" in desc_lower:
            threats.append({
                "category": "Tampering",
                "description": "Malicious file upload risk.",
                "mitigation": "Validate file types and scan for malware."
            })
            
        if not threats:
            threats.append({
                "category": "Information Disclosure",
                "description": "General risk of data leakage.",
                "mitigation": "Ensure encryption at rest and in transit."
            })

        return {
            "system_summary": "Heuristic Analysis (LLM not configured)",
            "threats": threats
        }
