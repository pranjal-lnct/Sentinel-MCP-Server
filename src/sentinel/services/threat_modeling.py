import os
import json
import httpx
from sentinel.core.logger import get_logger
from sentinel.core.exceptions import ConfigError

from sentinel.services.code_context import CodebaseSummarizer

logger = get_logger("sentinel.services.threat_modeling")

class ThreatModelingService:
    """
    AI-Powered Threat Modeling Service (STRIDE).
    """
    
    def __init__(self):
        self.api_key = os.getenv("SENTINEL_LLM_API_KEY")
        self.model = os.getenv("SENTINEL_LLM_MODEL", "gpt-4o")
        self.api_base = os.getenv("SENTINEL_LLM_API_BASE", "https://api.openai.com/v1")
        self.summarizer = CodebaseSummarizer()

    async def generate_stride_report(self, target_path: str, project_description: str = "") -> dict:
        """
        Generates a STRIDE threat model based on code context and optional description.
        """
        logger.info("generating_threat_model", target=target_path)
        
        # Extract context
        context = self.summarizer.summarize(target_path)
        
        if not self.api_key:
            logger.warning("no_llm_api_key", message="Falling back to heuristic analysis")
            return self._heuristic_analysis(context, project_description)
            
        try:
            prompt = f"""
            Perform a STRIDE threat modeling analysis on the following system.
            
            Technical Context:
            File Structure:
            {context['file_tree']}
            
            Key Configuration Files:
            {json.dumps(context['key_files'], indent=2)}
            
            Additional Description:
            {project_description}
            
            Return the output strictly as a JSON object with the following structure:
            {{
                "system_summary": "...",
                "dfd_diagram": "graph TD; ...",
                "threats": [
                    {{
                        "category": "Spoofing",
                        "description": "...",
                        "mitigation": "..."
                    }}
                ]
            }}
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
                    timeout=90.0
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
                "fallback": self._heuristic_analysis(context, project_description)
            }

    def _heuristic_analysis(self, context: dict, description: str) -> dict:
        """
        Heuristic analysis based on file presence and keywords.
        """
        threats = []
        files = context.get("key_files", {})
        tree = context.get("file_tree", "")
        desc_lower = description.lower()
        
        # Simple Heuristic DFD
        dfd = "graph TD;\n  User[User] -->|HTTPS| WebApp[Web Application];"
        
        # Database
        if "docker-compose" in str(files) and ("postgres" in str(files) or "mysql" in str(files)):
             threats.append({
                "category": "Tampering",
                "description": "Database detected in docker-compose. Potential SQL Injection or data tampering.",
                "mitigation": "Use parameterized queries and input validation."
            })
             dfd += "\n  WebApp -->|SQL| DB[(Database)];"
        elif "database" in desc_lower or "sql" in desc_lower:
             threats.append({
                "category": "Tampering",
                "description": "Potential SQL Injection or data tampering in database.",
                "mitigation": "Use parameterized queries and input validation."
            })
             dfd += "\n  WebApp -->|SQL| DB[(Database)];"

        # Auth
        if "login" in desc_lower or "auth" in desc_lower or "jwt" in str(files):
            threats.append({
                "category": "Spoofing",
                "description": "Risk of user impersonation or weak authentication.",
                "mitigation": "Implement MFA and strong session management."
            })
            
        # Docker
        if "Dockerfile" in files:
             threats.append({
                "category": "Elevation of Privilege",
                "description": "Containerized application. Risk of container breakout.",
                "mitigation": "Run as non-root user, limit capabilities."
            })
            
        if not threats:
            threats.append({
                "category": "Information Disclosure",
                "description": "General risk of data leakage.",
                "mitigation": "Ensure encryption at rest and in transit."
            })

        return {
            "system_summary": "Heuristic Analysis (LLM not configured). Based on file structure.",
            "dfd_diagram": dfd,
            "threats": threats
        }
