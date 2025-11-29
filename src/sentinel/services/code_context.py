import os
from typing import List, Dict

class CodebaseSummarizer:
    """
    Summarizes a codebase to provide technical context for AI analysis.
    """
    
    IMPORTANT_FILES = [
        "Dockerfile", "docker-compose.yml", "docker-compose.yaml",
        "requirements.txt", "Pipfile", "pyproject.toml",
        "package.json", "yarn.lock",
        "pom.xml", "build.gradle",
        "go.mod",
        "Cargo.toml",
        "openapi.json", "openapi.yaml", "swagger.json", "swagger.yaml",
        "serverless.yml", "netlify.toml", "vercel.json"
    ]

    def summarize(self, root_path: str) -> dict:
        """
        Generates a summary of the codebase at root_path.
        """
        return {
            "file_tree": self._generate_tree(root_path),
            "key_files": self._read_key_files(root_path)
        }

    def _generate_tree(self, root_path: str, max_depth: int = 2) -> str:
        """Generates a text representation of the file tree."""
        tree_lines = []
        root_path = os.path.abspath(root_path)
        
        for root, dirs, files in os.walk(root_path):
            # Calculate current depth
            rel_path = os.path.relpath(root, root_path)
            if rel_path == ".":
                depth = 0
            else:
                depth = rel_path.count(os.sep) + 1
                
            if depth > max_depth:
                del dirs[:] # Stop recursing
                continue
                
            # Filter ignored dirs
            dirs[:] = [d for d in dirs if not d.startswith(".") and d not in ["node_modules", "venv", "__pycache__", "target", "dist", "build"]]
            
            indent = "  " * depth
            if rel_path != ".":
                tree_lines.append(f"{indent}{os.path.basename(root)}/")
            
            for f in files:
                if not f.startswith("."):
                    tree_lines.append(f"{indent}  {f}")
                    
        return "\n".join(tree_lines)

    def _read_key_files(self, root_path: str) -> Dict[str, str]:
        """Reads content of important configuration files."""
        file_contents = {}
        
        for root, _, files in os.walk(root_path):
            for f in files:
                if f in self.IMPORTANT_FILES:
                    full_path = os.path.join(root, f)
                    rel_path = os.path.relpath(full_path, root_path)
                    
                    # Limit file size to avoid blowing up context
                    try:
                        if os.path.getsize(full_path) < 20 * 1024: # 20KB limit
                            with open(full_path, "r", errors="ignore") as f_obj:
                                file_contents[rel_path] = f_obj.read()
                        else:
                            file_contents[rel_path] = "(File too large)"
                    except Exception:
                        file_contents[rel_path] = "(Error reading file)"
                        
            # Don't recurse too deep for this
            if root.count(os.sep) - root_path.count(os.sep) > 2:
                break
                
        return file_contents
