import os
import ast
import re
from pathlib import Path
from utils.logging_utils import setup_logger
from predict import VulnerabilityPredictor
from services.risk_scorer import RepositoryRiskScorer
from services.recommender import SecurityRecommender

logger = setup_logger("scanner-service")

# Map file extensions to their corresponding programming language name
EXT_TO_LANG = {
    ".py": "Python",
    ".java": "Java",
    ".js": "JavaScript",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".c": "C",
    ".cpp": "C++",
    ".cc": "C++",
    ".h": "C",
    ".hpp": "C++",
    ".go": "Go",
    ".php": "PHP",
    ".rs": "Rust"
}

def extract_python_functions(code_content: str) -> list:
    """Extracts function names, source code, and line numbers from Python code using AST."""
    try:
        tree = ast.parse(code_content)
        functions = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                segment = ast.get_source_segment(code_content, node)
                if segment:
                    functions.append((node.name, segment, node.lineno))
        return functions
    except Exception as e:
        logger.debug(f"AST parsing failed: {e}. Fallback to bracket matching.")
        return []

def extract_brace_functions(code_content: str) -> list:
    """Extracts function names, source code, and line numbers from brace-based languages (C, C++, Java, JS, TS, Go, PHP)."""
    # Pattern looks for letters/words followed by parentheses and an open curly brace
    # Group 1 captures the potential function name
    pattern = re.compile(r'\b([a-zA-Z_]\w*)\s*\([^)]*\)\s*\{')
    functions = []
    
    for match in pattern.finditer(code_content):
        name = match.group(1)
        # Skip standard control keywords
        if name in ('if', 'for', 'while', 'switch', 'catch', 'synchronized', 'func'):
            continue
            
        start_idx = match.start()
        brace_start = match.end() - 1
        
        # Match curly braces forward
        brace_count = 0
        end_idx = -1
        for idx in range(brace_start, len(code_content)):
            char = code_content[idx]
            if char == '{':
                brace_count += 1
            elif char == '}':
                brace_count -= 1
                if brace_count == 0:
                    end_idx = idx + 1
                    break
                    
        if end_idx != -1:
            func_code = code_content[start_idx:end_idx]
            lineno = code_content[:start_idx].count('\n') + 1
            functions.append((name, func_code, lineno))
            
    return functions

class RepositoryScanner:
    """Recursively scans folders for vulnerable functions across multiple programming languages."""
    
    def __init__(self, predictor: VulnerabilityPredictor = None):
        self.predictor = predictor or VulnerabilityPredictor()
        
    def scan_file(self, file_path: Path) -> list:
        """Parses a file and runs vulnerability predictions on all its functions."""
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                code_content = f.read()
        except Exception as e:
            logger.error(f"Failed to read file {file_path}: {e}")
            return []
            
        ext = file_path.suffix.lower()
        functions = []
        lang = EXT_TO_LANG.get(ext, "")
        
        if ext == ".py":
            functions = extract_python_functions(code_content)
            if not functions:
                functions = extract_brace_functions(code_content)
        elif ext in EXT_TO_LANG:
            functions = extract_brace_functions(code_content)
            
        results = []
        for name, func_code, lineno in functions:
            # 1. Run inference & hybrid detection
            pred = self.predictor.predict(func_code, file_path=str(file_path))
            pred["function_name"] = name
            pred["line_number"] = lineno
            pred["language"] = lang
            
            # 2. Enrich with structured security recommendation advisory if vulnerable
            if pred["vulnerable"]:
                cwe_id = pred["predicted_cwe"]
                severity = pred["severity"]
                remediation = SecurityRecommender.generate(cwe_id, func_code, severity, language=lang)
                pred["remediation"] = remediation
                
            results.append(pred)
            
        return results

    def scan_directory(self, dir_path: str) -> dict:
        """Scans a directory recursively and aggregates vulnerability results and risk scores."""
        root_path = Path(dir_path).resolve()
        if not root_path.exists():
            return {
                "status": "error",
                "message": f"Path {dir_path} does not exist."
            }
            
        logger.info(f"Starting scan on directory: {root_path}...")
        
        total_files = 0
        total_functions = 0
        vulnerabilities_found = []
        
        # Supported extensions
        target_exts = set(EXT_TO_LANG.keys())
        
        for root, dirs, files in os.walk(root_path):
            # Skip hidden folders and runtime environments
            dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ('venv', '.git', '__pycache__', 'node_modules')]
            
            for file in files:
                file_p = Path(root) / file
                if file_p.suffix.lower() in target_exts:
                    total_files += 1
                    file_results = self.scan_file(file_p)
                    total_functions += len(file_results)
                    
                    try:
                        relative_file_path = str(file_p.relative_to(root_path))
                    except ValueError:
                        relative_file_path = str(file_p)
                        
                    for res in file_results:
                        if res["vulnerable"]:
                            # Structured format for vulnerabilities_found conforming to Phase 12 schema
                            remed = res.get("remediation", {})
                            vulnerabilities_found.append({
                                "type": res["cwe_name"] or "Security Risk",
                                "severity": res["severity"],
                                "confidence": res["confidence"],
                                "predicted_cwe": res["predicted_cwe"],
                                "owasp": res["owasp"] or "Unknown",
                                "file": relative_file_path,
                                "function": f"{res['function_name']}()",
                                "lines": f"{res['line_number']}-{res['line_number'] + res['explanation']['vulnerable_lines'][-1] - res['explanation']['vulnerable_lines'][0] if res['explanation']['vulnerable_lines'] else res['line_number']}",
                                "reason": res["explanation"]["reason"],
                                "recommendation": res["recommendation"],
                                "risk_score": res["confidence"], # internal metric
                                "remediation": remed
                            })
                            
        # Aggregate scores using the RepositoryRiskScorer
        metrics = RepositoryRiskScorer.calculate_scores(vulnerabilities_found, total_files, total_functions)
        
        # Format the response to fit exactly the requested Phase 12 schema
        response = {
            "status": "completed",
            "repository_score": metrics["repository_score"],
            "security_grade": metrics["security_grade"],
            "business_impact": metrics["business_impact"],
            "business_impact_score": metrics["business_impact_score"],
            "confidence": metrics["confidence"],
            "vulnerabilities": vulnerabilities_found,
            "metrics": {
                "files_scanned": total_files,
                "functions_scanned": total_functions,
                "total_vulnerabilities": len(vulnerabilities_found),
                "critical_issues": metrics["critical_issues"],
                "high_issues": metrics["high_issues"],
                "medium_issues": metrics["medium_issues"],
                "low_issues": metrics["low_issues"]
            }
        }
        
        logger.info(f"Scan complete. Scanned {total_files} files, {total_functions} functions. Found {len(vulnerabilities_found)} vulnerabilities. Grade: {metrics['security_grade']}.")
        return response
