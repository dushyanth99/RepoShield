import re
from typing import Dict, Any

class HybridDetector:
    """Combines CodeBERT ML model predictions, static pattern matching, and file metadata."""
    
    def __init__(self):
        # SQL Injection patterns
        self.sql_injection_re = re.compile(
            r'(select|insert|update|delete|replace).*?\+.*?(?:\'|")|'
            r'(select|insert|update|delete|replace).*?\.format\(|'
            r'f"(?:select|insert|update|delete|replace).*?\{',
            re.IGNORECASE | re.DOTALL
        )
        
        # OS Command Injection patterns
        self.cmd_injection_re = re.compile(
            r'(?:system|popen|subprocess\.run|subprocess\.Popen|subprocess\.call|subprocess\.check_output)\s*\([^)]*?(?:\+|,|\.format|f"|f\').*?\)',
            re.IGNORECASE | re.DOTALL
        )
        
        # Hardcoded Credentials / Secrets patterns
        self.secrets_re = re.compile(
            r'(?:api_key|apikey|secret|password|passwd|private_key|token|auth_token|jwt_secret)\s*=\s*[\'"][a-zA-Z0-9_\-\+\/]{16,}["\']',
            re.IGNORECASE
        )
        
        # Path Traversal patterns
        self.path_traversal_re = re.compile(
            r'(?:open|send_file|File|FileInputStream)\s*\([^)]*?(?:request\.args|params|input|filename|\+).*?(?:\.\./|\.\.\\).*?\)',
            re.IGNORECASE
        )
        
        # Unsafe Deserialization
        self.deserialization_re = re.compile(
            r'(?:pickle\.loads|pickle\.load|yaml\.load|yaml\.unsafe_load|jsonpickle\.decode|marshal\.loads)',
            re.IGNORECASE
        )

    def analyze(self, code: str, ml_prediction: Dict[str, Any], language: str = "", file_path: str = "") -> Dict[str, Any]:
        """Aggregates ML predictions with static analysis rules and file metadata.
        
        Args:
            code: Source code snippet.
            ml_prediction: Result dictionary from VulnerabilityPredictor.predict(code).
            language: Programming language name.
            file_path: Optional local relative file path of the snippet.
            
        Returns:
            Dict containing the aggregate prediction, aggregated confidence, and matching rules list.
        """
        # Start with ML prediction values
        vulnerable = ml_prediction["vulnerable"]
        ml_confidence = ml_prediction["confidence"]
        predicted_cwe = ml_prediction["predicted_cwe"]
        
        static_matches = []
        cwe_candidates = []
        
        # 1. Static pattern rule checks
        if self.deserialization_re.search(code):
            static_matches.append("Unsafe deserialization detected (potential object injection).")
            cwe_candidates.append(("CWE-502", 0.95))
            
        if self.sql_injection_re.search(code):
            static_matches.append("Potential SQL Injection: dynamic SQL query construction.")
            cwe_candidates.append(("CWE-89", 0.90))
            
        if self.cmd_injection_re.search(code):
            static_matches.append("OS Command Injection pattern found: unsanitized command parameter.")
            cwe_candidates.append(("CWE-78", 0.92))
            
        if self.secrets_re.search(code):
            static_matches.append("Hardcoded credential or sensitive secret token detected.")
            cwe_candidates.append(("CWE-798", 0.95))
            
        if self.path_traversal_re.search(code):
            static_matches.append("Potential Path Traversal pattern in file input/output stream.")
            cwe_candidates.append(("CWE-22", 0.85))

        # 2. Metadata Contextual analysis
        path_lower = file_path.lower()
        if "test" in path_lower or "mock" in path_lower or "fixture" in path_lower:
            # Metadata rule: Vulnerabilities in test/mock files are lower severity and less likely to be actual risks
            # De-escalate ML confidence slightly for tests to avoid high false positives in test suites
            if vulnerable:
                ml_confidence = max(ml_confidence - 0.25, 0.4)
                if ml_confidence < 0.5:
                    vulnerable = False
                    
        # 3. Hybrid aggregation logic
        # If static pattern matches, but ML says safe, boost vulnerability determination if patterns are clear
        static_found = len(static_matches) > 0
        
        if static_found:
            # High certainty static matches override marginal ML "safe" predictions
            if not vulnerable and ml_confidence < 0.65:
                vulnerable = True
                ml_confidence = max(ml_confidence, 0.70)
                # Map CWE from static analysis candidates
                if cwe_candidates:
                    predicted_cwe = cwe_candidates[0][0]
            elif vulnerable:
                # If both ML and static agree, boost confidence
                ml_confidence = min(ml_confidence + 0.1, 1.0)
                if cwe_candidates and not predicted_cwe:
                    predicted_cwe = cwe_candidates[0][0]
        
        return {
            "vulnerable": bool(vulnerable),
            "confidence": round(ml_confidence, 4),
            "static_patterns_triggered": static_matches,
            "static_cwe_candidates": [cwe for cwe, _ in cwe_candidates],
            "predicted_cwe": predicted_cwe
        }
