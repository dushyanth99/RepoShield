import difflib
from typing import Dict
from services.recommender import SecurityRecommender
from utils.logging_utils import setup_logger

logger = setup_logger("patch-generator")


class AIPatchGenerator:
    """Generates suggested diff patches and corrected function replacements for detected vulnerabilities."""

    @staticmethod
    def generate_patch(code: str, cwe_id: str, language: str = "python") -> Dict[str, str]:
        """Generates a suggested secure code version and computes a unified diff patch.

        Args:
            code: The original vulnerable function source code string.
            cwe_id: Inferred CWE identifier (e.g. ``"CWE-89"``).
            language: Programming language name hint.

        Returns:
            Dict containing:
                - ``"original_code"``: Raw input code.
                - ``"patched_code"``: Corrected/secured code replacement.
                - ``"diff"``: Unified diff output.
        """
        remediation = SecurityRecommender.generate(cwe_id, code, "High", language)
        example_secure = remediation.get("example_secure_implementation", "")
        
        original_lines = code.splitlines(keepends=True)
        
        # Build corrected code structure by wrapping or replacing parts of code with the secure template
        # For hackathon grade execution, we suggest a replacement snippet based on secure templates
        patched_code = (
            f"# Suggested Secure Replacement for {cwe_id}\n"
            f"# Remediation Recommendation: {remediation.get('secure_coding_recommendation')}\n"
            f"{example_secure}\n"
        )
        
        patched_lines = patched_code.splitlines(keepends=True)
        
        # Calculate Unified Diff
        diff_generator = difflib.unified_diff(
            original_lines,
            patched_lines,
            fromfile="vulnerable_function.py",
            tofile="secured_function.py",
            n=3
        )
        
        diff_str = "".join(diff_generator)
        
        return {
            "original_code": code,
            "patched_code": patched_code,
            "diff": diff_str
        }
