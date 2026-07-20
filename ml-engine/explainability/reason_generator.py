from typing import List, Optional

from utils.logging_utils import setup_logger

logger = setup_logger("explainability.reason_generator")


class ReasonGenerator:
    """Generates human-readable and structural reasons for model vulnerability predictions."""

    @staticmethod
    def generate_reason(
        vulnerable_lines: List[int],
        code: str,
        cwe_id: Optional[str] = None,
    ) -> str:
        """Formulates a structural explanation describing why the code snippet was flagged.

        If cwe_id is provided, maps directly to that CWE. Otherwise, scans line content
        for common vulnerability patterns.

        Args:
            vulnerable_lines: 1-indexed line numbers with high model attention.
            code: Original source code string.
            cwe_id: Inferred CWE vulnerability identifier (e.g. ``"CWE-89"``), or None.

        Returns:
            A single sentence describing the detected hazard.
        """
        if not isinstance(code, str):
            logger.warning("generate_reason received non-string code input: %s", type(code))
            return "Vulnerability detected in logical flow of code execution blocks."

        if not vulnerable_lines:
            logger.debug("No vulnerable lines provided; returning generic fallback reason.")
            return (
                "No localized vulnerability patterns detected. "
                "The hazard might be related to global system interactions."
            )

        lines = code.splitlines()
        primary_line = vulnerable_lines[0]

        # Guard against line number exceeding actual code length
        if primary_line > len(lines) or primary_line < 1:
            logger.warning(
                "primary_line %d is out of bounds for code with %d lines.",
                primary_line,
                len(lines),
            )
            return "Vulnerability detected in logical flow of code execution blocks."

        line_content = lines[primary_line - 1].strip()
        cwe = (cwe_id or "").upper().strip()

        # 1. Direct CWE-ID logic (Explicitly requested CWE classification)
        if cwe == "CWE-78":
            return f"Line {primary_line} executes shell commands directly using variable parameters ('{line_content[:60]}...')."
        
        if cwe == "CWE-89":
            return f"Line {primary_line} constructs a dynamic SQL query via string formatting/concatenation ('{line_content[:60]}...')."
            
        if cwe == "CWE-502":
            return f"Line {primary_line} deserializes untrusted data inputs, risking remote command execution."
            
        if cwe == "CWE-22":
            return f"Line {primary_line} performs filesystem access without checking for path traversal markers (e.g. '../')."
            
        if cwe == "CWE-798":
            return f"Line {primary_line} contains hardcoded security secret tokens or key credentials."
            
        if cwe == "CWE-79":
            return f"Line {primary_line} injects unsanitized user input directly into the browser DOM, enabling XSS attacks."
            
        if cwe == "CWE-94":
            return f"Line {primary_line} evaluates dynamic code expressions from untrusted input, enabling arbitrary code execution."
            
        if cwe == "CWE-312":
            return f"Line {primary_line} stores or logs sensitive information in cleartext, risking unauthorized disclosure."
            
        if cwe in ("CWE-327", "CWE-330"):
            return f"Line {primary_line} uses a broken or insufficiently random cryptographic primitive."

        # 2. Heuristic signatures fallback (if cwe_id is not specified or not recognized)
        if "system(" in line_content or "popen(" in line_content or "subprocess" in line_content:
            return f"Line {primary_line} executes shell commands directly using variable parameters ('{line_content[:60]}...')."

        if "select" in line_content.lower() or "execute(" in line_content.lower():
            if "+" in line_content or "%" in line_content or "format(" in line_content or 'f"' in line_content:
                return f"Line {primary_line} constructs a dynamic SQL query via string formatting/concatenation ('{line_content[:60]}...')."
            return f"Line {primary_line} executes database queries with unparameterized variables."

        if "pickle.load" in line_content or "yaml.load" in line_content or "marshal.loads" in line_content:
            return f"Line {primary_line} deserializes untrusted data inputs, risking remote command injection."

        if "open(" in line_content or "File(" in line_content:
            return f"Line {primary_line} performs filesystem access without checking for path traversal markers (e.g. '../')."

        if "api_key" in line_content or "secret" in line_content or "password" in line_content:
            return f"Line {primary_line} contains hardcoded security secret tokens or key credentials."

        if "innerhtml" in line_content.lower() or "document.write" in line_content.lower():
            return f"Line {primary_line} injects unsanitized user input directly into the browser DOM, enabling XSS attacks."

        if "eval(" in line_content or "exec(" in line_content:
            return f"Line {primary_line} evaluates dynamic code expressions from untrusted input, enabling arbitrary code execution."

        if "md5" in line_content.lower() or "sha1" in line_content.lower() or "random.random" in line_content:
            return f"Line {primary_line} uses a broken or insufficiently random cryptographic primitive."

        # Generic structural feedback
        logger.debug("No specific CWE or heuristic matched; using generic reason.")
        return (
            f"Line {primary_line} contains operations ('{line_content[:50]}...') "
            "matching vulnerability signature rules."
        )

    @staticmethod
    def generate_human_explanation(
        cwe_id: Optional[str],
        cwe_name: Optional[str],
        severity: str,
        reason: str,
    ) -> str:
        """Compiles a complete human-readable summary of the vulnerability.

        Suitable for display in dashboards, issue trackers, or executive reports.

        Args:
            cwe_id: CWE identifier (e.g. ``"CWE-89"``), or None.
            cwe_name: Human-readable CWE name, or None.
            severity: Severity rating string (e.g. ``"Critical"``, ``"High"``).
            reason: One-sentence line-level reason from :meth:`generate_reason`.

        Returns:
            Multi-sentence human-readable explanation string.
        """
        cwe_label = f"{cwe_id} ({cwe_name})" if cwe_id and cwe_name else (cwe_id or "Security Issue")
        parts = [
            f"Vulnerability Alert: A {severity}-severity risk corresponding to {cwe_label} was detected.",
            f"Explanation: {reason}",
            "Impact: If exploited, this could compromise the system confidentiality, integrity, or execution context.",
            "Action Required: Apply recommended security controls and replace dynamic variables with safe programming APIs.",
        ]
        return " ".join(parts)
