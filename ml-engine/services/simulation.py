from typing import Dict
from utils.logging_utils import setup_logger

logger = setup_logger("attack-simulation")


class AttackSimulator:
    """Simulates security attack vectors against codebases to verify resilience."""

    # Attack payload templates by CWE target
    PAYLOADS = {
        "CWE-89": [
            "' OR '1'='1",
            "'; DROP TABLE users; --",
            "1 UNION SELECT null, username, password FROM users"
        ],
        "CWE-78": [
            "; cat /etc/passwd",
            "&& rm -rf /",
            "| ping -c 4 127.0.0.1"
        ],
        "CWE-22": [
            "../../../../etc/passwd",
            "..\\..\\..\\windows\\win.ini",
            "/absolute/unauthorized/path"
        ],
        "CWE-79": [
            "<script>alert(1)</script>",
            "\" onerror=\"alert(1)",
            "javascript:alert(1)"
        ]
    }

    @classmethod
    def simulate_attack(cls, code: str, cwe_id: str) -> Dict:
        """Evaluates a code block against simulated attack payloads.

        Checks if the code contains regex controls, sanitizers, or parameter binding
        guards that would block typical payload strings.

        Args:
            code: Source code snippet.
            cwe_id: Target vulnerability category.

        Returns:
            Dict containing:
                - ``"status"``: ``"exploitable"`` or ``"mitigated"``.
                - ``"tested_payloads"``: List of string payloads run.
                - ``"bypass_details"``: Descriptive explanation of exploit potential.
        """
        payloads = cls.PAYLOADS.get(cwe_id.upper(), ["' OR '1'='1"])
        code_lower = code.lower()
        
        # Guard/mitigation heuristic keywords
        mitigated = False
        bypass_reason = "No mitigation controls found on line content checks."
        
        if cwe_id == "CWE-89":
            # Dynamic concatenation checks
            has_concat = "+" in code_lower or ".format(" in code_lower or "f\"" in code_lower or "f'" in code_lower
            # Check for python % formatting (e.g. query % args) but ignore %s SQL placeholders
            has_modulo_fmt = "%" in code_lower and "%s" not in code_lower
            
            if "execute(" in code_lower and (has_concat or has_modulo_fmt):
                bypass_reason = "Dynamic string formatting inside query execution is highly exploitable."
            elif "%s" in code_lower and "execute" in code_lower:
                mitigated = True
                bypass_reason = "Code appears to use database parameter bindings (%s tuple parameters)."
                
        elif cwe_id == "CWE-78":
            if "shell=true" in code_lower or "system(" in code_lower:
                bypass_reason = "Shell execution environment parses commands directly, enabling command stitching."
            elif "subprocess" in code_lower and "shell=false" in code_lower:
                mitigated = True
                bypass_reason = "Subprocess invoked with shell=False, preventing command injection payload parsing."

        elif cwe_id == "CWE-22":
            if "abspath" in code_lower or "realpath" in code_lower or "startswith" in code_lower:
                mitigated = True
                bypass_reason = "Canonical target boundaries are resolved and validated (startswith check)."
            else:
                bypass_reason = "File handles inputs directly without checking for parent directory escapes (e.g. '../')."
                
        return {
            "status": "mitigated" if mitigated else "exploitable",
            "tested_payloads": payloads,
            "bypass_details": bypass_reason
        }
