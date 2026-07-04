"""
Static Scanner Interface — services/scanner.py

Lightweight, dependency-free static analysis layer that mimics the output
contract of tools like Semgrep or Bandit. Designed to run at hackathon speed
(no binary invocation, no subprocess overhead) while producing structured
findings that are directly consumable by the AutonomousSecurityOrchestrator.

Architecture note
-----------------
Each rule is a self-contained RuleDefinition dataclass. Adding a new rule
means appending a single entry to RULE_REGISTRY — no other code changes needed.
"""

import re
import logging
from dataclasses import dataclass, field
from typing import Any, Optional
from enum import Enum

logger = logging.getLogger("reposhield.static_scanner")


# ---------------------------------------------------------------------------
# Severity & Category Enumerations
# ---------------------------------------------------------------------------
class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


class VulnerabilityCategory(str, Enum):
    SQL_INJECTION              = "SQL_INJECTION"
    HARDCODED_SECRET           = "HARDCODED_SECRET"
    UNVALIDATED_HEADER         = "UNVALIDATED_HEADER"
    COMMAND_INJECTION          = "COMMAND_INJECTION"
    INSECURE_DESERIALIZATION   = "INSECURE_DESERIALIZATION"
    PATH_TRAVERSAL             = "PATH_TRAVERSAL"
    WEAK_CRYPTOGRAPHY          = "WEAK_CRYPTOGRAPHY"
    OPEN_REDIRECT              = "OPEN_REDIRECT"
    DEBUG_EXPOSURE             = "DEBUG_EXPOSURE"


# ---------------------------------------------------------------------------
# Rule Definition
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class RuleDefinition:
    """Describes a single static-analysis rule."""
    rule_id:   str
    category:  VulnerabilityCategory
    severity:  Severity
    pattern:   re.Pattern                     # Compiled regex
    message:   str                            # Human-readable finding description
    cwe:       str                            # CWE reference (https://cwe.mitre.org)
    owasp:     str                            # OWASP Top-10 reference
    remediation: str                          # Short fix guidance


# ---------------------------------------------------------------------------
# Structured Finding
# ---------------------------------------------------------------------------
@dataclass
class ScanFinding:
    """One resolved vulnerability finding emitted by the scanner."""
    rule_id:          str
    category:         str
    severity:         str
    file_path:        str
    line_number:      int
    column_start:     int
    column_end:       int
    matched_snippet:  str
    message:          str
    cwe:              str
    owasp:            str
    remediation:      str
    # Agent handoff payload — mirrors the SecurityJobResponse contract
    agent_payload:    dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id":         self.rule_id,
            "category":        self.category,
            "severity":        self.severity,
            "location": {
                "file_path":    self.file_path,
                "line_number":  self.line_number,
                "column_start": self.column_start,
                "column_end":   self.column_end,
                "snippet":      self.matched_snippet,
            },
            "message":         self.message,
            "cwe":             self.cwe,
            "owasp":           self.owasp,
            "remediation":     self.remediation,
            "agent_payload":   self.agent_payload,
        }


# ---------------------------------------------------------------------------
# Rule Registry
# Each entry is a frozen RuleDefinition. Order determines scan priority.
# ---------------------------------------------------------------------------
RULE_REGISTRY: list[RuleDefinition] = [

    # ------------------------------------------------------------------
    # RS001 — Raw SQL String Concatenation (SQL Injection)
    # Matches patterns like: "SELECT * FROM users WHERE id = " + user_id
    # or f"SELECT ... {user_input}"
    # ------------------------------------------------------------------
    RuleDefinition(
        rule_id="RS001",
        category=VulnerabilityCategory.SQL_INJECTION,
        severity=Severity.CRITICAL,
        pattern=re.compile(
            r"""(?ix)
            (                                        # Variant A: string concat
                ["'`]                                # opening quote
                \s*SELECT\b.*?["'`]                  # SELECT … closing quote
                \s*[\+\%]                            # concatenation operator
                \s*\w+                               # variable being injected
            )
            |                                        # Variant B: f-string / .format
            (
                f["'`]                               # f-string prefix
                [^"'`]*
                \bSELECT\b
                [^"'`]*
                \{[^}]+\}                            # f-string interpolation
                [^"'`]*
                ["'`]
            )
            |                                        # Variant C: % formatting
            (
                ["'`][^"'`]*\bWHERE\b[^"'`]*%s[^"'`]*["'`]
            )
            """,
            re.IGNORECASE | re.VERBOSE,
        ),
        message="Raw SQL string concatenation or interpolation detected. User-controlled input may be injected directly into a SQL query, enabling SQL Injection attacks.",
        cwe="CWE-89",
        owasp="A03:2021 – Injection",
        remediation="Use parameterised queries or an ORM (e.g. SQLAlchemy `text()` with bound parameters). Never build SQL strings from user input.",
    ),

    # ------------------------------------------------------------------
    # RS002 — Hardcoded API Key / Secret Token
    # Matches common secret variable names assigned to string literals.
    # ------------------------------------------------------------------
    RuleDefinition(
        rule_id="RS002",
        category=VulnerabilityCategory.HARDCODED_SECRET,
        severity=Severity.CRITICAL,
        pattern=re.compile(
            r"""(?ix)
            (api[_\-]?key|secret[_\-]?key|access[_\-]?token|auth[_\-]?token
            |private[_\-]?key|client[_\-]?secret|password|passwd|db[_\-]?pass
            |GITHUB[_\-]TOKEN|AWS[_\-]SECRET)     # sensitive identifier names
            \s*=\s*                                # assignment
            ["'`][A-Za-z0-9+/=\-_\.]{8,}["'`]    # string literal ≥ 8 chars
            """,
            re.IGNORECASE | re.VERBOSE,
        ),
        message="Hardcoded secret or API key detected in source code. Credentials embedded in source are exposed via version control history and build artefacts.",
        cwe="CWE-798",
        owasp="A07:2021 – Identification and Authentication Failures",
        remediation="Move secrets to environment variables or a secrets manager (e.g., GCP Secret Manager, AWS Secrets Manager). Load at runtime with os.environ.get().",
    ),

    # ------------------------------------------------------------------
    # RS003 — Unvalidated HTTP Header Assignment
    # Matches direct assignments of request.headers[...] to variables
    # without any sanitisation call in the same expression.
    # ------------------------------------------------------------------
    RuleDefinition(
        rule_id="RS003",
        category=VulnerabilityCategory.UNVALIDATED_HEADER,
        severity=Severity.HIGH,
        pattern=re.compile(
            r"""(?ix)
            \b\w+\s*=\s*                            # assignment target
            request\.headers                        # header dict access
            (?:\.get\s*\([^)]+\)|\[[^\]]+\])        # .get() or [key] access
            (?!\s*\.strip|\s*\.lower|\s*\.replace   # NOT followed by sanitiser
              |\s*re\.match|\s*re\.fullmatch
              |\s*validate|\s*sanitize|\s*escape)
            """,
            re.IGNORECASE | re.VERBOSE,
        ),
        message="HTTP header value assigned to a variable without prior sanitisation. Attacker-controlled header values may propagate unsanitised into downstream logic (Header Injection / SSRF).",
        cwe="CWE-20",
        owasp="A03:2021 – Injection",
        remediation="Validate and whitelist header values before use. Use a schema validation library (Pydantic, marshmallow) or strip / escape the value before passing it downstream.",
    ),

    # ------------------------------------------------------------------
    # RS004 — Shell Command Injection via subprocess / os.system
    # Matches subprocess calls that pass shell=True with a variable.
    # ------------------------------------------------------------------
    RuleDefinition(
        rule_id="RS004",
        category=VulnerabilityCategory.COMMAND_INJECTION,
        severity=Severity.CRITICAL,
        pattern=re.compile(
            r"""(?ix)
            (os\.system|subprocess\.(call|run|Popen|check_output))
            \s*\(
            [^)]*                                    # any args
            (shell\s*=\s*True)                       # shell=True present
            [^)]*
            \)
            """,
            re.IGNORECASE | re.VERBOSE,
        ),
        message="Subprocess call with shell=True detected. If any part of the command string is user-controlled, arbitrary shell commands may be executed on the host.",
        cwe="CWE-78",
        owasp="A03:2021 – Injection",
        remediation="Pass commands as a list of arguments and set shell=False (the default). Validate and whitelist any user-controlled values before including them.",
    ),

    # ------------------------------------------------------------------
    # RS005 — Insecure Deserialization via pickle
    # ------------------------------------------------------------------
    RuleDefinition(
        rule_id="RS005",
        category=VulnerabilityCategory.INSECURE_DESERIALIZATION,
        severity=Severity.CRITICAL,
        pattern=re.compile(
            r"""(?ix)
            \bpickle\.(loads?|Unpickler)\s*\(
            """,
            re.IGNORECASE | re.VERBOSE,
        ),
        message="Pickle deserialization detected. Deserializing untrusted data with pickle allows arbitrary code execution.",
        cwe="CWE-502",
        owasp="A08:2021 – Software and Data Integrity Failures",
        remediation="Use safe serialization formats such as JSON or MessagePack. If pickle is required, sign payloads with HMAC and validate before deserializing.",
    ),

    # ------------------------------------------------------------------
    # RS006 — Path Traversal via unsanitised file path join
    # ------------------------------------------------------------------
    RuleDefinition(
        rule_id="RS006",
        category=VulnerabilityCategory.PATH_TRAVERSAL,
        severity=Severity.HIGH,
        pattern=re.compile(
            r"""(?ix)
            os\.path\.(join|open)               # path construction
            \s*\([^)]*                          # opening paren + any args
            (request\.|params\.|query\.)        # user-controlled input source
            [^)]*\)                             # closing paren
            """,
            re.IGNORECASE | re.VERBOSE,
        ),
        message="Potential path traversal: user-controlled input used directly in a file path operation without sanitisation.",
        cwe="CWE-22",
        owasp="A01:2021 – Broken Access Control",
        remediation="Resolve the final path with os.path.realpath() and assert it is within the expected base directory. Reject inputs containing '..' sequences.",
    ),

    # ------------------------------------------------------------------
    # RS007 — Weak Cryptography (MD5 / SHA1 for security purposes)
    # ------------------------------------------------------------------
    RuleDefinition(
        rule_id="RS007",
        category=VulnerabilityCategory.WEAK_CRYPTOGRAPHY,
        severity=Severity.MEDIUM,
        pattern=re.compile(
            r"""(?ix)
            hashlib\.(md5|sha1)\s*\(
            |
            Crypto\.Hash\.(MD5|SHA1)
            """,
            re.IGNORECASE | re.VERBOSE,
        ),
        message="Use of weak cryptographic hash function (MD5/SHA1) detected. These algorithms are vulnerable to collision attacks and should not be used for security-sensitive operations.",
        cwe="CWE-327",
        owasp="A02:2021 – Cryptographic Failures",
        remediation="Use SHA-256 or SHA-3 via hashlib.sha256() for security-sensitive hashing. For password hashing, use bcrypt, scrypt, or argon2.",
    ),

    # ------------------------------------------------------------------
    # RS008 — Debug Mode / Stack Trace Exposure
    # ------------------------------------------------------------------
    RuleDefinition(
        rule_id="RS008",
        category=VulnerabilityCategory.DEBUG_EXPOSURE,
        severity=Severity.MEDIUM,
        pattern=re.compile(
            r"""(?ix)
            (app\.run\s*\([^)]*debug\s*=\s*True)   # Flask debug=True
            |
            (DEBUG\s*=\s*True)                      # Django/generic DEBUG flag
            |
            (traceback\.print_exc\s*\(\s*\))        # raw traceback to stdout
            """,
            re.IGNORECASE | re.VERBOSE,
        ),
        message="Debug mode or raw stack trace exposure detected. Debug flags and unhandled traceback dumps can leak internal implementation details to end users.",
        cwe="CWE-489",
        owasp="A05:2021 – Security Misconfiguration",
        remediation="Set debug=False in production. Use structured logging with a centralised log sink rather than printing tracebacks directly to HTTP responses.",
    ),
]


# ---------------------------------------------------------------------------
# Static Scanner Interface
# ---------------------------------------------------------------------------
class StaticScannerInterface:
    """
    Lightweight static analysis engine that produces Semgrep-compatible
    structured findings without requiring any external binary.

    Intended for use during development, CI pre-checks, and hackathon demos.
    Swap `_run_rules` for a real Semgrep subprocess call when moving to
    production without changing the public `scan` interface.
    """

    def __init__(self, rules: Optional[list[RuleDefinition]] = None) -> None:
        """
        Args:
            rules: Custom rule list. Defaults to the built-in RULE_REGISTRY.
        """
        self._rules: list[RuleDefinition] = rules if rules is not None else RULE_REGISTRY

    # -----------------------------------------------------------------------
    # Internal helpers
    # -----------------------------------------------------------------------
    def _resolve_line_and_column(
        self, source: str, match_start: int, match_end: int
    ) -> tuple[int, int, int]:
        """
        Convert a flat character offset into (line_number, col_start, col_end).
        Line numbers are 1-indexed to match editor conventions.
        """
        lines_before = source[:match_start].splitlines()
        line_number  = len(lines_before) + 1
        col_start    = match_start - (len("\n".join(lines_before)) + (1 if lines_before else 0))
        col_end      = col_start + (match_end - match_start)
        return line_number, col_start, col_end

    def _build_agent_payload(
        self,
        rule: RuleDefinition,
        file_path: str,
        line_number: int,
        snippet: str,
    ) -> dict[str, Any]:
        """
        Constructs the structured handoff payload the Antigravity agent
        consumes to understand what to patch and where.
        """
        return {
            "status":               "vulnerability_detected",
            "active_file":          file_path,
            "vulnerability_rule":   rule.rule_id,
            "category":             rule.category.value,
            "severity":             rule.severity.value,
            "business_impact_score": {
                Severity.CRITICAL: 0.95,
                Severity.HIGH:     0.75,
                Severity.MEDIUM:   0.50,
                Severity.LOW:      0.25,
                Severity.INFO:     0.05,
            }.get(rule.severity, 0.5),
            "compliance_verified":  False,
            "sandbox_command":      f"semgrep --config=auto {file_path}",
            "model_armor_status":   "SCAN_FLAGGED",
            "patch_instruction":    rule.remediation,
            "location": {
                "file":   file_path,
                "line":   line_number,
                "snippet": snippet,
            },
            "pr_url": None,
        }

    def _run_rules(self, file_path: str, source_code: str) -> list[ScanFinding]:
        """
        Iterates every rule against the source code and collects all matches.
        Returns a flat list of ScanFinding objects, ordered by line number.
        """
        findings: list[ScanFinding] = []

        for rule in self._rules:
            for match in rule.pattern.finditer(source_code):
                line_no, col_start, col_end = self._resolve_line_and_column(
                    source_code, match.start(), match.end()
                )
                snippet = match.group(0).strip().replace("\n", " ")[:120]

                finding = ScanFinding(
                    rule_id         = rule.rule_id,
                    category        = rule.category.value,
                    severity        = rule.severity.value,
                    file_path       = file_path,
                    line_number     = line_no,
                    column_start    = col_start,
                    column_end      = col_end,
                    matched_snippet = snippet,
                    message         = rule.message,
                    cwe             = rule.cwe,
                    owasp           = rule.owasp,
                    remediation     = rule.remediation,
                    agent_payload   = self._build_agent_payload(
                        rule, file_path, line_no, snippet
                    ),
                )
                findings.append(finding)
                logger.warning(
                    f"[{rule.severity.value}] {rule.rule_id} ({rule.category.value}) "
                    f"— {file_path}:{line_no}:{col_start} — {snippet!r}"
                )

        # Sort by severity (CRITICAL first) then by line number
        severity_order = {s: i for i, s in enumerate(Severity)}
        findings.sort(key=lambda f: (severity_order.get(Severity(f.severity), 99), f.line_number))
        return findings

    # -----------------------------------------------------------------------
    # Public async interface
    # -----------------------------------------------------------------------
    async def scan(
        self,
        file_path: str,
        source_code: str,
    ) -> dict[str, Any]:
        """
        Asynchronously scan a code string for known vulnerability patterns.

        The method is declared async so it integrates cleanly with the FastAPI
        event loop and the AutonomousSecurityOrchestrator's async pipeline.
        The regex work itself is CPU-light enough not to require
        asyncio.to_thread for typical file sizes (< 5 000 lines).
        For very large files, wrap `_run_rules` in asyncio.to_thread.

        Args:
            file_path:   Repository-relative path used for location metadata
                         and agent handoff payload construction.
            source_code: Raw source code string to analyse.

        Returns:
            A structured result dict:
            {
                "scanned_file":   str,
                "total_findings": int,
                "has_critical":   bool,
                "findings":       list[dict],   # one per match
                "summary": {
                    "CRITICAL": int,
                    "HIGH":     int,
                    "MEDIUM":   int,
                    "LOW":      int,
                    "INFO":     int,
                }
            }
        """
        logger.info(f"StaticScannerInterface: scanning {file_path} ({len(source_code)} chars)")

        findings = self._run_rules(file_path, source_code)

        severity_summary: dict[str, int] = {s.value: 0 for s in Severity}
        for f in findings:
            severity_summary[f.severity] += 1

        result: dict[str, Any] = {
            "scanned_file":   file_path,
            "total_findings": len(findings),
            "has_critical":   severity_summary[Severity.CRITICAL.value] > 0,
            "findings":       [f.to_dict() for f in findings],
            "summary":        severity_summary,
        }

        logger.info(
            f"Scan complete — {file_path}: "
            f"{len(findings)} finding(s) | "
            + " | ".join(f"{k}:{v}" for k, v in severity_summary.items() if v)
        )
        return result
