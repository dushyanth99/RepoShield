"""
Static Scanner Interface — services/scanner.py

Lightweight AST-based static analysis layer that parses Python source code
into an Abstract Syntax Tree (AST) to identify vulnerabilities (e.g. hardcoded
secrets, raw SQL string concatenations) and determine a baseline business impact float.
"""

import ast
import logging
from typing import Any, Optional
from enum import Enum

logger = logging.getLogger("reposhield.static_scanner")

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

class ASTScanner(ast.NodeVisitor):
    """
    AST Visitor to actively scan Python code for vulnerability patterns:
    1. Hardcoded Secrets (Assignments of string literals >= 8 chars to sensitive variable names).
    2. SQL Injection (Raw string concatenation or f-string interpolation containing SQL keywords).
    """
    def __init__(self, file_path: str, source_code: str):
        self.file_path = file_path
        self.source_code = source_code.splitlines()
        self.raw_source = source_code
        self.findings = []

    def visit_Assign(self, node: ast.Assign):
        # Scan for hardcoded secret assignments
        for target in node.targets:
            if isinstance(target, ast.Name):
                name = target.id
                secret_keywords = [
                    "api_key", "secret_key", "access_token", "auth_token", 
                    "private_key", "client_secret", "password", "passwd", 
                    "db_pass", "github_token", "aws_secret"
                ]
                if any(kw in name.lower() for kw in secret_keywords):
                    value_str = None
                    if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                        value_str = node.value.value
                    elif isinstance(node.value, ast.Str):
                        value_str = node.value.s
                    
                    if value_str and len(value_str) >= 8:
                        line_no = node.lineno
                        col_offset = node.col_offset
                        snippet = self.source_code[line_no-1] if 0 < line_no <= len(self.source_code) else ""
                        self.findings.append({
                            "rule_id": "RS002",
                            "category": VulnerabilityCategory.HARDCODED_SECRET,
                            "severity": Severity.CRITICAL,
                            "line_number": line_no,
                            "column_start": col_offset,
                            "column_end": col_offset + len(name) + len(value_str) + 3,
                            "matched_snippet": snippet.strip()[:120],
                            "message": "Hardcoded secret or API key detected in source code.",
                            "cwe": "CWE-798",
                            "owasp": "A07:2021 – Identification and Authentication Failures",
                            "remediation": "Move secrets to environment variables or a secrets manager. Load at runtime with os.environ.get().",
                            "business_impact_float": 0.95
                        })
        self.generic_visit(node)

    def visit_BinOp(self, node: ast.BinOp):
        # Scan for raw SQL string concatenation
        if isinstance(node.op, ast.Add):
            left_str = self._get_constant_str(node.left)
            right_str = self._get_constant_str(node.right)
            sql_keywords = ["select", "insert", "update", "delete", "where", "from", "join"]
            
            has_sql = False
            if left_str and any(kw in left_str.lower() for kw in sql_keywords):
                has_sql = True
            if right_str and any(kw in right_str.lower() for kw in sql_keywords):
                has_sql = True
                
            if has_sql:
                line_no = node.lineno
                col_offset = node.col_offset
                snippet = self.source_code[line_no-1] if 0 < line_no <= len(self.source_code) else ""
                self.findings.append({
                    "rule_id": "RS001",
                    "category": VulnerabilityCategory.SQL_INJECTION,
                    "severity": Severity.CRITICAL,
                    "line_number": line_no,
                    "column_start": col_offset,
                    "column_end": col_offset + 40,
                    "matched_snippet": snippet.strip()[:120],
                    "message": "Raw SQL string concatenation detected. User-controlled input may be injected directly into a SQL query.",
                    "cwe": "CWE-89",
                    "owasp": "A03:2021 – Injection",
                    "remediation": "Use parameterised queries or an ORM. Never build SQL strings from user input.",
                    "business_impact_float": 0.95
                })
        self.generic_visit(node)

    def visit_JoinedStr(self, node: ast.JoinedStr):
        # Scan for SQL f-string interpolation
        has_sql = False
        has_expr = False
        sql_keywords = ["select", "insert", "update", "delete", "where", "from", "join"]
        
        for val in node.values:
            if isinstance(val, ast.FormattedValue):
                has_expr = True
            else:
                val_str = self._get_constant_str(val)
                if val_str and any(kw in val_str.lower() for kw in sql_keywords):
                    has_sql = True
                    
        if has_sql and has_expr:
            line_no = node.lineno
            col_offset = node.col_offset
            snippet = self.source_code[line_no-1] if 0 < line_no <= len(self.source_code) else ""
            self.findings.append({
                "rule_id": "RS001",
                "category": VulnerabilityCategory.SQL_INJECTION,
                "severity": Severity.CRITICAL,
                "line_number": line_no,
                "column_start": col_offset,
                "column_end": col_offset + 50,
                "matched_snippet": snippet.strip()[:120],
                "message": "Raw SQL string interpolation (f-string) detected. User-controlled input may be injected directly into a SQL query.",
                "cwe": "CWE-89",
                "owasp": "A03:2021 – Injection",
                "remediation": "Use parameterised queries or an ORM. Never build SQL strings from user input.",
                "business_impact_float": 0.95
            })
        self.generic_visit(node)

    def _get_constant_str(self, node) -> Optional[str]:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        elif isinstance(node, ast.Str):
            return node.s
        return None

class StaticScannerInterface:
    """
    AST-based vulnerability scanner that parses Python source code.
    Identifies flaws, calculates business impact, and returns structured findings.
    """
    def __init__(self, rules: Optional[Any] = None) -> None:
        pass

    async def scan(self, file_path: str, source_code: str) -> dict[str, Any]:
        logger.info(f"StaticScannerInterface: AST scanning {file_path} ({len(source_code)} chars)")
        
        try:
            tree = ast.parse(source_code)
            scanner = ASTScanner(file_path, source_code)
            scanner.visit(tree)
            findings = scanner.findings
        except Exception as e:
            logger.error(f"AST parsing failed for {file_path}: {e}")
            findings = []

        severity_summary = {s.value: 0 for s in Severity}
        formatted_findings = []

        for f in findings:
            severity_val = f["severity"].value
            severity_summary[severity_val] += 1
            
            agent_payload = {
                "status":               "vulnerability_detected",
                "active_file":          file_path,
                "vulnerability_rule":   f["rule_id"],
                "category":             f["category"].value,
                "severity":             severity_val,
                "business_impact_score": f["business_impact_float"],
                "compliance_verified":  False,
                "sandbox_command":      f"semgrep --config=auto {file_path}",
                "model_armor_status":   "SCAN_FLAGGED",
                "patch_instruction":    f["remediation"],
                "location": {
                    "file":    file_path,
                    "line":    f["line_number"],
                    "snippet": f["matched_snippet"],
                },
                "pr_url": None,
            }

            formatted_findings.append({
                "rule_id": f["rule_id"],
                "category": f["category"].value,
                "severity": severity_val,
                "location": {
                    "file_path": file_path,
                    "line_number": f["line_number"],
                    "column_start": f["column_start"],
                    "column_end": f["column_end"],
                    "snippet": f["matched_snippet"],
                },
                "message": f["message"],
                "cwe": f["cwe"],
                "owasp": f["owasp"],
                "remediation": f["remediation"],
                "agent_payload": agent_payload,
            })

        result: dict[str, Any] = {
            "scanned_file":   file_path,
            "total_findings": len(formatted_findings),
            "has_critical":   severity_summary[Severity.CRITICAL.value] > 0,
            "findings":       formatted_findings,
            "summary":        severity_summary,
        }

        logger.info(
            f"AST Scan complete — {file_path}: "
            f"{len(formatted_findings)} finding(s) | "
            + " | ".join(f"{k}:{v}" for k, v in severity_summary.items() if v)
        )
        return result
