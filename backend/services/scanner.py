"""
Static Scanner Interface — services/scanner.py

Lightweight AST-based static analysis layer that parses Python source code
into an Abstract Syntax Tree (AST) to identify vulnerabilities (e.g. hardcoded
secrets, raw SQL string concatenations) and determine a baseline business impact float.

Provides two scan surfaces:
  1. scan(file_path, source_code)  — inline scan of a single file's raw source
  2. scan_github_repo(repo_url)    — clone a public repo, walk all .py files,
                                     return on first vulnerability found
"""

import ast
import asyncio
import logging
import os
import shutil
import tempfile
from typing import Any, Optional
from enum import Enum

logger = logging.getLogger("reposhield.static_scanner")


# ---------------------------------------------------------------------------
# Enums
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
# AST Visitor — core detection engine
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# StaticScannerInterface — the public API consumed by pipeline and agents
# ---------------------------------------------------------------------------

class StaticScannerInterface:
    """
    AST-based vulnerability scanner.

    Two scan surfaces:
      • scan(file_path, source_code)   — parse a single raw source string
      • scan_github_repo(repo_url)     — shallow-clone a public GitHub repo,
                                          walk every .py file, return on the
                                          first vulnerability detected
    """

    # ── Timeout (seconds) for the git clone subprocess ─────────────────────
    _CLONE_TIMEOUT_SECONDS: int = 60

    def __init__(self, rules: Optional[Any] = None) -> None:
        pass

    # -----------------------------------------------------------------------
    # Inline single-file scan (used by POST /api/v1/jobs/scan)
    # -----------------------------------------------------------------------

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

    # -----------------------------------------------------------------------
    # Full-repo scan: clone → walk → AST-parse → return first vulnerability
    # -----------------------------------------------------------------------

    async def scan_github_repo(self, repo_url: str) -> dict[str, Any]:
        """
        Clone a public GitHub repository (shallow, depth=1) into a temporary
        directory, walk every .py file through the AST scanner, and return
        immediately on the first vulnerability detected.

        Returns
        -------
        dict
            On vulnerability:
                {"status": "vulnerable", "file_path": str, "raw_code": str,
                 "category": str, "business_impact": float}
            On clean scan:
                {"status": "secure"}
        """
        logger.info(f"scan_github_repo: starting shallow clone of {repo_url}")

        tmp_dir: Optional[str] = None
        try:
            # -- 1. Create a temp directory for the clone ───────────────────
            tmp_dir = tempfile.mkdtemp(prefix="reposhield_scan_")
            logger.debug(f"Temporary clone directory: {tmp_dir}")

            # -- 2. Shallow clone via asyncio subprocess ────────────────────
            proc = await asyncio.create_subprocess_exec(
                "git", "clone", "--depth", "1", repo_url, ".",
                cwd=tmp_dir,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=self._CLONE_TIMEOUT_SECONDS,
                )
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
                logger.error(
                    f"git clone timed out after {self._CLONE_TIMEOUT_SECONDS}s for {repo_url}"
                )
                return {"status": "error", "message": "git clone timed out"}

            if proc.returncode != 0:
                err_msg = stderr.decode(errors="replace").strip()
                logger.error(f"git clone failed (rc={proc.returncode}): {err_msg}")
                return {"status": "error", "message": f"git clone failed: {err_msg}"}

            logger.info(f"Shallow clone complete for {repo_url}")

            # -- 3. Walk .py files and AST-scan each ────────────────────────
            for dirpath, _dirnames, filenames in os.walk(tmp_dir):
                # Skip hidden directories (.git, .github, etc.)
                rel_dir = os.path.relpath(dirpath, tmp_dir)
                if any(part.startswith(".") for part in rel_dir.split(os.sep) if part != "."):
                    continue

                for filename in filenames:
                    if not filename.endswith(".py"):
                        continue

                    abs_path = os.path.join(dirpath, filename)
                    relative_path = os.path.relpath(abs_path, tmp_dir)

                    try:
                        with open(abs_path, "r", encoding="utf-8", errors="replace") as fh:
                            source_code = fh.read()
                    except OSError as read_err:
                        logger.warning(f"Could not read {relative_path}: {read_err}")
                        continue

                    # Skip empty files
                    if not source_code.strip():
                        continue

                    # Parse the AST
                    try:
                        tree = ast.parse(source_code, filename=relative_path)
                    except SyntaxError:
                        logger.debug(f"SyntaxError in {relative_path} — skipping")
                        continue

                    scanner = ASTScanner(relative_path, source_code)
                    scanner.visit(tree)

                    if scanner.findings:
                        first = scanner.findings[0]
                        category_label = first["category"].value
                        impact = first["business_impact_float"]

                        logger.warning(
                            f"Vulnerability detected in {relative_path}: "
                            f"{category_label} (impact={impact})"
                        )

                        return {
                            "status":          "vulnerable",
                            "file_path":       relative_path,
                            "raw_code":        source_code,
                            "category":        category_label,
                            "business_impact": impact,
                        }

            # -- 4. No vulnerabilities found ────────────────────────────────
            logger.info(f"scan_github_repo: no vulnerabilities found in {repo_url}")
            return {"status": "secure"}

        except Exception as exc:
            logger.error(f"scan_github_repo unexpected error: {exc}", exc_info=True)
            return {"status": "error", "message": str(exc)}

        finally:
            # -- 5. Cleanup temp directory ──────────────────────────────────
            if tmp_dir and os.path.isdir(tmp_dir):
                try:
                    shutil.rmtree(tmp_dir, ignore_errors=True)
                    logger.debug(f"Cleaned up temp directory: {tmp_dir}")
                except Exception as cleanup_err:
                    logger.warning(f"Failed to clean temp directory {tmp_dir}: {cleanup_err}")
