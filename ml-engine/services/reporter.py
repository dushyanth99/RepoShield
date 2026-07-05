from typing import Dict, Any
from pathlib import Path
from utils.logging_utils import setup_logger

logger = setup_logger("reporter-service")

class ExecutiveReporter:
    """Generates structured Markdown executive security reports from scanner results."""
    
    @staticmethod
    def generate_report(scan_results: Dict[str, Any], output_path: str = "") -> str:
        """Translates scanner JSON outputs into a formatted Markdown report.
        
        Args:
            scan_results: Scanner aggregate scan results dictionary.
            output_path: Optional file path to write report to.
            
        Returns:
            The markdown report string.
        """
        metrics = scan_results.get("metrics", {})
        vulnerabilities = scan_results.get("vulnerabilities", [])
        
        # Aggregate compliance violations
        compliance_violations = set()
        from services.agent_orchestrator import ComplianceAgent
        comp_agent = ComplianceAgent()
        
        for vuln in vulnerabilities:
            cwe = vuln.get("predicted_cwe")
            if cwe:
                for issue in comp_agent.assess(cwe):
                    compliance_violations.add(issue)
                    
        total_vulns = len(vulnerabilities)
        
        # Build Markdown report
        report = []
        report.append("# RepoShield Executive Security Report")
        report.append("\n## 1. Executive Summary")
        report.append("This report details the security architecture evaluation and risk profile of the scanned codebase. "
                      "RepoShield utilizes fine-tuned CodeBERT semantics, regulatory compliance checkers, and hybrid static heuristics "
                      "to identify software vulnerabilities and policy violations.")
                      
        # Scorecard
        report.append("\n### Security Scorecard")
        report.append(f"- **Security Grade:** `{scan_results.get('security_grade', 'A')}`")
        report.append(f"- **Security Score:** `{scan_results.get('repository_score', 100)}/100` (Higher is better)")
        report.append(f"- **Business Impact Severity:** `{scan_results.get('business_impact', 'Low')}`")
        report.append(f"- **Vulnerability Density:** `{round((total_vulns / metrics.get('functions_scanned', 1)) * 100, 2) if metrics.get('functions_scanned') else 0.0}%` of functions flagged.")
        
        # Metrics Table
        report.append("\n### Scan Scope & Coverage")
        report.append("| Metric | Count |")
        report.append("| :--- | :--- |")
        report.append(f"| Files Scanned | {metrics.get('files_scanned', 0)} |")
        report.append(f"| Functions Analyzed | {metrics.get('functions_scanned', 0)} |")
        report.append(f"| Total Vulnerabilities Identified | {total_vulns} |")
        report.append(f"| Critical Issues | {metrics.get('critical_issues', 0)} |")
        report.append(f"| High Issues | {metrics.get('high_issues', 0)} |")
        report.append(f"| Medium Issues | {metrics.get('medium_issues', 0)} |")
        report.append(f"| Low Issues | {metrics.get('low_issues', 0)} |")
        
        # Regulatory Compliance
        report.append("\n## 2. Regulatory Compliance Posture")
        if compliance_violations:
            report.append("The following regulatory standards, compliance frameworks, or secure coding guidelines are actively violated by the detected issues:")
            for violation in sorted(compliance_violations):
                report.append(f"- **Non-compliance:** `{violation}`")
        else:
            report.append("✅ No regulatory compliance violations identified in the analyzed scope.")
            
        # Top Vulnerabilities
        report.append("\n## 3. High-Risk Vulnerability Details")
        if vulnerabilities:
            # Sort findings by severity weight
            sev_weights = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
            sorted_vulns = sorted(vulnerabilities, key=lambda v: sev_weights.get(v.get("severity", "Medium"), 2), reverse=True)
            
            for idx, vuln in enumerate(sorted_vulns[:10], 1): # list top 10 issues
                report.append(f"\n### [{idx}] {vuln.get('type')} ({vuln.get('severity')})")
                report.append(f"- **CWE Mapping:** `{vuln.get('predicted_cwe')}`")
                report.append(f"- **OWASP Category:** `{vuln.get('owasp')}`")
                report.append(f"- **Location:** `{vuln.get('file')}` inside `{vuln.get('function')}` (Lines {vuln.get('lines')})")
                report.append(f"- **Confidence:** `{vuln.get('confidence'):.2%}`")
                report.append(f"- **Advisory Detail:** {vuln.get('reason')}")
                report.append(f"- **Remediation Action:** {vuln.get('recommendation')}")
        else:
            report.append("✅ No vulnerabilities identified in this scan execution.")
            
        # Remediation Roadmap
        report.append("\n## 4. Strategic Remediation Roadmap")
        if total_vulns > 0:
            report.append("Based on the security findings, the following actions are recommended:")
            if metrics.get('critical_issues', 0) > 0 or metrics.get('high_issues', 0) > 0:
                report.append("1. **Critical/High Mitigation (Next 7 days):** Apply parameter binding filters, parameterized statements, and patch credential/deserialization issues immediately.")
            if metrics.get('medium_issues', 0) > 0:
                report.append("2. **Medium Mitigation (Next 30 days):** Sanitize input schemas, refactor path resolutions, and isolate file permissions.")
            report.append("3. **Continuous Monitoring:** Integrate RepoShield scan checkpoints into pre-commit hooks or CI pipeline stages.")
        else:
            report.append("Maintain system updates, continue periodic repository checks, and keep dependencies patched.")
            
        report_str = "\n".join(report)
        
        # Write to file if path requested
        if output_path:
            try:
                p = Path(output_path)
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(report_str, encoding="utf-8")
                logger.info(f"Executive security report successfully compiled and written to: {p.resolve()}")
            except Exception as e:
                logger.error(f"Failed to write executive security report to {output_path}: {e}")
                
        return report_str
