from typing import List, Dict

class RepositoryRiskScorer:
    """Calculates security metrics, grades, and risk ratings based on scanner findings."""
    
    @staticmethod
    def calculate_scores(findings: List[Dict], total_files: int, total_functions: int) -> Dict:
        """Computes comprehensive repository risk scores, counts, and security grades.
        
        Args:
            findings: List of vulnerability details found in the codebase.
            total_files: Total number of files scanned.
            total_functions: Total number of functions parsed.
            
        Returns:
            Dict containing security metrics and grades.
        """
        counts = {
            "Critical": 0,
            "High": 0,
            "Medium": 0,
            "Low": 0
        }
        
        # Count findings by severity
        confidences = []
        for finding in findings:
            severity = finding.get("severity", "Medium")
            if severity in counts:
                counts[severity] += 1
            confidences.append(finding.get("risk_score", 1.0)) # risk_score represents prediction confidence
            
        total_vulns = len(findings)
        
        # 1. Risk Score calculation (Scale: 0 to 100)
        # Weighted severity sums: Critical=40, High=25, Medium=10, Low=3
        weighted_sum = (
            (counts["Critical"] * 40) +
            (counts["High"] * 25) +
            (counts["Medium"] * 10) +
            (counts["Low"] * 3)
        )
        
        # Normalize risk score against the size of the codebase to prevent large repos from always being scored F
        if total_functions > 0:
            # Code density factor: ratio of vulnerable functions to total functions
            vuln_ratio = total_vulns / total_functions
            # Combined score: combination of base count severity weight and vulnerability density
            raw_risk = (weighted_sum * 0.7) + (vuln_ratio * 100 * 0.3)
        else:
            raw_risk = weighted_sum
            
        risk_score = min(round(raw_risk, 1), 100.0)
        
        # 2. Map Risk Score to Security Grade
        # A: 0 - 5 (Excellent)
        # B: 5.1 - 15 (Good)
        # C: 15.1 - 30 (Warning)
        # D: 30.1 - 50 (Danger)
        # F: 50.1+ (Critical Security Failure)
        if risk_score <= 5.0:
            security_grade = "A"
        elif risk_score <= 15.0:
            security_grade = "B"
        elif risk_score <= 30.0:
            security_grade = "C"
        elif risk_score <= 50.0:
            security_grade = "D"
        else:
            security_grade = "F"
            
        # 3. Business Impact Score (Scale: 0.0 to 1.0)
        # Reflects the potential operational impact of the found vulnerabilities
        if total_vulns == 0:
            business_impact_score = 0.0
            business_impact = "Low"
        else:
            max_weight = 1 # Low
            if counts["Critical"] > 0:
                max_weight = 4
            elif counts["High"] > 0:
                max_weight = 3
            elif counts["Medium"] > 0:
                max_weight = 2
                
            severity_ratio = max_weight / 4.0
            vuln_density_ratio = min(total_vulns / 10.0, 1.0) # caps at 10 vulnerabilities
            
            raw_impact = (0.6 * severity_ratio) + (0.4 * vuln_density_ratio)
            business_impact_score = min(round(raw_impact, 2), 1.0)
            
            if business_impact_score >= 0.8:
                business_impact = "Critical"
            elif business_impact_score >= 0.6:
                business_impact = "High"
            elif business_impact_score >= 0.3:
                business_impact = "Medium"
            else:
                business_impact = "Low"
                
        # 4. Aggregated confidence score
        avg_confidence = round(sum(confidences) / total_vulns, 4) if total_vulns > 0 else 1.0
        
        return {
            "repository_score": int(100 - risk_score), # Security Score (higher is better)
            "risk_score": risk_score,                   # Risk rating (lower is better)
            "security_grade": security_grade,
            "business_impact": business_impact,
            "business_impact_score": business_impact_score,
            "confidence": avg_confidence,
            "critical_issues": counts["Critical"],
            "high_issues": counts["High"],
            "medium_issues": counts["Medium"],
            "low_issues": counts["Low"]
        }
