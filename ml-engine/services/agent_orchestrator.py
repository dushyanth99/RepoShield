from typing import List
from pydantic import BaseModel, Field
from predict import VulnerabilityPredictor
from services.hybrid_detector import HybridDetector
from utils.logging_utils import setup_logger

logger = setup_logger("agent-orchestrator")

class AgentOpinion(BaseModel):
    """Represents a specialized security agent's assessment of a code snippet."""
    agent_name: str = Field(..., description="Name of the specialized analyzer agent.")
    vulnerable: bool = Field(..., description="Whether the agent flags code as vulnerable.")
    confidence: float = Field(..., description="Confidence rating from 0.0 to 1.0.")
    cwe_id: str = Field(None, description="Identified CWE identifier if vulnerable.")
    rationale: str = Field(..., description="Reasoning statement justifying the assessment.")

class MultiAgentAssessment(BaseModel):
    """Aggregated assessment result compiled by the Agent Orchestrator."""
    vulnerable: bool = Field(..., description="Final consensus vulnerability determination.")
    consensus_score: float = Field(..., description="Merged consensus confidence rating.")
    final_cwe: str = Field(None, description="Consensus CWE mapping.")
    agent_opinions: List[AgentOpinion] = Field(..., description="Detailed individual opinions from all agents.")
    compliance_issues: List[str] = Field(..., description="List of triggered compliance violations (e.g. PCI-DSS, SOC2, HIPAA).")

class MLSecurityAgent:
    """Agent that performs semantic vulnerability analysis using the CodeBERT ML Model."""
    
    def __init__(self, predictor: VulnerabilityPredictor):
        self.predictor = predictor
        
    def assess(self, code: str) -> AgentOpinion:
        try:
            # CodeBERT raw prediction (ignoring static overrides here to capture raw ML opinion)
            inputs = self.predictor.tokenizer(
                code,
                padding="max_length",
                truncation=True,
                max_length=512,
                return_tensors="pt"
            )
            input_ids = inputs['input_ids'].to(self.predictor.device)
            attention_mask = inputs['attention_mask'].to(self.predictor.device)
            
            import torch
            with torch.no_grad():
                logits, _ = self.predictor.model(input_ids, attention_mask)
                probs = torch.softmax(logits, dim=1).cpu().numpy()[0]
                
            prob = float(probs[1])
            is_vuln = prob >= 0.5
            cwe = self.predictor._heuristic_cwe_match(code) if is_vuln else None
            
            rationale = (
                f"CodeBERT ML detected semantic vulnerability signatures (Confidence: {prob:.2%})."
                if is_vuln else f"CodeBERT ML evaluated the code logic structure as safe (Confidence: {1-prob:.2%})."
            )
            return AgentOpinion(
                agent_name="MLSecurityAgent",
                vulnerable=is_vuln,
                confidence=prob if is_vuln else 1.0 - prob,
                cwe_id=cwe,
                rationale=rationale
            )
        except Exception as e:
            logger.error(f"MLSecurityAgent assessment failed: {e}")
            return AgentOpinion(
                agent_name="MLSecurityAgent",
                vulnerable=False,
                confidence=0.0,
                rationale=f"Error during ML assessment: {e}"
            )

class StaticRuleAgent:
    """Agent that applies static pattern matching rules to look for common vulnerabilities."""
    
    def __init__(self, detector: HybridDetector):
        self.detector = detector
        
    def assess(self, code: str) -> AgentOpinion:
        try:
            ml_mock = {"vulnerable": False, "confidence": 0.0, "predicted_cwe": None}
            res = self.detector.analyze(code, ml_mock)
            
            is_vuln = len(res["static_patterns_triggered"]) > 0
            cwe = res["predicted_cwe"] if is_vuln else None
            
            if is_vuln:
                rationale = "Static rules triggered: " + "; ".join(res["static_patterns_triggered"])
            else:
                rationale = "No static vulnerability patterns triggered."
                
            return AgentOpinion(
                agent_name="StaticRuleAgent",
                vulnerable=is_vuln,
                confidence=0.90 if is_vuln else 1.0, # High static confidence on pattern hits
                cwe_id=cwe,
                rationale=rationale
            )
        except Exception as e:
            logger.error(f"StaticRuleAgent assessment failed: {e}")
            return AgentOpinion(
                agent_name="StaticRuleAgent",
                vulnerable=False,
                confidence=0.0,
                rationale=f"Error during static rule assessment: {e}"
            )

class ComplianceAgent:
    """Agent that verifies regulatory compliance parameters (OWASP, PCI-DSS, HIPAA, SOC2) based on active vulnerabilities."""
    
    def assess(self, cwe_id: str) -> List[str]:
        if not cwe_id:
            return []
            
        violations = []
        cwe_upper = cwe_id.upper()
        
        # Mapping CWEs to compliance policies
        if cwe_upper == "CWE-89": # SQLi
            violations.extend([
                "PCI-DSS v4.0 Requirement 6.2.4 (Prevention of SQL Injection)",
                "OWASP Top 10 A03:2021-Injection",
                "SOC2 CC7.1 (System Boundary Protection against Injection Attacks)"
            ])
        elif cwe_upper == "CWE-79": # XSS
            violations.extend([
                "PCI-DSS v4.0 Requirement 6.2.4 (Prevention of Cross-Site Scripting)",
                "OWASP Top 10 A03:2021-Injection"
            ])
        elif cwe_upper == "CWE-798": # Hardcoded Secrets
            violations.extend([
                "PCI-DSS v4.0 Requirement 3.2 (Protection of Cardholder Data Secrets)",
                "OWASP Top 10 A07:2021-Identification and Authentication Failures",
                "SOC2 CC6.1 (Access Control & Credential Safeguarding)"
            ])
        elif cwe_upper == "CWE-312": # Cleartext Sensitive Info
            violations.extend([
                "PCI-DSS v4.0 Requirement 3.4 (Render PAN Unreadable)",
                "HIPAA Security Rule 45 CFR 164.312(a)(2)(iv) (Encryption/Decryption of ePHI)",
                "OWASP Top 10 A02:2021-Cryptographic Failures"
            ])
        elif cwe_upper == "CWE-502": # Deserialization
            violations.extend([
                "OWASP Top 10 A08:2021-Software and Data Integrity Failures",
                "SOC2 CC7.2 (Patching & Secure Data Deserialization)"
            ])
            
        return violations

class AgentOrchestrator:
    """Orchestrates multiple specialized agents to produce a consensus security prediction."""
    
    def __init__(self, predictor: VulnerabilityPredictor = None):
        self.predictor = predictor or VulnerabilityPredictor()
        self.ml_agent = MLSecurityAgent(self.predictor)
        self.static_agent = StaticRuleAgent(self.predictor.hybrid_detector)
        self.compliance_agent = ComplianceAgent()

    def analyze_snippet(self, code: str) -> MultiAgentAssessment:
        """Runs the multi-agent analysis on a single code snippet and returns unified report.
        
        Args:
            code: Source code snippet.
            
        Returns:
            MultiAgentAssessment model containing consensus and agent-specific feedback.
        """
        # Collect agent reviews
        ml_opinion = self.ml_agent.assess(code)
        static_opinion = self.static_agent.assess(code)
        
        # Consensus negotiation logic
        opinions = [ml_opinion, static_opinion]
        
        # If any agent flags code as vulnerable, evaluate weight
        vulnerable = False
        final_cwe = None
        consensus_score = 0.0
        
        # If both agree:
        if ml_opinion.vulnerable == static_opinion.vulnerable:
            vulnerable = ml_opinion.vulnerable
            consensus_score = (ml_opinion.confidence + static_opinion.confidence) / 2
            final_cwe = ml_opinion.cwe_id or static_opinion.cwe_id
        else:
            # Discordance: Static agent overrides ML if static agent is extremely confident (e.g. pattern matched)
            if static_opinion.vulnerable and static_opinion.confidence >= 0.90:
                vulnerable = True
                consensus_score = 0.85
                final_cwe = static_opinion.cwe_id
            else:
                # Fall back to ML model opinion
                vulnerable = ml_opinion.vulnerable
                consensus_score = ml_opinion.confidence
                final_cwe = ml_opinion.cwe_id
                
        # Generate compliance audit checklist
        compliance_issues = []
        if vulnerable and final_cwe:
            compliance_issues = self.compliance_agent.assess(final_cwe)
            
        return MultiAgentAssessment(
            vulnerable=vulnerable,
            consensus_score=round(consensus_score, 4),
            final_cwe=final_cwe,
            agent_opinions=opinions,
            compliance_issues=compliance_issues
        )
