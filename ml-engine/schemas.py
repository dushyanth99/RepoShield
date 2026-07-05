from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any


class CodeSnippetRequest(BaseModel):
    code: str = Field(
        ...,
        description="The source code snippet or function to evaluate.",
        examples=[
            "def login(u, p):\n    db.execute('SELECT * FROM users WHERE u = ' + u)"
        ]
    )


class ScanRepositoryRequest(BaseModel):
    path: str = Field(
        ...,
        description="The absolute local path to the repository directory.",
        examples=[
            "C:/Users/thanm/Downloads/wow/RepoShield"
        ]
    )


class ScanFileRequest(BaseModel):
    path: str = Field(
        ...,
        description="The absolute local path to a single code file to evaluate.",
        examples=[
            "C:/Users/thanm/Downloads/wow/RepoShield/app.py"
        ]
    )


class ExplanationSchema(BaseModel):
    vulnerable_lines: List[int] = Field(
        ...,
        description="Vulnerable line numbers identified in the snippet."
    )
    reason: str = Field(
        ...,
        description="Explanation of why this is considered vulnerable."
    )
    highlighted_tokens: List[Dict[str, Any]] = Field(
        ...,
        description="High-risk token lists with their attention weights."
    )


class RemediationSchema(BaseModel):
    root_cause: str = Field(
        ...,
        description="Underlying architectural root cause of the vulnerability."
    )
    why_dangerous: str = Field(
        ...,
        description="Description of the risk/damage potential of this vulnerability."
    )
    secure_coding_recommendation: str = Field(
        ...,
        description="Secure programming pattern guideline."
    )
    example_secure_implementation: str = Field(
        ...,
        description="Concrete code example showing how to secure it."
    )
    priority_level: str = Field(
        ...,
        description="Fix priority rating (P0 to P3)."
    )


class VulnerabilitySchema(BaseModel):
    type: str = Field(
        ...,
        description="The type of vulnerability (e.g. SQL Injection)."
    )
    severity: str = Field(
        ...,
        description="Severity level: Critical, High, Medium, Low, None."
    )
    confidence: float = Field(
        ...,
        description="Confidence score from model prediction."
    )
    predicted_cwe: str = Field(
        ...,
        description="Predicted CWE identifier (e.g. CWE-89)."
    )
    owasp: str = Field(
        ...,
        description="Associated OWASP category."
    )
    file: str = Field(
        ...,
        description="File name containing the vulnerability."
    )
    function: str = Field(
        ...,
        description="Function name context."
    )
    lines: str = Field(
        ...,
        description="Vulnerable line numbers context, e.g. 42-51."
    )
    reason: str = Field(
        ...,
        description="Attention-based explanation reason."
    )
    recommendation: str = Field(
        ...,
        description="Direct remediation advisory summary."
    )
    remediation: Optional["RemediationSchema"] = Field(
        None,
        description="Detailed remediation instructions and code sample templates."
    )


class RepositoryScanResponse(BaseModel):
    status: str = Field(
        "completed",
        description="Overall scan execution status."
    )
    repository_score: int = Field(
        ...,
        description="Security health rating (0-100, higher is better)."
    )
    security_grade: str = Field(
        ...,
        description="Letter security grade (A, B, C, D, F)."
    )
    business_impact: str = Field(
        ...,
        description="Aggregated business impact rating: Critical, High, Medium, Low."
    )
    business_impact_score: float = Field(
        ...,
        description="Aggregated business impact score (0.0 to 1.0)."
    )
    confidence: float = Field(
        ...,
        description="Weighted average prediction confidence."
    )
    vulnerabilities: List[VulnerabilitySchema] = Field(
        ...,
        description="List of vulnerability findings."
    )
    metrics: Dict[str, Any] = Field(
        ...,
        description="Summary scan execution metrics."
    )


class RiskSummaryResponse(BaseModel):
    repository_score: int = Field(
        ...,
        description="Security health score (0-100, higher is better)."
    )
    security_grade: str = Field(
        ...,
        description="Letter security grade (A, B, C, D, F)."
    )
    business_impact: str = Field(
        ...,
        description="Aggregated business impact rating."
    )
    business_impact_score: float = Field(
        ...,
        description="Aggregated business impact score."
    )
    confidence: float = Field(
        ...,
        description="Average finding prediction confidence."
    )
    critical_issues: int = Field(
        ...,
        description="Number of critical issues detected."
    )
    high_issues: int = Field(
        ...,
        description="Number of high issues detected."
    )
    medium_issues: int = Field(
        ...,
        description="Number of medium issues detected."
    )
    low_issues: int = Field(
        ...,
        description="Number of low issues detected."
    )


class AgentOpinionSchema(BaseModel):
    agent_name: str = Field(
        ...,
        description="Agent name."
    )
    vulnerable: bool = Field(
        ...,
        description="Vulnerability vote."
    )
    confidence: float = Field(
        ...,
        description="Confidence rating."
    )
    cwe_id: Optional[str] = Field(
        None,
        description="Inferred CWE."
    )
    rationale: str = Field(
        ...,
        description="Detailed explanation text."
    )


class MultiAgentAssessmentResponse(BaseModel):
    vulnerable: bool = Field(
        ...,
        description="Consensus determination."
    )
    consensus_score: float = Field(
        ...,
        description="Aggregated consensus rating."
    )
    final_cwe: Optional[str] = Field(
        None,
        description="Consensus CWE target."
    )
    agent_opinions: List[AgentOpinionSchema] = Field(
        ...,
        description="Individual specialized agent opinions."
    )
    compliance_issues: List[str] = Field(
        ...,
        description="Triggered regulatory compliance violations."
    )


class EmbeddingRequest(BaseModel):
    code: str = Field(
        ...,
        description="Source code snippet to embed."
    )


class SimilarityRequest(BaseModel):
    code_1: str = Field(
        ...,
        description="First code snippet."
    )
    code_2: str = Field(
        ...,
        description="Second code snippet."
    )


class GraphQueryRequest(BaseModel):
    entity_id: str = Field(
        ...,
        description="Entity to query relationships for (e.g. CWE-89)."
    )
    relation_type: Optional[str] = Field(
        None,
        description="Relation type (e.g. violates, mitigated_by)."
    )


class AttackSimulationRequest(BaseModel):
    code: str = Field(
        ...,
        description="Code block to test."
    )
    cwe_id: str = Field(
        ...,
        description="CWE category to simulate attacks for."
    )


class PatchGenerationRequest(BaseModel):
    code: str = Field(
        ...,
        description="Vulnerable source code string."
    )
    cwe_id: str = Field(
        ...,
        description="Predicted CWE ID."
    )
    language: Optional[str] = Field(
        "python",
        description="Target programming language."
    )