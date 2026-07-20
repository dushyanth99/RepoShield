from fastapi.testclient import TestClient
from utils.db import parse_sql_values
from preprocessing.data_loader import clean_code, advanced_clean_code
from services.scanner import extract_brace_functions, extract_python_functions
from services.explainer import VulnerabilityExplainer
from services.risk_scorer import RepositoryRiskScorer
from services.hybrid_detector import HybridDetector
from services.recommender import SecurityRecommender
from services.agent_orchestrator import AgentOrchestrator, ComplianceAgent
from services.reporter import ExecutiveReporter
from predict import VulnerabilityPredictor
from app import app

client = TestClient(app)

def test_parse_sql_values():
    """Verifies that SQL dump parser handles lists and escaped quotes correctly."""
    test_str = "123, 'test_hash', 'filename.py', 'code with ''escaped'' quotes', NULL"
    parsed = parse_sql_values(test_str)
    assert len(parsed) == 5
    assert parsed[0] == "123"
    assert parsed[1] == "test_hash"
    assert parsed[2] == "filename.py"
    assert parsed[3] == "code with 'escaped' quotes"
    assert parsed[4] == "NULL"

def test_clean_code():
    """Verifies whitespace cleaning helper."""
    raw = "   \n def test():\n    pass   \n"
    assert clean_code(raw) == "def test():\n    pass"

def test_advanced_clean_code():
    """Verifies comment/docstring stripping and formatting pipeline."""
    # Test Python comments and docstrings
    py_code = """
    # This is a comment
    def test():
        \"\"\"This is a docstring\"\"\"
        pass # end comment
    """
    cleaned_py = advanced_clean_code(py_code, "Python")
    assert "comment" not in cleaned_py
    assert "docstring" not in cleaned_py
    assert "def test():" in cleaned_py
    
    # Test C style comments
    c_code = """
    /* Block comment */
    void func() {
        // Line comment
        int x = 0;
    }
    """
    cleaned_c = advanced_clean_code(c_code, "C")
    assert "Block comment" not in cleaned_c
    assert "Line comment" not in cleaned_c
    assert "void func()" in cleaned_c

def test_extract_brace_functions():
    """Verifies bracket-matching function parser on C++/Java style syntax."""
    c_code = """
    #include <stdio.h>
    void calculate_sum(int a, int b) {
        int sum = a + b;
        printf("Sum is %d\\n", sum);
    }
    int main() {
        calculate_sum(5, 10);
        return 0;
    }
    """
    funcs = extract_brace_functions(c_code)
    assert len(funcs) == 2
    assert funcs[0][0] == "calculate_sum"
    assert "int sum = a + b;" in funcs[0][1]
    assert funcs[1][0] == "main"

def test_extract_python_functions():
    """Verifies Python AST function extraction."""
    py_code = """
def authenticate_user(username, password):
    if username == "admin":
        return True
    return False
    """
    funcs = extract_python_functions(py_code)
    assert len(funcs) == 1
    assert funcs[0][0] == "authenticate_user"
    assert "authenticate_user" in funcs[0][1]

def test_heuristic_cwe_match():
    """Verifies rule-based backup CWE matcher."""
    predictor = VulnerabilityPredictor()
    
    sql_snippet = "query = 'SELECT * FROM users WHERE id = ' + input_val\ndb.execute(query)"
    assert predictor._heuristic_cwe_match(sql_snippet) == "CWE-89"
    
    xss_snippet = "element.innerHTML = '<div>' + user_input + '</div>'"
    assert predictor._heuristic_cwe_match(xss_snippet) == "CWE-79"

def test_recommender():
    """Verifies secure recommendation mapping and example templates."""
    rec = SecurityRecommender.generate("CWE-89", "query = sql + input", "Critical", "python")
    assert "parameterized" in rec["secure_coding_recommendation"].lower()
    assert "P0" in rec["priority_level"]
    assert "%s" in rec["example_secure_implementation"]

def test_risk_scorer():
    """Verifies security grades, risk rating calculations, and business impact ratios."""
    findings = [
        {"severity": "Critical", "risk_score": 0.95},
        {"severity": "High", "risk_score": 0.85}
    ]
    scores = RepositoryRiskScorer.calculate_scores(findings, total_files=10, total_functions=50)
    assert scores["security_grade"] in ("A", "B", "C", "D", "F")
    assert scores["critical_issues"] == 1
    assert scores["high_issues"] == 1
    assert scores["confidence"] == 0.90
    assert 0.0 <= scores["business_impact_score"] <= 1.0

def test_hybrid_detector():
    """Verifies static pattern combinations and test-context overrides."""
    detector = HybridDetector()
    ml_res = {"vulnerable": False, "confidence": 0.30, "predicted_cwe": None}
    
    # Static detection override
    code = "import pickle\npickle.loads(user_input)"
    ans = detector.analyze(code, ml_res)
    assert ans["vulnerable"] is True
    assert ans["predicted_cwe"] == "CWE-502"
    
    # Test file de-escalation
    ml_vuln = {"vulnerable": True, "confidence": 0.70, "predicted_cwe": "CWE-89"}
    ans_test = detector.analyze("sql = 'select * from ' + inp", ml_vuln, file_path="test_db.py")
    assert ans_test["confidence"] < 0.70

def test_explainer():
    """Verifies token highlights and attention lines mapping."""
    explainer = VulnerabilityExplainer()
    code = "def check(x):\n    print(x)\n    return x"
    res = explainer.explain(code, 0.80, file_path="test_file.py", function_name="check", cwe_id="CWE-89")
    
    # Assert requested explainability keys are present
    assert "confidence" in res
    assert res["affected_file"] == "test_file.py"
    assert res["affected_function"] == "check"
    assert "affected_lines" in res
    assert "reason_for_prediction" in res
    assert "important_tokens" in res
    assert "attention_visualization_hooks" in res
    assert "human_readable_explanation" in res
    assert "probability_distribution" in res

def test_explainability_submodules():
    """Directly tests LineMapper, ReasonGenerator, ConfidenceExplainer, and AttentionVisualizer."""
    from explainability.line_mapper import LineMapper
    from explainability.reason_generator import ReasonGenerator
    from explainability.confidence_explainer import ConfidenceExplainer
    from explainability.attention_visualizer import AttentionVisualizer

    # Test LineMapper
    code = "line1\nline2\nline3"
    offsets = LineMapper.compute_line_offsets(code)
    assert len(offsets) == 3
    # "line1" starts at offset 0
    assert LineMapper.map_offset_to_line(2, offsets) == 1
    # "line2" starts at offset 6
    assert LineMapper.map_offset_to_line(8, offsets) == 2

    # Test ReasonGenerator
    reason = ReasonGenerator.generate_reason([2], "line1\nos.system('ping ' + cmd)\n", "CWE-78")
    assert "shell commands" in reason or "variable parameters" in reason
    
    human = ReasonGenerator.generate_human_explanation("CWE-78", "Command Injection", "Critical", reason)
    assert "Vulnerability Alert" in human
    assert "Command Injection" in human

    # Test ConfidenceExplainer
    dist = ConfidenceExplainer.get_probability_distribution(0.85)
    assert dist["vulnerable"] == 0.85
    assert dist["safe"] == 0.15
    explanation = ConfidenceExplainer.explain_confidence(0.85, True)
    assert "Confident" in explanation

    # Test AttentionVisualizer
    heatmap = AttentionVisualizer.generate_heatmap_data(["print", "x"], [0.1, 0.9], [(0, 5), (6, 7)])
    assert len(heatmap) == 2
    assert heatmap[0]["token"] == "x"
    assert heatmap[0]["importance"] == 1.0 # normalized max


def test_compliance_agent():
    """Verifies that ComplianceAgent accurately checks regulatory policies based on CWEs."""
    agent = ComplianceAgent()
    pci_issues = agent.assess("CWE-89")
    assert len(pci_issues) > 0
    assert any("PCI-DSS" in issue for issue in pci_issues)

def test_agent_orchestrator():
    """Verifies multi-agent consensus coordination and final agreement scores."""
    orchestrator = AgentOrchestrator()
    code = "def query(inp):\n    db.execute('select * from users where val = ' + inp)"
    assessment = orchestrator.analyze_snippet(code)
    assert assessment.vulnerable is True
    assert assessment.final_cwe == "CWE-89"
    assert len(assessment.compliance_issues) > 0

def test_executive_reporter():
    """Verifies markdown compiling and structural formatting for executive reporting."""
    mock_scan_data = {
        "repository_score": 90,
        "security_grade": "A",
        "business_impact": "Low",
        "vulnerabilities": [
            {
                "type": "SQL Injection",
                "severity": "Critical",
                "confidence": 0.95,
                "predicted_cwe": "CWE-89",
                "owasp": "A03:2021-Injection",
                "file": "db.py",
                "function": "query()",
                "lines": "12-15",
                "reason": "Attention high on concatenation",
                "recommendation": "Use parameterized queries"
            }
        ],
        "metrics": {
            "files_scanned": 5,
            "functions_scanned": 12,
            "total_vulnerabilities": 1,
            "critical_issues": 1,
            "high_issues": 0,
            "medium_issues": 0,
            "low_issues": 0
        }
    }
    report_md = ExecutiveReporter.generate_report(mock_scan_data)
    assert "# RepoShield Executive Security Report" in report_md
    assert "Compliance Posture" in report_md
    assert "CWE-89" in report_md

def test_api_health():
    """Tests /health check endpoint."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "model_loaded" in data
    assert "training_job" in data
    assert "memory_usage_mb" in data

def test_api_predict_safe():
    """Tests /predict endpoint on mock input."""
    response = client.post(
        "/predict",
        json={"code": "def process():\n    return 42"}
    )
    assert response.status_code == 200
    data = response.json()
    assert "vulnerable" in data
    assert "confidence" in data
    assert "predicted_cwe" in data
    assert "recommendations" in data

def test_api_agent_analyze():
    """Tests /agent-analyze endpoint on mock injection snippet."""
    response = client.post(
        "/agent-analyze",
        json={"code": "def raw_exec(cmd):\n    import os\n    os.system('ping ' + cmd)\n"}
    )
    assert response.status_code == 200
    data = response.json()
    assert "vulnerable" in data
    assert "consensus_score" in data
    assert "agent_opinions" in data
    assert "compliance_issues" in data

def test_api_scan_file(tmp_path):
    """Tests /scan-file endpoint on temporary python script file."""
    temp_file = tmp_path / "unsafe.py"
    temp_file.write_text("def raw_exec(cmd):\n    import os\n    os.system('ping ' + cmd)\n")
    
    response = client.post(
        "/scan-file",
        json={"path": str(temp_file)}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "completed"
    assert "vulnerabilities" in data
    assert len(data["vulnerabilities"]) > 0

def test_api_scan_report(tmp_path):
    """Tests /scan-report endpoint which compiles and returns markdown report."""
    temp_dir = tmp_path / "repo"
    temp_dir.mkdir()
    (temp_dir / "unsafe.py").write_text("def raw_exec(cmd):\n    import os\n    os.system('ping ' + cmd)\n")
    
    response = client.post(
        "/scan-report",
        json={"path": str(temp_dir)}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert "report_path" in data
    assert "report_preview" in data

def test_api_repository_risk(tmp_path):
    """Tests /repository-risk endpoint on temporary folder scan."""
    temp_dir = tmp_path / "repo"
    temp_dir.mkdir()
    (temp_dir / "safe.py").write_text("def do_nothing():\n    pass\n")
    
    response = client.post(
        "/repository-risk",
        json={"path": str(temp_dir)}
    )
    assert response.status_code == 200
    data = response.json()
    assert "repository_score" in data
    assert "security_grade" in data
    assert "critical_issues" in data
