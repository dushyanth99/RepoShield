import pytest
from fastapi.testclient import TestClient
from unittest.mock import MagicMock

# Import new production modules
from services.embeddings import EmbeddingService
from services.knowledge_graph import SecurityKnowledgeGraph
from services.patch_generator import AIPatchGenerator
from services.simulation import AttackSimulator
from utils.monitoring import SystemMonitor
from tests.benchmark_suite import BenchmarkSuite
from app import app

client = TestClient(app)

# =====================================================================
# 1. UNIT TESTS
# =====================================================================

def test_embedding_service_cosine_similarity():
    """Unit test: EmbeddingService calculates cosine similarity between list vectors correctly."""
    v1 = [1.0, 0.0, 0.0]
    v2 = [1.0, 0.0, 0.0]
    assert EmbeddingService.cosine_similarity(v1, v2) == pytest.approx(1.0)
    
    # Orthogonal vectors
    v3 = [0.0, 1.0, 0.0]
    assert EmbeddingService.cosine_similarity(v1, v3) == pytest.approx(0.0)

    # Empty/zero vectors
    assert EmbeddingService.cosine_similarity([0.0], [1.0]) == pytest.approx(0.0)


def test_knowledge_graph_mappings():
    """Unit test: SecurityKnowledgeGraph models node relationships and mitigations."""
    graph = SecurityKnowledgeGraph()
    
    # Check violations
    violations = graph.find_all_violations("CWE-89")
    assert len(violations) > 0
    assert any("Req 6.2.4" in v for v in violations)

    # Check mitigations
    mitigations = graph.get_related_entities("CWE-89", "mitigated_by")
    assert len(mitigations) > 0
    assert mitigations[0]["id"] == "M-PARAM"


def test_patch_generator_unified_diff():
    """Unit test: AIPatchGenerator computes git-compatible unified diff files."""
    code = "def query(inp):\n    db.execute('select * from users where id = ' + inp)\n"
    res = AIPatchGenerator.generate_patch(code, "CWE-89", "python")
    
    assert res["original_code"] == code
    assert "patched_code" in res
    assert "diff" in res
    assert "SELECT" in res["patched_code"] or "parameterized" in res["diff"].lower() or "secure" in res["diff"].lower()


def test_attack_simulator_rules():
    """Unit test: AttackSimulator verifies bypass/sanitization controls against inputs."""
    # Test SQL Injection simulation
    vulnerable_code = "db.execute('SELECT * FROM users WHERE name = ' + name)"
    res = AttackSimulator.simulate_attack(vulnerable_code, "CWE-89")
    assert res["status"] == "exploitable"
    assert len(res["tested_payloads"]) > 0

    # Test mitigated SQL Injection
    mitigated_code = "db.execute('SELECT * FROM users WHERE name = %s', (name,))"
    res_mit = AttackSimulator.simulate_attack(mitigated_code, "CWE-89")
    assert res_mit["status"] == "mitigated"


def test_system_monitor_metrics():
    """Unit test: SystemMonitor records requests and formats resource utilization dictionaries."""
    SystemMonitor.record_request(0.125)
    metrics = SystemMonitor.get_metrics()
    
    assert "cpu_usage_percent" in metrics["system_resources"]
    assert "ram_usage_mb" in metrics["system_resources"]
    assert metrics["uptime_stats"]["total_requests"] >= 1
    assert metrics["uptime_stats"]["average_latency_sec"] > 0.0


def test_benchmark_suite_stress():
    """Unit test: BenchmarkSuite executes model predictions and returns throughput parameters."""
    


# =====================================================================
# 2. API ENDPOINTS TESTS
# =====================================================================

def test_api_embeddings():
    """API test: POST /embeddings returns high-dimensional semantic lists."""
    response = client.post(
        "/embeddings",
        json={"code": "def process(): pass"}
    )
    assert response.status_code == 200
    data = response.json()
    assert "embedding" in data
    assert "dimensions" in data
    assert data["dimensions"] == 768


def test_api_similarity():
    """API test: POST /similarity returns semantic similarity scores."""
    response = client.post(
        "/similarity",
        json={
            "code_1": "def query(): select()",
            "code_2": "def execute(): query()"
        }
    )
    assert response.status_code == 200
    data = response.json()
    assert "cosine_similarity" in data
    assert 0.0 <= data["cosine_similarity"] <= 1.0


def test_api_graph_query():
    """API test: POST /graph-query returns compliance links and mitigations."""
    response = client.post(
        "/graph-query",
        json={
            "entity_id": "CWE-89",
            "relation_type": "violates"
        }
    )
    assert response.status_code == 200
    data = response.json()
    assert data["entity_id"] == "CWE-89"
    assert "related_entities" in data
    assert len(data["related_entities"]) > 0


def test_api_attack_simulation():
    """API test: POST /attack-simulation returns bypass details and exploitable status."""
    response = client.post(
        "/attack-simulation",
        json={
            "code": "os.system(cmd)",
            "cwe_id": "CWE-78"
        }
    )
    assert response.status_code == 200
    data = response.json()
    assert "status" in data
    assert "tested_payloads" in data
    assert "bypass_details" in data


def test_api_generate_patch():
    """API test: POST /generate-patch returns git patch files."""
    response = client.post(
        "/generate-patch",
        json={
            "code": "db.execute('select * from users where id = ' + u)",
            "cwe_id": "CWE-89",
            "language": "python"
        }
    )
    assert response.status_code == 200
    data = response.json()
    assert "patched_code" in data
    assert "diff" in data


def test_api_benchmark():
    """API test: POST /benchmark triggers execution runs and returns stats."""
    response = client.post("/benchmark")
    assert response.status_code == 200
    data = response.json()
    assert "throughput_req_per_sec" in data
    assert "average_latency_sec" in data
