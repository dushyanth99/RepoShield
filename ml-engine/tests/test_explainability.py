import pytest
from unittest.mock import MagicMock

from explainability.line_mapper import LineMapper
from explainability.reason_generator import ReasonGenerator
from explainability.confidence_explainer import ConfidenceExplainer
from explainability.attention_visualizer import AttentionVisualizer
from services.explainer import VulnerabilityExplainer


# =====================================================================
# 1. UNIT TESTS
# =====================================================================

def test_line_mapper_map_attention_to_lines():
    """Unit test: map_attention_to_lines maps tokens to line numbers."""
    code = "line1\nline2\nline3"
    # Mapping for 3 tokens, pointing to char indexes corresponding to line 1, 2, and 3
    offset_mapping = [(0, 5), (6, 11), (12, 17)]
    token_attentions = [0.1, 0.6, 0.3]
    
    line_scores = LineMapper.map_attention_to_lines(code, offset_mapping, token_attentions)
    assert line_scores[1] == pytest.approx(0.1)
    assert line_scores[2] == pytest.approx(0.6)
    assert line_scores[3] == pytest.approx(0.3)


def test_line_mapper_empty_whitespace_none():
    """Unit test: LineMapper handles empty, whitespace-only, and None code inputs gracefully."""
    # None inputs
    assert LineMapper.compute_line_offsets(None) == []
    assert LineMapper.map_attention_to_lines(None, [(0, 1)], [0.5]) == {}

    # Empty inputs
    assert LineMapper.compute_line_offsets("") == []
    assert LineMapper.map_attention_to_lines("", [], []) == {}

    # Whitespace-only
    offsets = LineMapper.compute_line_offsets("   \n   ")
    assert len(offsets) == 2
    assert LineMapper.map_offset_to_line(1, offsets) == 1
    assert LineMapper.map_offset_to_line(5, offsets) == 2


def test_line_mapper_invalid_code_input_types():
    """Unit test: LineMapper handles invalid input types (e.g. dict, int) without raising exception."""
    # Invalid code types
    assert LineMapper.compute_line_offsets(12345) == []
    assert LineMapper.map_attention_to_lines({"code": "print()"}, [(0, 1)], [0.5]) == {}
    
    # Invalid offset mapping types
    assert LineMapper.map_offset_to_line("invalid", [(0, 5)]) == 1


def test_confidence_explainer_out_of_range():
    """Unit test: ConfidenceExplainer clamps probability inputs outside [0, 1]."""
    # Negative probability
    dist_neg = ConfidenceExplainer.get_probability_distribution(-0.5)
    assert dist_neg["vulnerable"] == 0.0
    assert dist_neg["safe"] == 1.0

    # Over 1.0 probability
    dist_over = ConfidenceExplainer.get_probability_distribution(1.2)
    assert dist_over["vulnerable"] == 1.0
    assert dist_over["safe"] == 0.0


def test_confidence_explainer_nan_probability():
    """Unit test: ConfidenceExplainer handles NaN probability input by falling back to 0.5."""
    dist_nan = ConfidenceExplainer.get_probability_distribution(float('nan'))
    assert dist_nan["vulnerable"] == 0.5
    assert dist_nan["safe"] == 0.5


def test_confidence_explainer_infinite_probability():
    """Unit test: ConfidenceExplainer handles infinite probability input by falling back to 0.5."""
    dist_inf = ConfidenceExplainer.get_probability_distribution(float('inf'))
    assert dist_inf["vulnerable"] == 0.5
    assert dist_inf["safe"] == 0.5

    dist_neginf = ConfidenceExplainer.get_probability_distribution(float('-inf'))
    assert dist_neginf["vulnerable"] == 0.5
    assert dist_neginf["safe"] == 0.5


def test_attention_visualizer_get_attention_matrix_hook():
    """Unit test: get_attention_matrix_hook parses valid attention tensors."""
    class MockTensor:
        def __init__(self, shape):
            self.shape = shape
            
    # Mock attentions tuple for 6 layers, 12 heads, seq len 128
    mock_matrix = (
        MockTensor((1, 12, 128, 128)),
        MockTensor((1, 12, 128, 128))
    )
    hook = AttentionVisualizer.get_attention_matrix_hook(mock_matrix)
    assert hook["num_layers"] == 2
    assert hook["num_heads"] == 12
    assert hook["sequence_length"] == 128
    assert hook["explainability_dimension"] == "2x12x128x128"


def test_attention_visualizer_malformed_attention_matrices():
    """Unit test: get_attention_matrix_hook handles None, empty, or wrong shape matrices gracefully."""
    # None
    hook_none = AttentionVisualizer.get_attention_matrix_hook(None)
    assert hook_none["num_layers"] == 0
    assert hook_none["explainability_dimension"] == "0x0x0x0"

    # Empty tuple
    hook_empty = AttentionVisualizer.get_attention_matrix_hook(())
    assert hook_empty["num_layers"] == 0

    # Malformed shape
    class MalformedTensor:
        shape = (1,)  # too small
    hook_malformed = AttentionVisualizer.get_attention_matrix_hook((MalformedTensor(),))
    assert hook_malformed["num_layers"] == 0


def test_attention_visualizer_normalization():
    """Unit test: generate_heatmap_data normalizes attentions relative to maximum value."""
    tokens = ["a", "b", "c"]
    attentions = [1.0, 5.0, 0.0]
    offsets = [(0, 1), (2, 3), (4, 5)]
    
    heatmap = AttentionVisualizer.generate_heatmap_data(tokens, attentions, offsets)
    # Sorted descending by weight, so 'b' is first
    assert heatmap[0]["token"] == "b"
    assert heatmap[0]["weight"] == 5.0
    assert heatmap[0]["importance"] == 1.0 # max normalized

    assert heatmap[1]["token"] == "a"
    assert heatmap[1]["weight"] == 1.0
    assert heatmap[1]["importance"] == 0.2 # 1.0 / 5.0


def test_attention_visualizer_empty_and_mismatched():
    """Unit test: generate_heatmap_data handles empty tokens and length mismatches."""
    # Empty
    assert AttentionVisualizer.generate_heatmap_data([], [], []) == []

    # Mismatched lengths
    with pytest.raises(ValueError):
        AttentionVisualizer.generate_heatmap_data(["a"], [0.5, 0.6], [(0, 1)])


def test_confidence_explainer_certainty_labels():
    """Unit test: explain_confidence returns descriptive text depending on decision thresholds."""
    exp1 = ConfidenceExplainer.explain_confidence(0.95, True)
    assert "Extremely Confident" in exp1
    assert "vulnerable risk signatures" in exp1

    exp2 = ConfidenceExplainer.explain_confidence(0.10, False)
    assert "Extremely Confident" in exp2 # safe prob is 0.90
    assert "safe logic structures" in exp2


def test_reason_generator_cwe_mapping():
    """Unit test: ReasonGenerator generates CWE-specific messages and triggers fallback generic text."""
    # SQLi CWE-89
    reason_sqli = ReasonGenerator.generate_reason([1], "query = 'SELECT * FROM users WHERE name = ' + username", "CWE-89")
    assert "SQL" in reason_sqli
    
    # OS Command CWE-78
    reason_cmd = ReasonGenerator.generate_reason([1], "subprocess.run('ping ' + host)", "CWE-78")
    assert "shell" in reason_cmd

    # Deserialization CWE-502
    reason_des = ReasonGenerator.generate_reason([1], "pickle.loads(payload)", "CWE-502")
    assert "deserializes" in reason_des

    # Path Traversal CWE-22
    reason_path = ReasonGenerator.generate_reason([1], "open(filename)", "CWE-22")
    assert "traversal" in reason_path

    # XSS CWE-79
    reason_xss = ReasonGenerator.generate_reason([1], "elem.innerHTML = content", "CWE-79")
    assert "browser DOM" in reason_xss

    # Code Injection CWE-94
    reason_eval = ReasonGenerator.generate_reason([1], "eval(code)", "CWE-94")
    assert "dynamic code" in reason_eval

    # Cleartext secrets CWE-312
    reason_clear = ReasonGenerator.generate_reason([1], "log.info(password)", "CWE-312")
    assert "cleartext" in reason_clear

    # Fallback generic message
    reason_fallback = ReasonGenerator.generate_reason([1], "def some_func():\n    pass", "CWE-999")
    assert "signature rules" in reason_fallback


# =====================================================================
# 2. INTEGRATION TESTS
# =====================================================================

def test_explainer_integration_safe_snippet():
    """Integration test: explain() correctly identifies safe patterns and populates correct schema."""
    explainer = VulnerabilityExplainer()
    safe_code = (
        "def add(a, b):\n"
        "    return a + b\n"
    )
    res = explainer.explain(safe_code, confidence=0.02, file_path="math.py", function_name="add")
    assert res["confidence"] == 0.02
    assert res["probability_distribution"]["safe"] == 0.98
    assert res["affected_lines"] == []
    assert "safe" in res["human_readable_explanation"].lower() or "vulnerability alert" not in res["human_readable_explanation"].lower()


def test_explainer_integration_vulnerable_sqli():
    """Integration test: SQL injection snippet generates line scores and precise reason explanation."""
    explainer = VulnerabilityExplainer()
    code = (
        "def query_user(user_id):\n"
        "    sql = 'SELECT * FROM users WHERE id = ' + user_id\n"
        "    db.execute(sql)\n"
    )
    res = explainer.explain(code, confidence=0.92, file_path="db.py", function_name="query_user", cwe_id="CWE-89")
    assert res["confidence"] == 0.92
    assert len(res["affected_lines"]) > 0
    assert "SQL" in res["reason_for_prediction"]


def test_explainer_integration_vulnerable_cmd():
    """Integration test: command injection snippet generates line scores and command reason explanation."""
    explainer = VulnerabilityExplainer()
    code = (
        "def ping_host(host):\n"
        "    os.system('ping -c 1 ' + host)\n"
    )
    res = explainer.explain(code, confidence=0.95, file_path="network.py", function_name="ping_host", cwe_id="CWE-78")
    assert res["confidence"] == 0.95
    assert len(res["affected_lines"]) > 0
    assert "shell" in res["reason_for_prediction"]


def test_explainer_integration_vulnerable_secrets():
    """Integration test: hardcoded credentials snippet generates precise credentials warning."""
    explainer = VulnerabilityExplainer()
    code = (
        "def get_client():\n"
        "    api_key = 'AIzaSyA1234567890Secret'\n"
        "    return api_key\n"
    )
    res = explainer.explain(code, confidence=0.91, file_path="auth.py", function_name="get_client", cwe_id="CWE-798")
    assert "secret" in res["reason_for_prediction"].lower() or "credentials" in res["reason_for_prediction"].lower()


def test_explainer_integration_large_file_multi_function():
    """Integration test: checks execution safety and line maps on large multi-function segments."""
    explainer = VulnerabilityExplainer()
    large_code = "\n".join([f"def func_{i}():\n    return {i}" for i in range(150)])
    res = explainer.explain(large_code, confidence=0.1, file_path="large.py", function_name="func_0")
    assert res["confidence"] == 0.1
    # Should not crash on high line counts
    assert len(res["probability_distribution"]) == 2


# =====================================================================
# 3. NEGATIVE & ROBUSTNESS TESTS
# =====================================================================

def test_explainer_negative_tokenizer_fails():
    """Negative test: explain() fails gracefully when tokenizer raises an exception."""
    explainer = VulnerabilityExplainer()
    # Replace tokenizer with mock that raises Exception
    explainer.tokenizer = MagicMock()
    explainer.tokenizer.side_effect = Exception("Tokenizer crash!")

    res = explainer.explain("def test(): pass", confidence=0.88)
    assert res["confidence"] == 0.88
    assert res["affected_lines"] == []
    assert "Tokenizer crash!" in res["reason_for_prediction"]


def test_explainer_negative_model_fails():
    """Negative test: explain() fails gracefully when model forward pass raises an exception."""
    explainer = VulnerabilityExplainer()
    # Mock model that raises Exception
    explainer.model = MagicMock()
    explainer.model.side_effect = Exception("Model forward pass failure!")

    res = explainer.explain("def test(): pass", confidence=0.75)
    assert res["confidence"] == 0.75
    assert res["affected_lines"] == []
    assert "Model forward pass failure!" in res["reason_for_prediction"]


def test_explainer_negative_attention_missing():
    """Negative test: explain() handles missing attention outputs from model."""
    explainer = VulnerabilityExplainer()
    # Mock model returning empty attention tuple
    mock_model = MagicMock()
    mock_model.return_value = (None, ())
    explainer.model = mock_model

    res = explainer.explain("def test(): pass", confidence=0.60)
    assert res["confidence"] == 0.60
    assert res["affected_lines"] == []
    assert res["attention_visualization_hooks"]["num_layers"] == 0
