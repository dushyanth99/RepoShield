import torch
import numpy as np
from pathlib import Path
from typing import Optional
from transformers import AutoTokenizer

from models.codebert_classifier import CodeBERTClassifier
from config import MODEL_CHECKPOINT, SAVED_MODEL_DIR
from utils.logging_utils import setup_logger
from explainability.line_mapper import LineMapper
from explainability.reason_generator import ReasonGenerator
from explainability.confidence_explainer import ConfidenceExplainer
from explainability.attention_visualizer import AttentionVisualizer

logger = setup_logger("explainer-service")

# Default number of top tokens to surface in the explainability output
DEFAULT_TOP_TOKENS = 15


class VulnerabilityExplainer:
    """Provides Explainable AI (XAI) details for vulnerability predictions.

    Delegates to four specialised submodules:
    - :class:`~explainability.line_mapper.LineMapper`          — maps tokens to lines
    - :class:`~explainability.reason_generator.ReasonGenerator` — builds explanations
    - :class:`~explainability.confidence_explainer.ConfidenceExplainer` — probability dist
    - :class:`~explainability.attention_visualizer.AttentionVisualizer` — heatmap hooks
    """

    def __init__(
        self,
        model: Optional[CodeBERTClassifier] = None,
        tokenizer: Optional[AutoTokenizer] = None,
    ) -> None:
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.model = model
        self.tokenizer = tokenizer

        # Lazy-load model and tokenizer if not injected
        if self.model is None or self.tokenizer is None:
            best_model_path = Path(SAVED_MODEL_DIR) / "best_model"
            if best_model_path.exists():
                logger.info("Loading fine-tuned model for explainer from %s...", best_model_path)
                if self.tokenizer is None:
                    self.tokenizer = AutoTokenizer.from_pretrained(str(best_model_path))
                if self.model is None:
                    self.model = CodeBERTClassifier.from_pretrained(str(best_model_path))
            else:
                logger.warning(
                    "No fine-tuned model found at %s. Falling back to base checkpoint %s.",
                    best_model_path,
                    MODEL_CHECKPOINT,
                )
                if self.tokenizer is None:
                    self.tokenizer = AutoTokenizer.from_pretrained(MODEL_CHECKPOINT)
                if self.model is None:
                    self.model = CodeBERTClassifier(MODEL_CHECKPOINT)

            self.model.to(self.device)
            self.model.eval()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def explain(
        self,
        code: str,
        confidence: float,
        file_path: str = "",
        function_name: str = "",
        cwe_id: Optional[str] = None,
        cwe_name: Optional[str] = None,
        severity: str = "Medium",
        top_tokens: int = DEFAULT_TOP_TOKENS,
    ) -> dict:
        """Analyzes a code snippet and returns a full explainability report.

        Runs the code through CodeBERT to extract attention maps, then delegates
        to the four submodules to produce per-line scores, token heatmaps, a
        human-readable explanation, and a probability distribution.

        Args:
            code: Source code string to analyze.
            confidence: Model confidence score (class-1 probability, 0–1).
            file_path: Relative file path where the snippet lives (for context).
            function_name: Name of the function containing the snippet (for context).
            cwe_id: Predicted CWE identifier (e.g. ``"CWE-89"``).
            cwe_name: Full CWE name (e.g. ``"SQL Injection"``).
            severity: Severity string: ``"Critical"``, ``"High"``, ``"Medium"``, ``"Low"``.
            top_tokens: Maximum number of high-importance tokens to include.

        Returns:
            Dict with the following keys (all are always present, even on empty input):

            - ``confidence`` – float, 0–1
            - ``affected_file`` – str
            - ``affected_function`` – str
            - ``affected_lines`` – List[int], 1-indexed
            - ``reason_for_prediction`` – str
            - ``important_tokens`` – List[Dict]
            - ``attention_visualization_hooks`` – Dict with layer/head metadata
            - ``human_readable_explanation`` – str
            - ``probability_distribution`` – Dict[str, float]
            - ``vulnerable_lines`` – alias of ``affected_lines`` (backward compat)
            - ``attention_weights`` – Dict[str, float] per line (backward compat)
            - ``reason`` – alias of ``reason_for_prediction`` (backward compat)
            - ``highlighted_tokens`` – alias of ``important_tokens`` (backward compat)
        """
        # --- Empty-input fast path ---
        if not code or not code.strip():
            logger.debug("explain() called with empty code; returning stub result.")
            prob_dist = ConfidenceExplainer.get_probability_distribution(confidence)
            stub: dict = {
                "confidence": round(confidence, 4),
                "affected_file": file_path,
                "affected_function": function_name,
                "affected_lines": [],
                "reason_for_prediction": "Code snippet is empty.",
                "important_tokens": [],
                "attention_visualization_hooks": {
                    "num_layers": 0, "num_heads": 0,
                    "sequence_length": 0, "explainability_dimension": "0x0x0x0",
                },
                "human_readable_explanation": "The analyzed input is empty or invalid.",
                "probability_distribution": prob_dist,
                # backward-compat keys
                "vulnerable_lines": [],
                "attention_weights": {},
                "reason": "Code snippet is empty.",
                "highlighted_tokens": [],
            }
            return stub

        # --- Step 1: Tokenize with offset mapping ---
        try:
            inputs = self.tokenizer(
                code,
                padding=False,
                truncation=True,
                max_length=512,
                return_offsets_mapping=True,
                return_tensors="pt",
            )
        except Exception as exc:
            logger.error("Tokenization failed: %s", exc)
            return self._error_stub(confidence, file_path, function_name, str(exc))

        input_ids = inputs["input_ids"].to(self.device)
        attention_mask = inputs["attention_mask"].to(self.device)
        offset_mapping = inputs["offset_mapping"][0].numpy()  # (seq_len, 2)
        tokens = self.tokenizer.convert_ids_to_tokens(input_ids[0])

        # --- Step 2: Forward pass to extract attention weights ---
        try:
            with torch.no_grad():
                _, attentions = self.model(input_ids, attention_mask)
        except Exception as exc:
            logger.error("Model forward pass failed: %s", exc)
            return self._error_stub(confidence, file_path, function_name, str(exc))

        # Average CLS-token row across all heads in the final layer
        try:
            last_layer = attentions[-1][0].cpu().numpy()    # (heads, seq_len, seq_len)
            mean_attention = np.mean(last_layer, axis=0)    # (seq_len, seq_len)
            cls_attention = mean_attention[0]               # (seq_len,)
            att_sum = np.sum(cls_attention)
            if att_sum > 0:
                cls_attention = cls_attention / att_sum
        except Exception as exc:
            logger.error("Attention aggregation failed: %s", exc)
            cls_attention = np.zeros(len(tokens))

        # --- Step 3: Map attention to lines (LineMapper) ---
        try:
            line_attention_scores = LineMapper.map_attention_to_lines(
                code, offset_mapping, cls_attention
            )
        except Exception as exc:
            logger.error("LineMapper.map_attention_to_lines failed: %s", exc)
            line_attention_scores = {}

        # Cache splitlines result to avoid repeated calls
        code_lines = code.splitlines()
        num_lines = len(code_lines)

        sorted_lines = sorted(line_attention_scores.items(), key=lambda x: x[1], reverse=True)
        vulnerable_lines = []
        if confidence >= 0.5:
            vulnerable_lines = [
                ln for ln, score in sorted_lines
                if score > 0.15
                and 1 <= ln <= num_lines
                and len(code_lines[ln - 1].strip()) > 1
            ]
            # Fallback: surface top-2 lines if nothing crosses threshold and we have valid attention
            if not vulnerable_lines and attentions:
                for ln, _ in sorted_lines[:2]:
                    if 1 <= ln <= num_lines and len(code_lines[ln - 1].strip()) > 1:
                        vulnerable_lines.append(ln)
            vulnerable_lines = sorted(vulnerable_lines)

        # --- Step 4: Generate reasons (ReasonGenerator) ---
        try:
            reason = ReasonGenerator.generate_reason(vulnerable_lines, code, cwe_id)
            human_explanation = ReasonGenerator.generate_human_explanation(
                cwe_id, cwe_name, severity, reason
            )
        except Exception as exc:
            logger.error("ReasonGenerator failed: %s", exc)
            reason = "Reason generation encountered an error."
            human_explanation = reason

        # --- Step 5: Heatmap + matrix hooks (AttentionVisualizer) ---
        try:
            important_tokens = AttentionVisualizer.generate_heatmap_data(
                tokens, cls_attention, offset_mapping
            )
        except Exception as exc:
            logger.error("AttentionVisualizer.generate_heatmap_data failed: %s", exc)
            important_tokens = []

        try:
            attention_matrix_hooks = AttentionVisualizer.get_attention_matrix_hook(attentions)
        except Exception as exc:
            logger.error("AttentionVisualizer.get_attention_matrix_hook failed: %s", exc)
            attention_matrix_hooks = {
                "num_layers": 0, "num_heads": 0,
                "sequence_length": 0, "explainability_dimension": "0x0x0x0",
            }

        # --- Step 6: Probability distribution (ConfidenceExplainer) ---
        try:
            prob_distribution = ConfidenceExplainer.get_probability_distribution(confidence)
        except Exception as exc:
            logger.error("ConfidenceExplainer.get_probability_distribution failed: %s", exc)
            prob_distribution = {"vulnerable": round(confidence, 4), "safe": round(1.0 - confidence, 4)}

        top = important_tokens[:top_tokens]

        return {
            # Requested output schema
            "confidence": round(confidence, 4),
            "affected_file": file_path,
            "affected_function": function_name,
            "affected_lines": vulnerable_lines,
            "reason_for_prediction": reason,
            "important_tokens": top,
            "attention_visualization_hooks": attention_matrix_hooks,
            "human_readable_explanation": human_explanation,
            "probability_distribution": prob_distribution,
            # Backward-compatible keys (used by predict.py and scanner.py)
            "vulnerable_lines": vulnerable_lines,
            "attention_weights": {str(k): round(v, 4) for k, v in line_attention_scores.items()},
            "reason": reason,
            "highlighted_tokens": top,
        }

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _error_stub(
        self,
        confidence: float,
        file_path: str,
        function_name: str,
        error_msg: str,
    ) -> dict:
        """Returns a safe, fully-keyed dict when an internal error prevents normal output."""
        prob_dist = {"vulnerable": round(confidence, 4), "safe": round(1.0 - confidence, 4)}
        stub = {
            "confidence": round(confidence, 4),
            "affected_file": file_path,
            "affected_function": function_name,
            "affected_lines": [],
            "reason_for_prediction": f"Explainability error: {error_msg}",
            "important_tokens": [],
            "attention_visualization_hooks": {
                "num_layers": 0, "num_heads": 0,
                "sequence_length": 0, "explainability_dimension": "0x0x0x0",
            },
            "human_readable_explanation": f"An internal error occurred during explanation: {error_msg}",
            "probability_distribution": prob_dist,
            "vulnerable_lines": [],
            "attention_weights": {},
            "reason": f"Explainability error: {error_msg}",
            "highlighted_tokens": [],
        }
        return stub
