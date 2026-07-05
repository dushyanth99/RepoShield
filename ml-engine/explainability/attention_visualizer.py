import numpy as np
from typing import Any, Dict, List, Optional, Tuple

from utils.logging_utils import setup_logger

logger = setup_logger("explainability.attention_visualizer")

# Tokens emitted by the RoBERTa/CodeBERT tokenizer that carry no semantic information
_SPECIAL_TOKENS = frozenset(["<s>", "</s>", "<pad>", "<mask>", "[CLS]", "[SEP]", "[PAD]"])


class AttentionVisualizer:
    """Formats attention weight maps into visual hooks and heatmaps for developer portals."""

    @staticmethod
    def generate_heatmap_data(
        tokens: List[str],
        attentions: List[float],
        offset_mapping: List[Tuple[int, int]],
    ) -> List[Dict[str, Any]]:
        """Compiles tokens and normalized weights for line and keyword highlighting.

        All three lists must have equal length (one entry per token).  Special tokens
        (``<s>``, ``</s>``, ``<pad>``, ``<mask>`` etc.) are excluded from the output.

        Args:
            tokens: String representation of each subword token.
            attentions: Summed or mean attention score for each token.  Must be the same
                length as ``tokens`` and ``offset_mapping``.
            offset_mapping: Token character start/end boundary pairs.  Must be the same
                length as ``tokens`` and ``attentions``.

        Returns:
            List of visualization hook dicts, sorted descending by ``weight``.  Each dict
            contains ``token``, ``weight`` (raw), ``importance`` (0–1 normalized), and
            ``range`` ([start, end] character positions).

        Raises:
            ValueError: If the three input lists have different lengths.
        """
        # Convert numpy arrays to standard Python lists to avoid type checks / truth value errors
        if isinstance(tokens, np.ndarray):
            tokens = tokens.tolist()
        if isinstance(attentions, np.ndarray):
            attentions = attentions.tolist()
        if isinstance(offset_mapping, np.ndarray):
            offset_mapping = offset_mapping.tolist()

        if not isinstance(tokens, list) or not isinstance(attentions, list) or not isinstance(offset_mapping, list):
            logger.warning("generate_heatmap_data received invalid argument types; returning [].")
            return []

        if len(tokens) != len(attentions) or len(tokens) != len(offset_mapping):
            raise ValueError(
                f"tokens ({len(tokens)}), attentions ({len(attentions)}), and "
                f"offset_mapping ({len(offset_mapping)}) must all have the same length."
            )

        if len(tokens) == 0:
            logger.debug("generate_heatmap_data called with empty token list; returning [].")
            return []

        try:
            max_att = float(max(attentions)) if len(attentions) > 0 else 1.0
        except (ValueError, TypeError) as exc:
            logger.warning("Could not calculate max of attentions: %s", exc)
            max_att = 1.0

        if max_att == 0.0:
            max_att = 1.0  # avoid division by zero when all attentions are 0

        heatmap: List[Dict[str, Any]] = []
        for idx, token in enumerate(tokens):
            # Skip special / padding tokens in visualization output
            if token in _SPECIAL_TOKENS:
                continue

            try:
                weight = float(attentions[idx])
                start, end = offset_mapping[idx]
            except (IndexError, ValueError, TypeError) as exc:
                logger.warning("Malformed token metadata or weight at index %d: %s", idx, exc)
                continue

            normalized_weight = weight / max_att

            heatmap.append({
                "token": str(token),
                "weight": round(weight, 5),
                "importance": round(normalized_weight, 4),  # relative weight 0.0–1.0
                "range": [int(start), int(end)],
            })

        return sorted(heatmap, key=lambda x: x["weight"], reverse=True)

    @staticmethod
    def get_attention_matrix_hook(attentions_tuple: Optional[Tuple[Any, ...]]) -> Dict[str, Any]:
        """Exposes raw visual hook metadata from the CodeBERT model attention layers.

        Provides layer/head/sequence-length information so a frontend can allocate the
        correct tensor shapes for full attention-matrix rendering.

        Args:
            attentions_tuple: Tuple of attention tensors, one per transformer layer.
                Each tensor has shape ``(batch, heads, seq_len, seq_len)``.
                Pass ``None`` or an empty tuple for a safe empty-hook response.

        Returns:
            Dict with keys ``num_layers``, ``num_heads``, ``sequence_length``,
            ``explainability_dimension``.  Returns a zeroed dict if input is empty/None.
        """
        if not attentions_tuple:
            logger.warning("get_attention_matrix_hook received empty/None attentions_tuple.")
            return {
                "num_layers": 0,
                "num_heads": 0,
                "sequence_length": 0,
                "explainability_dimension": "0x0x0x0",
            }

        try:
            num_layers = len(attentions_tuple)
            # Validate expected tensor shape properties
            if num_layers == 0 or not hasattr(attentions_tuple[0], "shape"):
                raise ValueError("attentions_tuple contains malformed layers.")
            
            shape = attentions_tuple[0].shape
            if len(shape) < 3:
                raise ValueError(f"attentions_tuple[0] shape is too small: {shape}")

            num_heads = int(shape[1])
            seq_len = int(shape[2])
            return {
                "num_layers": num_layers,
                "num_heads": num_heads,
                "sequence_length": seq_len,
                "explainability_dimension": f"{num_layers}x{num_heads}x{seq_len}x{seq_len}",
            }
        except (IndexError, AttributeError, ValueError, TypeError) as exc:
            logger.error("Failed to extract attention matrix hook metadata: %s", exc)
            return {
                "num_layers": 0,
                "num_heads": 0,
                "sequence_length": 0,
                "explainability_dimension": "0x0x0x0",
            }
