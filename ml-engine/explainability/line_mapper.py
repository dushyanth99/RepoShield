import numpy as np
from typing import Dict, List, Tuple

from utils.logging_utils import setup_logger

logger = setup_logger("explainability.line_mapper")


class LineMapper:
    """Maps token-level offsets and character spans back to source code lines."""

    @staticmethod
    def compute_line_offsets(code: str) -> List[Tuple[int, int]]:
        """Computes the start and end character offsets for each line in the code.

        Args:
            code: The source code string.

        Returns:
            A list of tuples (start_offset, end_offset) for each line (0-indexed).
            Returns an empty list if code is empty, None, or not a string.
        """
        if not isinstance(code, str):
            logger.warning("compute_line_offsets received non-string code input: %s", type(code))
            return []
        if not code:
            return []
        lines = code.splitlines()
        offsets: List[Tuple[int, int]] = []
        current = 0
        for line in lines:
            offsets.append((current, current + len(line)))
            current += len(line) + 1  # +1 for the newline character
        return offsets

    @classmethod
    def map_offset_to_line(cls, offset: int, line_offsets: List[Tuple[int, int]]) -> int:
        """Finds the 1-indexed line number corresponding to a character offset.

        Scans all line ranges and returns the matching line number.
        Falls back to 1 when the offset does not match any line (e.g. padding tokens).

        Args:
            offset: The character index offset in the source code.
            line_offsets: Output of :meth:`compute_line_offsets`.

        Returns:
            Line number (1-indexed), or 1 as fallback.
        """
        try:
            val = int(offset)
        except (TypeError, ValueError):
            logger.warning("map_offset_to_line received invalid offset: %s", offset)
            return 1

        for idx, (start, end) in enumerate(line_offsets):
            if start <= val <= end:
                return idx + 1
        return 1

    @classmethod
    def map_attention_to_lines(
        cls,
        code: str,
        offset_mapping: List[Tuple[int, int]],
        token_attentions: List[float],
    ) -> Dict[int, float]:
        """Aggregates attention weights across lines of code.

        Maps each token's attention weight onto the source line it belongs to,
        producing a per-line score suitable for highlighting the most suspicious areas.

        Args:
            code: Original source code string.
            offset_mapping: Token offset mappings — list of (char_start, char_end) tuples,
                one per token.  Must be the same length as ``token_attentions``.
            token_attentions: Attention weight for each token.  Must be the same length
                as ``offset_mapping``.

        Returns:
            Dictionary mapping line number (int, 1-indexed) to aggregated attention
            weight (float).  All lines present in ``code`` are guaranteed to appear
            as keys with at least 0.0.

        Raises:
            ValueError: If ``offset_mapping`` and ``token_attentions`` have different lengths.
        """
        # Convert numpy arrays to standard Python lists to avoid type checks / truth value errors
        if isinstance(offset_mapping, np.ndarray):
            offset_mapping = offset_mapping.tolist()
        if isinstance(token_attentions, np.ndarray):
            token_attentions = token_attentions.tolist()

        if not isinstance(offset_mapping, list) or not isinstance(token_attentions, list):
            logger.warning("map_attention_to_lines received invalid argument types.")
            return {}

        if len(offset_mapping) != len(token_attentions):
            raise ValueError(
                f"offset_mapping length ({len(offset_mapping)}) must equal "
                f"token_attentions length ({len(token_attentions)})."
            )

        line_offsets = cls.compute_line_offsets(code)
        line_scores: Dict[int, float] = {i + 1: 0.0 for i in range(len(line_offsets))}

        if not line_offsets:
            return line_scores

        for idx, item in enumerate(offset_mapping):
            try:
                start, end = item
                weight = float(token_attentions[idx])
            except (TypeError, ValueError, IndexError) as exc:
                logger.warning("Malformed input or weight at index %d: %s", idx, exc)
                continue

            # Skip padding / special tokens (both offsets == 0 and idx > 0)
            if start == 0 and end == 0 and idx > 0:
                continue

            line_num = cls.map_offset_to_line(int(start), line_offsets)
            if line_num in line_scores:
                line_scores[line_num] += weight

        return line_scores
