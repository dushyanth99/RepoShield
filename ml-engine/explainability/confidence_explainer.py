import math
from typing import Dict

from utils.logging_utils import setup_logger

logger = setup_logger("explainability.confidence_explainer")


class ConfidenceExplainer:
    """Explains model confidence ratings and evaluates classification probability distributions."""

    @staticmethod
    def get_probability_distribution(vulnerable_prob: float) -> Dict[str, float]:
        """Formulates the binary probability distribution for a vulnerability prediction.

        Clamps ``vulnerable_prob`` to ``[0.0, 1.0]`` before computing the complementary
        safe probability to prevent negative or >1.0 values from invalid inputs.
        Gracefully handles NaN and infinite float values by falling back to 0.5.

        Args:
            vulnerable_prob: Raw probability of class 1 (vulnerable).  Should be in
                ``[0.0, 1.0]``; values outside this range are clamped with a warning.

        Returns:
            Dict with keys ``"vulnerable"`` and ``"safe"``, both rounded to 4 decimal places.
        """
        # Handle NaN or Infinite probabilities
        try:
            if math.isnan(vulnerable_prob) or math.isinf(vulnerable_prob):
                logger.warning("vulnerable_prob is NaN or Infinite; falling back to 0.5")
                vulnerable_prob = 0.5
        except (TypeError, ValueError):
            logger.warning("vulnerable_prob is not a valid float; falling back to 0.5")
            vulnerable_prob = 0.5

        if not 0.0 <= vulnerable_prob <= 1.0:
            logger.warning(
                "vulnerable_prob %.4f is outside [0.0, 1.0]; clamping.", vulnerable_prob
            )
            vulnerable_prob = max(0.0, min(1.0, vulnerable_prob))

        safe_prob = 1.0 - vulnerable_prob
        return {
            "vulnerable": round(float(vulnerable_prob), 4),
            "safe": round(float(safe_prob), 4),
        }

    @classmethod
    def explain_confidence(cls, vulnerable_prob: float, vulnerable: bool) -> str:
        """Generates a text description explaining the model's certainty level.

        Derives certainty language from the probability of whichever class the
        model decided (vulnerable or safe), so the explanation always matches the
        final decision rather than raw logit magnitude.

        Args:
            vulnerable_prob: Raw class-1 probability (before any threshold adjustment).
            vulnerable: Final consensus decision — ``True`` if classified as vulnerable.

        Returns:
            Human-readable certainty sentence.
        """
        prob_dist = cls.get_probability_distribution(vulnerable_prob)
        target_prob = prob_dist["vulnerable"] if vulnerable else prob_dist["safe"]

        if target_prob >= 0.90:
            certainty = "Extremely Confident"
        elif target_prob >= 0.70:
            certainty = "Confident"
        elif target_prob >= 0.50:
            certainty = "Marginally Confident"
        else:
            certainty = "Low Confidence"

        action = "vulnerable risk signatures" if vulnerable else "safe logic structures"
        return (
            f"Model is {certainty} ({target_prob:.2%}) in its decision. "
            f"The code demonstrates strong features correlating to {action}."
        )
