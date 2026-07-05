import torch
import torch.nn as nn
from transformers import AutoModelForSequenceClassification, AutoConfig
from utils.logging_utils import setup_logger
from config import MODEL_CHECKPOINT

logger = setup_logger("model-classifier")

class CodeBERTClassifier(nn.Module):
    """Wrapper around Hugging Face Sequence Classification models with dropout and attention extraction."""
    def __init__(self, checkpoint: str = MODEL_CHECKPOINT, num_labels: int = 2, dropout_prob: float = 0.1):
        super().__init__()
        logger.info(f"Initializing Sequence Classifier model using checkpoint: {checkpoint}...")
        
        # Load config and ensure it exports attentions for explainability
        config = AutoConfig.from_pretrained(checkpoint)
        config.num_labels = num_labels
        config.output_attentions = True
        config.hidden_dropout_prob = dropout_prob
        config.attention_probs_dropout_prob = dropout_prob

        self.model = AutoModelForSequenceClassification.from_pretrained(
            checkpoint,
            config=config
        )
        
    def forward(self, input_ids: torch.Tensor, attention_mask: torch.Tensor, labels: torch.Tensor = None) -> tuple:
        """Forward pass of the model.
        
        Returns:
            If labels is provided: (loss, logits, attentions)
            If labels is NOT provided: (logits, attentions)
        """
        outputs = self.model(
            input_ids=input_ids,
            attention_mask=attention_mask,
            labels=labels
        )
        # outputs.attentions contains tuple of attention weights from all layers
        if labels is not None:
            return outputs.loss, outputs.logits, outputs.attentions
        return outputs.logits, outputs.attentions

    def save_pretrained(self, save_path: str) -> None:
        """Saves the fine-tuned model and configuration."""
        logger.info(f"Saving model to {save_path}")
        self.model.save_pretrained(save_path)

    @classmethod
    def from_pretrained(cls, save_path: str) -> 'CodeBERTClassifier':
        """Loads a fine-tuned model from the local directory."""
        logger.info(f"Loading custom fine-tuned model from {save_path}")
        classifier = cls()
        classifier.model = AutoModelForSequenceClassification.from_pretrained(
            save_path,
            output_attentions=True
        )
        return classifier
