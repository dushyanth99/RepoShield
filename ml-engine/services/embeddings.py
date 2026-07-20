import torch
import numpy as np
from typing import List
from transformers import AutoModel, AutoTokenizer
from config import MODEL_CHECKPOINT
from utils.logging_utils import setup_logger

logger = setup_logger("embeddings-service")


class EmbeddingService:
    """Generates semantic code embeddings using CodeBERT for similarity analysis and semantic search."""

    def __init__(self, checkpoint: str = MODEL_CHECKPOINT):
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        logger.info("Initializing EmbeddingService on device: %s...", self.device)
        try:
            self.tokenizer = AutoTokenizer.from_pretrained(checkpoint)
            # Load base transformer model without classification head for raw embeddings
            self.model = AutoModel.from_pretrained(checkpoint)
            self.model.to(self.device)
            self.model.eval()
        except Exception as e:
            logger.error("Failed to initialize EmbeddingService: %s", e)
            raise e

    def get_embedding(self, code: str) -> List[float]:
        """Extracts the semantic embedding vector (CLS token hidden state) for a code snippet.

        Args:
            code: Source code snippet.

        Returns:
            List of floats representing the embedding vector.
        """
        if not code or not code.strip():
            # Return zero vector if input is empty
            return [0.0] * 768

        try:
            inputs = self.tokenizer(
                code,
                padding=False,
                truncation=True,
                max_length=512,
                return_tensors="pt"
            )
            input_ids = inputs["input_ids"].to(self.device)
            attention_mask = inputs["attention_mask"].to(self.device)

            with torch.no_grad():
                outputs = self.model(input_ids, attention_mask=attention_mask)
                # Take CLS token embedding (index 0 of last hidden state)
                cls_embedding = outputs.last_hidden_state[0, 0].cpu().numpy()

            return cls_embedding.tolist()
        except Exception as e:
            logger.error("Failed to extract embedding: %s", e)
            return [0.0] * 768

    @staticmethod
    def cosine_similarity(v1: List[float], v2: List[float]) -> float:
        """Computes the cosine similarity score between two embedding vectors.

        Args:
            v1: First vector.
            v2: Second vector.

        Returns:
            Cosine similarity score as a float between -1.0 and 1.0.
        """
        arr1 = np.array(v1)
        arr2 = np.array(v2)
        norm1 = np.linalg.norm(arr1)
        norm2 = np.linalg.norm(arr2)
        if norm1 == 0.0 or norm2 == 0.0:
            return 0.0
        return float(np.dot(arr1, arr2) / (norm1 * norm2))
