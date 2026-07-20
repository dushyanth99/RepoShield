import os
from pathlib import Path
from huggingface_hub import snapshot_download
from models.config import MODEL_REPO_ID, LOCAL_MODEL_DIR, HF_TOKEN
from utils.logging_utils import setup_logger

logger = setup_logger("model-downloader")

def check_model() -> Path:
    """
    Checks whether the Hugging Face model exists locally inside saved_models/best_model.
    If missing, downloads Thanmaisri/RepoShield-CodeBERT using snapshot_download().
    Supports HF_TOKEN authentication and anonymous downloads.
    """
    logger.info("Checking Hugging Face model...")

    token = os.getenv("HF_TOKEN", HF_TOKEN)
    if token:
        logger.info("HF_TOKEN detected.")
    else:
        logger.info("HF_TOKEN not provided. Using anonymous download.")
        token = None

    config_file = LOCAL_MODEL_DIR / "config.json"
    if config_file.exists():
        logger.info("Model already cached.")
        return LOCAL_MODEL_DIR

    logger.info("Downloading model...")
    try:
        LOCAL_MODEL_DIR.mkdir(parents=True, exist_ok=True)
        snapshot_download(
            repo_id=MODEL_REPO_ID,
            local_dir=str(LOCAL_MODEL_DIR),
            token=token
        )
        logger.info("Download completed.")
        return LOCAL_MODEL_DIR
    except Exception as e:
        logger.error(f"Download failed for repository '{MODEL_REPO_ID}': {e}")
        # Clean up directory if partially downloaded
        if LOCAL_MODEL_DIR.exists():
            for child in LOCAL_MODEL_DIR.glob("*"):
                try:
                    if child.is_file():
                        child.unlink()
                except OSError:
                    pass
        raise RuntimeError(
            f"Failed to download model from Hugging Face repository '{MODEL_REPO_ID}': {e}"
        ) from e

def download_model() -> Path:
    """Alias for check_model() for backward compatibility."""
    return check_model()

if __name__ == "__main__":
    check_model()
