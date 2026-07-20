import logging
from pathlib import Path
from huggingface_hub import hf_hub_download
from dataset.config import HF_REPO_ID, HF_FILENAME, LOCAL_DB_PATH

# Configure basic logging for the downloader
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def download_dataset():
    local_path = Path(LOCAL_DB_PATH)
    logger.info("Checking local dataset...")
    if local_path.exists():
        logger.info("Dataset found locally.")
        return

    logger.info("Dataset not found.")
    logger.info("Downloading dataset from Hugging Face...")
    try:
        # Download the database to the specified local path parent folder
        hf_hub_download(
            repo_id=HF_REPO_ID,
            filename=HF_FILENAME,
            repo_type="dataset",
            local_dir=str(local_path.parent)
        )
        logger.info("Download completed successfully.")
    except Exception as e:
        logger.error(f"Download failed: {e}")
        # Clean up partially downloaded database if huggingface_hub leaves one locally
        if local_path.exists():
            try:
                local_path.unlink()
            except OSError:
                pass
        raise RuntimeError(f"Failed to download dataset from Hugging Face: {e}") from e
