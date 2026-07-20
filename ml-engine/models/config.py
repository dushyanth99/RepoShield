import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

# Hugging Face Model Repository Configuration
MODEL_REPO_ID = os.getenv("MODEL_REPO_ID", "Thanmaisri/RepoShield-CodeBERT")
MODEL_FILENAME = os.getenv("MODEL_FILENAME", "model.safetensors")
HF_TOKEN = os.getenv("HF_TOKEN", None)

# Path configuration for local model storage
SAVED_MODELS_DIR = Path(__file__).parent.parent / "saved_models"
LOCAL_MODEL_DIR = SAVED_MODELS_DIR / "best_model"
LOCAL_MODEL_PATH = LOCAL_MODEL_DIR / MODEL_FILENAME
