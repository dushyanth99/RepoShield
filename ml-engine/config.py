import os
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables from a .env file if it exists
load_dotenv()

# Base directories
ML_ENGINE_DIR = Path(__file__).parent.resolve()
WORKSPACE_DIR = ML_ENGINE_DIR.parent.parent.resolve()

# Auto-detect CVEfixes SQL dump location
def detect_sql_path() -> Path:
    # Potential paths relative to workspace or ml-engine
    candidates = [
        WORKSPACE_DIR / "CVEfixes_v1.0.8" / "CVEfixes_v1.0.8" / "Data" / "CVEfixes_v1.0.8.sql" / "CVEfixes_v1.0.8.sql",
        WORKSPACE_DIR / "CVEfixes_v1.0.8" / "Data" / "CVEfixes_v1.0.8.sql" / "CVEfixes_v1.0.8.sql",
        ML_ENGINE_DIR / "dataset" / "CVEfixes_v1.0.8.sql",
    ]
    
    # Check environment variable overrides first
    env_path = os.getenv("CVEFIXES_SQL_PATH")
    if env_path:
        p = Path(env_path)
        if p.exists():
            return p
            
    for candidate in candidates:
        if candidate.exists():
            return candidate
            
    # Default to standard location even if not found yet (so it can be configured)
    return candidates[0]

# Database Config
CVEFIXES_SQL_PATH = Path(os.getenv("CVEFIXES_SQL_PATH", str(detect_sql_path())))
DB_PATH = Path(os.getenv("DB_PATH", str(ML_ENGINE_DIR / "dataset" / "CVEFixes.db")))

# Model & Training Config
MODEL_CHECKPOINT = os.getenv("MODEL_CHECKPOINT", "huggingface/CodeBERTa-small-v1")
SAVED_MODEL_DIR = Path(os.getenv("SAVED_MODEL_DIR", str(ML_ENGINE_DIR / "saved_models")))

MAX_TRAIN_SAMPLES = int(os.getenv("MAX_TRAIN_SAMPLES", "5000"))
BATCH_SIZE = int(os.getenv("BATCH_SIZE", "8"))
EPOCHS = int(os.getenv("EPOCHS", "3"))
LEARNING_RATE = float(os.getenv("LEARNING_RATE", "2e-5"))

# API Config
FASTAPI_HOST = os.getenv("FASTAPI_HOST", "0.0.0.0")
FASTAPI_PORT = int(os.getenv("FASTAPI_PORT", "8000"))

# Ensure required directories exist
DB_PATH.parent.mkdir(parents=True, exist_ok=True)
SAVED_MODEL_DIR.mkdir(parents=True, exist_ok=True)
