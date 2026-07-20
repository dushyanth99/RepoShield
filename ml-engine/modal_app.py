import os
import sys
import modal

# Define the Modal application
app = modal.App("RepoShield-ml-engine")

# Define the container image
# - Uses Debian Slim with Python 3.11
# - Installs dependencies from the local requirements.txt
# Mount the entire current directory (ml-engine) to /root/ml-engine inside the container
# This ensures all folders like saved_models/, config.py, services/, etc., are available
image = (
    modal.Image.debian_slim(python_version="3.11")
    .pip_install_from_requirements("requirements.txt")
    .add_local_dir(
        ".", 
        remote_path="/root/ml-engine",
        ignore=["**/.venv/**", "**/__pycache__/**", "**/.git/**", "**/*.pyc"]
    )
)

# Expose the FastAPI app as an ASGI application
# - Applies the custom image and local mount
# - Sets a timeout of 600 seconds for longer ML inference tasks
@app.function(
    image=image,
    timeout=600,
)
@modal.asgi_app()
def fastapi_endpoint():
    """
    Entry point for the Modal deployment.
    This function sets up the environment and returns the FastAPI application instance.
    """
    # Ensure the working directory is set to where the project is mounted
    target_dir = "/root/ml-engine"
    if target_dir not in sys.path:
        sys.path.insert(0, target_dir)
    os.chdir(target_dir)

    # Import the FastAPI instance from app.py
    # This must be done inside the function so it executes inside the Modal container
    from app import app as fastapi_app
    
    return fastapi_app
