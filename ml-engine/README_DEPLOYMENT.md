# RepoShield Deployment Guide

This document outlines how to deploy the RepoShield ML Engine.

## Dataset & Model Download Flow
The application is designed to be lightweight in version control. The heavy SQLite dataset (`CVEFixes.db`) and large fine-tuned model weights (`model.safetensors`, ~318 MB) are **not** stored in Git.
Instead, when the application starts, it performs checks and automatically downloads the dataset and model weights from Hugging Face if they are missing locally.
This ensures seamless deployment on cloud platforms without ballooning the repository size.

## Hosting ML Model on Hugging Face Models
The fine-tuned CodeBERT model weights (`model.safetensors`) are hosted on Hugging Face Models.

### Required Environment Variables
* `MODEL_REPO_ID`: The Hugging Face model repository ID (e.g., `Thanmaisri/RepoShield-CodeBERT`).
* `MODEL_FILENAME`: Name of the model weight file (default: `model.safetensors`).
* `HF_TOKEN`: Hugging Face User Access Token (required only if the repository is private).

### Deployment Flow
1. **Application Starts**
2. **Check Dataset** → Downloads `CVEFixes.db` from Hugging Face Datasets if missing.
3. **Check Model** → Downloads `model.safetensors` from Hugging Face Models if missing.
4. **Open SQLite** → Connects to local datastore.
5. **Load Tokenizer & CodeBERT Model** → Loads tokenizer & model into memory.
6. **Initialize Services** → Prepares scanner and agent orchestrators.
7. **Start FastAPI** → Begins serving API endpoints.

## Local Run
1. Ensure you have Python 3.11 installed.
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Run the application:
   ```bash
   uvicorn main:app --host 0.0.0.0 --port 8000
   ```
   The application will automatically download the dataset and initialize the database on first startup.

## Environment Variables
Refer to `.env.example` for configurable variables. You can set these in your hosting provider's dashboard or in a local `.env` file.

## Render Deployment
1. Connect your repository to Render.
2. The `render.yaml` file in the root directory will automatically configure the service.
3. Render will run the `buildCommand` and then the `startCommand` defined in `render.yaml`.
4. The application will fetch its dataset dynamically upon startup.

## Railway Deployment
1. Connect your repository to Railway.
2. Railway will automatically detect the `Procfile` and use it to start the service.
3. Alternatively, Railway can build from the provided `Dockerfile` if you prefer containerized deployment.

## Docker Deployment
Build the image:
```bash
docker build -t reposhield-ml .
```
Run the container:
```bash
docker run -p 8000:8000 reposhield-ml
```
