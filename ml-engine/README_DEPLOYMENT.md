# RepoShield Deployment Guide

This document outlines how to deploy the RepoShield ML Engine.

## Dataset Download Flow
The application is designed to be lightweight in version control. The heavy SQLite dataset (`CVEFixes.db`) and ML models are **not** stored in Git.
Instead, when the application starts, it performs a check and automatically downloads the dataset from Hugging Face if it's missing locally.
This ensures seamless deployment on cloud platforms without ballooning the repository size.

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
