# 🛡️ RepoShield

**RepoShield** is an autonomous, AI-driven DevSecOps pipeline. It actively scans GitHub repositories for vulnerabilities (such as hardcoded secrets and SQL injections) and employs advanced agents to generate, validate, and propose self-healing code patches in real-time.

---

## 🏗️ Architectural Overview

RepoShield is structured as a monorepo containing three core microservices:

1. **`frontend/` (React)**
   - The user-facing dashboard for linking GitHub repositories and viewing live telemetry.
2. **`backend/` (FastAPI + SQLAlchemy)**
   - The core orchestration engine. Manages secure webhooks, client authentication (JWT), database state, and the autonomous Shield Agent execution loop.
3. **`ml-engine/` (Python / CodeBERT)**
   - The intelligence layer responsible for evaluating vulnerabilities, predicting business impact, and assisting the agent with remediation logic.

---

## 🚀 Setup & Installation Guide

To run RepoShield locally, you will need to start the three services in their respective environments.

### Prerequisites
- Python 3.10+
- Node.js 18+
- Git

---

### 1. ML Engine Setup
The Machine Learning engine must be started first, as the backend relies on it for vulnerability analysis.

```bash
cd ml-engine
python -m venv venv

# Activate the virtual environment
# On Windows:
venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Start the ML Engine server
python app.py
```
*The ML Engine will run on `http://127.0.0.1:8001`.*

---

### 2. Backend Setup
The backend utilizes FastAPI and asynchronous database connections.

```bash
cd backend
python -m venv venv

# Activate the virtual environment
# On Windows:
venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Set up the Database (Applies Alembic migrations)
python -m alembic upgrade head

# Start the Backend Server
python -m uvicorn main:app --host 127.0.0.1 --port 8000 --reload
```
*The Backend API will run on `http://127.0.0.1:8000`.*

---

### 3. Frontend Setup
The frontend is built with React and serves as the primary dashboard.

```bash
cd frontend

# Install dependencies
npm install

# Start the development server
npm run dev
```
*The Frontend will run on `http://localhost:3000`.*

---

## 🔗 Environment Variables (`.env`)

You will need to configure `.env` files for your environments.

**Backend (`backend/.env`):**
```env
# Database Configuration
DATABASE_URL=sqlite+aiosqlite:///reposhield.db
# Or for MySQL: mysql+aiomysql://user:password@localhost:3306/reposhield

# Security (Replace with strong random values in production)
JWT_SECRET_KEY=your_secure_jwt_secret
GITHUB_WEBHOOK_SECRET=your_secure_webhook_secret

# LLM / ML Engine Endpoints
ML_ENGINE_URL=http://127.0.0.1:8001
```

---

## 📡 Unified JSON Handshake (Telemetry)
RepoShield utilizes a real-time Server-Sent Events (SSE) stream to provide live feedback to the frontend without heavy polling. The standardized payload looks like this:

```json
{
  "status": "VERIFIED",
  "active_file": "app/auth.py",
  "business_impact_score": 0.94,
  "compliance_verified": false,
  "sandbox_command": "pytest tests/test_auth.py",
  "model_armor_status": "SECURE",
  "fable_5_trace_applied": "Resolved implicit string allocation mismatch.",
  "predictive_trend": "High probability of unvalidated parameter exploits.",
  "pr_url": "https://github.com/user/repo/pull/1"
}
```

For a deeper dive into the API endpoints and webhook ingestion, see the [Frontend Integration Guide](frontend_integration_guide.md).