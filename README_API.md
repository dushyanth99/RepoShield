# 🔒 RepoShield Core API — Frontend Integration Guide

This guide describes how the React frontend interacts with the FastAPI backend. It covers URLs, authentication mechanics, endpoint payloads, rate limits, status tracking lifecycle, and code integration patterns.

---

## 🚀 Interactive API Documentation
When the backend server is running locally (e.g., via ngrok or on `localhost:8000`), you can access real-time interactive documentation directly in your browser:

*   **Swagger Interactive Docs:** [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs) (Allows you to construct requests, fill in JSON objects, and trigger endpoints directly).
*   **ReDoc Alternative View:** [http://127.0.0.1:8000/redoc](http://127.0.0.1:8000/redoc) (Clean, structured list view of schemas and models).

---

## 🔑 Authentication Endpoints

All requests to the backend authentication router are prefixed with `/auth`.

### 1. Register User
*   **Method:** `POST`
*   **Path:** `/auth/register`
*   **Content-Type:** `application/json`

#### Request Body
```json
{
  "full_name": "Alice Nguyen",
  "email": "alice@example.com",
  "password": "S3cur3P@ssw0rd!"
}
```
*Note: Passwords must be at least 8 characters long and contain at least one uppercase letter, one number, and one special character (e.g. `!@#$`).*

#### Response (201 Created)
```json
{
  "user_id": "848da07c-9a4f-4d32-9c32-a5de42e39958",
  "email": "alice@example.com",
  "message": "Account created successfully. You can now log in."
}
```

#### Error States
*   **409 Conflict:** Email is already registered.
*   **422 Unprocessable Entity:** Email is invalid or password does not meet complexity rules.

---

### 2. Login & JWT Token Retrieval
*   **Method:** `POST`
*   **Path:** `/auth/login`
*   **Content-Type:** `application/json`
*   **Rate Limit:** Strictly capped at **5 requests per minute per IP address**. Exceeding this rate limits return `HTTP 429 Too Many Requests`.

#### Request Body
```json
{
  "email": "alice@example.com",
  "password": "S3cur3P@ssw0rd!"
}
```

#### Response (200 OK)
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "user_id": "848da07c-9a4f-4d32-9c32-a5de42e39958",
  "email": "alice@example.com"
}
```
*Handoff: Store the `access_token` in local storage or state. Authenticated requests require the HTTP header:*
`Authorization: Bearer <your_access_token>`

#### Error States
*   **401 Unauthorized:** Invalid email or password (generic message to prevent email enumeration).
*   **429 Too Many Requests:** Rate limit exceeded.

---

## 🛠️ Security Remediation Pipeline

All pipeline requests are prefixed with `/api/v1/jobs`.

### 1. Trigger Vulnerability Scan & Remediation (Asynchronous)
*   **Method:** `POST`
*   **Path:** `/api/v1/jobs/scan`
*   **Content-Type:** `application/json`

#### Request Body
```json
{
  "file_path": "app/auth.py",
  "source_code": "query = 'SELECT * FROM users WHERE id = ' + user_id\ndb.execute(query)",
  "test_command": "pytest tests/test_auth.py -v",
  "user_id": "848da07c-9a4f-4d32-9c32-a5de42e39958"
}
```

#### Response (202 Accepted)
The server returns instantly with a `202 Accepted` status. The autonomous agent is queued as a FastAPI BackgroundTask so that the UI is not blocked during long-running tasks.
```json
{
  "job_id": "5fa7a1b8-c31a-4d22-b5cc-fb5a111a43ef",
  "status": "PENDING",
  "file_path": "app/auth.py",
  "initial_findings": 1,
  "has_critical": true,
  "business_risk_score": 0.95,
  "scan_summary": {
    "CRITICAL": 1,
    "HIGH": 0,
    "MEDIUM": 0,
    "LOW": 0,
    "INFO": 0
  },
  "message": "Scan job accepted. ShieldAgentOrchestrator is running in the background. Poll /api/v1/jobs/5fa7a1b8-c31a-4d22-b5cc-fb5a111a43ef for live status."
}
```

---

### 2. Poll Scan & Remediation Job Status
*   **Method:** `GET`
*   **Path:** `/api/v1/jobs/{job_id}`

#### Response (200 OK)
Use this endpoint to poll progress in the UI (e.g., every 2–3 seconds) until the status transitions to a final state (`VERIFIED` or `FAILED`).
```json
{
  "job_id": "5fa7a1b8-c31a-4d22-b5cc-fb5a111a43ef",
  "status": "VERIFIED",
  "file_path": "app/auth.py",
  "business_risk_score": 0.95,
  "model_armor_blocked": 0,
  "self_healing_count": 1,
  "pull_request_url": "https://github.com/dushyanth99/RepoShield/pull/24"
}
```

#### Lifecycle Status States (`status` field)
To draw a progression timeline in your UI, map the state values:

```
[ PENDING ] ────────► [ IN_PROGRESS ] ────────► [ SANDBOXING ]
                                                     │
                             ┌───────────────────────┴───────────────────────┐
                             ▼                                               ▼
                       [ VERIFIED ]                                     [ FAILED ]
                (Remediation PR opened,                         (Vulnerability could
               pull_request_url is populated)                 not be automatically fixed)
```

1.  `PENDING`: Initial state, analysis is starting.
2.  `IN_PROGRESS`: The background worker has picked up the job and is starting database transactions.
3.  `SANDBOXING`: The isolated Google Antigravity Agent sandbox has initialized; the code is being run and analyzed inside the secure environment.
4.  `VERIFIED`: Success state. The agent successfully patched the code, ran tests, and opened a remediation Pull Request. The `pull_request_url` contains the GitHub PR link.
5.  `FAILED`: Failure state. The file failed checks, model armor blocked command execution, or the agent reached maximum retries without fixing failing tests.

---

## 💻 React Integration Templates

Here are quick copy-paste snippets you can drop into your services layer.

### 1. Trigger Scan Request
```javascript
async function triggerVulnerabilityScan(filePath, code, testCommand, userId, jwtToken) {
  const url = "http://127.0.0.1:8000/api/v1/jobs/scan";
  
  const response = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${jwtToken}`
    },
    body: JSON.stringify({
      file_path: filePath,
      source_code: code,
      test_command: testCommand || "pytest tests/",
      user_id: userId
    })
  });
  
  if (!response.ok) {
    const err = await response.json();
    throw new Error(err.detail || "Failed to trigger scan");
  }
  
  return await response.json(); // Returns initial ScanAcceptedResponse payload
}
```

### 2. Polling Status Manager
```javascript
function startPollingJob(jobId, jwtToken, onStateChange, onComplete, onError) {
  const url = `http://127.0.0.1:8000/api/v1/jobs/${jobId}`;
  
  const interval = setInterval(async () => {
    try {
      const response = await fetch(url, {
        method: "GET",
        headers: {
          "Authorization": `Bearer ${jwtToken}`
        }
      });
      
      if (!response.ok) {
        throw new Error("Failed to poll status");
      }
      
      const jobData = await response.json();
      onStateChange(jobData);
      
      // Stop polling when we reach terminal states
      if (jobData.status === "VERIFIED" || jobData.status === "FAILED") {
        clearInterval(interval);
        onComplete(jobData);
      }
    } catch (err) {
      clearInterval(interval);
      onError(err);
    }
  }, 3000); // Polls every 3 seconds
  
  return () => clearInterval(interval); // Return cleanup function
}
```
