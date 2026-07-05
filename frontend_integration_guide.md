# RepoShield: Frontend Integration Guide

Welcome to the RepoShield Frontend Integration Guide. This document provides the React engineering team with a crystal-clear roadmap for interfacing with our bifurcated FastAPI backend. 

Our architecture enforces strict security boundaries: **the client application must never hold, process, or transmit webhook secrets (HMAC).** All client-to-server operations utilize standard JSON Web Tokens (JWT) for authentication.

---

## 1. The Repository Connection Flow

In RepoShield, we do not require users to upload raw code blocks or zip files. Instead, repositories are ingested securely via our GitHub App installation loop.

### How it Works:
- **Step A:** The user clicks a "Connect GitHub" button in the React UI, which redirects them to our public GitHub App installation URL.
- **Step B:** The user authorizes the application on GitHub. GitHub then redirects the user back to our React application, injecting an `installation_id` and the authorized repository names as URL query parameters.
- **Step C:** The frontend extracts these parameters and makes an authenticated `POST` request to the backend to finalize the repository linkage.

### Implementation

Ensure you define strict TypeScript interfaces for your payloads.

```typescript
import axios from 'axios';

interface RepositoryLinkPayload {
  user_id: string;
  repo_name: string;
  installation_id: number;
}

/**
 * Links an authorized GitHub repository to the user's account.
 * Call this function after the GitHub OAuth redirect.
 */
export const linkRepository = async (
  payload: RepositoryLinkPayload,
  jwtToken: string
): Promise<void> => {
  try {
    const response = await axios.post('/api/v1/repositories/', payload, {
      headers: {
        Authorization: `Bearer ${jwtToken}`,
        'Content-Type': 'application/json'
      }
    });
    
    console.log('Repository linked successfully:', response.data);
  } catch (error) {
    console.error('Failed to link repository:', error);
    throw error;
  }
};
```

---

## 2. Manually Triggering a Security Scan

To trigger a scan manually from the UI, the frontend utilizes Route A (`/scan/manual`). 

> [!CAUTION]
> The frontend must **NEVER** attempt to mock or generate GitHub HMAC signatures. Webhook emulation is strictly prohibited on the client. Always use the `/scan/manual` endpoint with your standard session JWT.

### Implementation

When a user initiates a scan, the backend verifies ownership, enqueues the job, and immediately returns an `HTTP 202 Accepted` response containing the `job_id`.

```typescript
interface ManualScanPayload {
  repository_id: string;
}

interface ScanAcceptedResponse {
  job_id: string;
  status: string;
  file_path: string;
  category: string;
  business_risk_score: number;
  message: string;
}

/**
 * Triggers an autonomous security scan on a linked repository.
 */
export const triggerManualScan = async (
  repositoryId: string,
  jwtToken: string
): Promise<string> => {
  try {
    const payload: ManualScanPayload = { repository_id: repositoryId };
    
    const response = await axios.post<ScanAcceptedResponse>(
      '/api/v1/jobs/scan/manual', 
      payload, 
      {
        headers: {
          Authorization: `Bearer ${jwtToken}`,
          'Content-Type': 'application/json'
        }
      }
    );
    
    // Extract the job_id to initialize the live telemetry stream
    return response.data.job_id;
  } catch (error) {
    console.error('Failed to trigger scan:', error);
    throw error;
  }
};
```

---

## 3. Real-Time Telemetry Stream (Server-Sent Events)

RepoShield's autonomous agents operate asynchronously. Instead of aggressively polling a REST API—which chokes the database and degrades UX—the frontend must open a single, lightweight Server-Sent Events (SSE) connection to track live progress.

### Implementation

Utilize the native browser `EventSource` API within a React `useEffect` hook. This ensures the connection is established when the component mounts and is cleanly severed when the component unmounts or the job completes.

```tsx
import React, { useEffect, useState } from 'react';

// Define the expected stream states
type JobStatus = 'PENDING' | 'SANDBOXING' | 'ML_EVALUATION' | 'FABLE_5_REMEDIATION' | 'VERIFIED' | 'FAILED';

interface TelemetryEvent {
  job_id: string;
  status: JobStatus;
  file_path: string;
  business_risk_score: number;
  model_armor_blocked: number;
  self_healing_count: number;
  pull_request_url?: string | null;
}

interface LiveScannerProps {
  jobId: string;
}

export const LiveScannerStream: React.FC<LiveScannerProps> = ({ jobId }) => {
  const [telemetry, setTelemetry] = useState<TelemetryEvent | null>(null);
  const [isComplete, setIsComplete] = useState<boolean>(false);

  useEffect(() => {
    if (!jobId) return;

    // Initialize the SSE connection
    const eventSource = new EventSource(`/api/v1/jobs/${jobId}/stream`);

    // Listen for incoming messages
    eventSource.onmessage = (event) => {
      try {
        const data: TelemetryEvent = JSON.parse(event.data);
        setTelemetry(data);

        // Terminate the connection if the job reaches a terminal state
        if (data.status === 'VERIFIED' || data.status === 'FAILED') {
          setIsComplete(true);
          eventSource.close();
        }
      } catch (error) {
        console.error('Failed to parse SSE telemetry data:', error);
      }
    };

    eventSource.onerror = (error) => {
      console.error('SSE Stream disconnected or encountered an error:', error);
      eventSource.close();
    };

    // Cleanup function: guarantee the socket closes when the component unmounts
    return () => {
      eventSource.close();
    };
  }, [jobId]);

  return (
    <div className="telemetry-dashboard">
      <h3>Live Job Status: {telemetry?.status || 'CONNECTING...'}</h3>
      {telemetry && (
        <ul>
          <li><strong>Target File:</strong> {telemetry.file_path}</li>
          <li><strong>Self-Healing Iterations:</strong> {telemetry.self_healing_count}</li>
          <li><strong>Model Armor Blocked Prompts:</strong> {telemetry.model_armor_blocked}</li>
        </ul>
      )}
      
      {isComplete && telemetry?.status === 'VERIFIED' && (
        <div className="success-banner">
          Vulnerability neutralized! View PR: 
          <a href={telemetry.pull_request_url ?? '#'}> {telemetry.pull_request_url}</a>
        </div>
      )}
    </div>
  );
};
```

By adhering to this architectural guide, the React application will remain performant, stateless, and mathematically sealed from the complexities of webhook signatures and background orchestration logic.
