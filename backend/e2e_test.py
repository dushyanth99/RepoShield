import os
import sys
import time
import uuid
import hmac
import hashlib
import requests
import subprocess
import json
import asyncio
from sqlalchemy import text

def print_step(msg):
    print(f"\n[+] {msg}")

def print_success(msg):
    print(f"  --> [OK] {msg}")

def abort(reason):
    print(f"\n[!] ABORT: {reason}")
    sys.exit(1)

def run_tests():
    # Phase 1: Environment & Persistence Verification
    print_step("Starting Uvicorn Server in background (port 8081)")
    server_process = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8081"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    time.sleep(3) # Wait for startup
    if server_process.poll() is not None:
        abort("Server failed to start.")

    base_url = "http://127.0.0.1:8081"
    
    try:
        # Phase 2: Authentication & Gateway Stress Test
        user_email = f"test_{uuid.uuid4().hex[:8]}@example.com"
        user_pass = "S3cur3P@ssw0rd!"
        
        print_step("Registering new user")
        reg_resp = requests.post(f"{base_url}/auth/register", json={
            "full_name": "QA Tester",
            "email": user_email,
            "password": user_pass
        })
        if reg_resp.status_code != 201:
            abort(f"Registration failed: {reg_resp.text}")
        print_success("User registered")

        print_step("Authenticating user")
        login_resp = requests.post(f"{base_url}/auth/login", json={
            "email": user_email,
            "password": user_pass
        })
        if login_resp.status_code != 200:
            abort(f"Login failed: {login_resp.text}")
        
        access_token = login_resp.json()["access_token"]
        user_id = login_resp.json()["user_id"]
        print_success("JWT extracted")

        print_step("Stress Testing /auth/login for Rate Limiter")
        for i in range(6):
            r = requests.post(f"{base_url}/auth/login", json={"email": user_email, "password": user_pass})
            if i == 5:
                if r.status_code != 429:
                    abort(f"Rate Limiter Failed! Expected 429 on 6th request, got {r.status_code}")
                else:
                    print_success("Rate Limiter correctly returned HTTP 429")

        # Phase 3: The Bifurcated Ingestion Test
        # Before hitting Route A, we need a repository. We will seed one via Python sqlite3 script
        print_step("Seeding Mock Repository in Database")
        
        async def seed_repo():
            import sys
            sys.path.append(os.getcwd())
            from config.database import AsyncSessionLocal
            from models.user import Repository
            async with AsyncSessionLocal() as session:
                repo_id_val = str(uuid.uuid4())
                repo = Repository(
                    id=repo_id_val,
                    user_id=user_id,
                    repo_name="octocat/Hello-World",
                    installation_id=123,
                    default_branch="master",
                    is_private=False,
                    github_repo_url="https://github.com/octocat/Hello-World"
                )
                session.add(repo)
                await session.commit()
                return repo_id_val
                
        repo_id = asyncio.run(seed_repo())
        print_success("Mock repository seeded")

        print_step("Testing Route A: POST /api/v1/jobs/scan/manual (JWT)")
        headers = {"Authorization": f"Bearer {access_token}"}
        scan_resp = requests.post(f"{base_url}/api/v1/jobs/scan/manual", json={
            "repository_id": repo_id,
            "test_command": "echo test"
        }, headers=headers)
        
        if scan_resp.status_code != 202:
            abort(f"Manual scan failed: {scan_resp.text}")
        job_id = scan_resp.json()["job_id"]
        print_success(f"Manual scan accepted, job_id: {job_id}")

        print_step("Testing Route B: POST /api/v1/webhooks/github (HMAC)")
        webhook_secret = os.environ.get("GITHUB_WEBHOOK_SECRET", "dummy_secret_for_local_dev")
        payload = json.dumps({"repository": {"html_url": "https://github.com/octocat/Hello-World"}}).encode("utf-8")
        signature_hash = hmac.new(webhook_secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()
        hmac_headers = {"X-Hub-Signature-256": f"sha256={signature_hash}", "Content-Type": "application/json"}
        
        wh_resp = requests.post(f"{base_url}/api/v1/jobs/webhooks/github", data=payload, headers=hmac_headers)
        if wh_resp.status_code != 202 and wh_resp.status_code != 200:
            abort(f"Webhook failed: {wh_resp.text}")
        print_success("Webhook accepted securely with HMAC")

        # Phase 4: Telemetry & Asynchronous Loop Verification
        print_step("Capturing Live Telemetry Stream (SSE)")
        # For SSE, stream=True
        stream_resp = requests.get(f"{base_url}/api/v1/jobs/{job_id}/stream", stream=True)
        if stream_resp.status_code != 200:
            abort(f"SSE endpoint failed: {stream_resp.status_code}")
            
        events_captured = 0
        for line in stream_resp.iter_lines():
            if line:
                decoded = line.decode('utf-8')
                if decoded.startswith("data: "):
                    events_captured += 1
                    data_json = json.loads(decoded[6:])
                    print_success(f"First event captured: {data_json}")
                    break
                    
        if events_captured == 0:
            abort("No events captured from SSE stream")

        print("\n==========================================")
        print("[*] FINAL VERDICT: GO FOR LAUNCH")
        print("==========================================")

    finally:
        print_step("Tearing down Uvicorn server")
        server_process.kill()
        server_process.wait()

if __name__ == "__main__":
    run_tests()
