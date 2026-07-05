"""
GitHub App authentication and PR manager — services/git_handler.py

Manages stateless, short-lived GitHub App authentication:
  1. Generate a 10-minute RS256 JWT signed with the App's RSA private key.
  2. Exchange the JWT for an ephemeral installation access token (≈1 h)
     scoped to a specific repository installation.
  3. Provides methods to create branch, commit remediation code, and open PRs.

No long-lived PATs are ever used or stored.

Dependencies:
    pip install PyJWT[cryptography] requests PyGithub
"""

import time
import logging
import uuid
import asyncio
import requests
from typing import Optional, Any

import jwt
from config.settings import settings

logger = logging.getLogger("reposhield.git_handler")

GITHUB_API_BASE_URL:    str = "https://api.github.com"
JWT_ALGORITHM:          str = "RS256"
JWT_EXPIRY_SECONDS:     int = 10 * 60
JWT_CLOCK_SKEW_SECONDS: int = 60

class GitHubAppManager:
    """
    Manages GitHub App lifecycle operations: authentication, token exchange,
    branch creation, file commits, and opening remediation Pull Requests.
    """
    def __init__(self) -> None:
        self.app_id: str = str(settings.github_app_id)
        self.private_key_pem: str = settings.github_private_key.replace("\\n", "\n")

    def _generate_app_jwt(self) -> str:
        now: int = int(time.time())
        payload: dict = {
            "iss": self.app_id,
            "iat": now - JWT_CLOCK_SKEW_SECONDS,
            "exp": now + JWT_EXPIRY_SECONDS,
        }
        token: str = jwt.encode(payload, self.private_key_pem, algorithm=JWT_ALGORITHM)
        logger.debug(f"Generated GitHub App JWT for App ID {self.app_id}.")
        return token

    def get_installation_access_token(self, installation_id: int) -> str:
        app_jwt = self._generate_app_jwt()
        url = f"{GITHUB_API_BASE_URL}/app/installations/{installation_id}/access_tokens"
        headers = {
            "Authorization":        f"Bearer {app_jwt}",
            "Accept":               "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

        logger.info(f"Requesting installation access token for installation_id={installation_id}.")
        try:
            response = requests.post(url, headers=headers, timeout=15)
            response.raise_for_status()
        except Exception as exc:
            logger.error(f"Failed to obtain installation access token: {exc}")
            raise

        payload = response.json()
        access_token: Optional[str] = payload.get("token")
        if not access_token:
            raise RuntimeError("GitHub API returned 200 but token is missing.")
        return access_token

    async def create_remediation_pr(
        self,
        repo_url: str,
        file_path: str,
        patched_code: str,
        base_branch: str = "main",
        installation_id: Optional[int] = None
    ) -> str:
        """
        Creates a branch, commits the patched code, and opens a Pull Request on GitHub.
        Runs blocking PyGithub operations inside a thread pool using asyncio.to_thread.
        """
        repo_name = repo_url.replace("https://github.com/", "").replace(".git", "")
        if repo_name.endswith("/"):
            repo_name = repo_name[:-1]
        if not installation_id:
            try:
                # Auto-discover first available installation ID if not specified
                installations_url = f"{GITHUB_API_BASE_URL}/app/installations"
                jwt_token = self._generate_app_jwt()
                headers = {
                    "Authorization": f"Bearer {jwt_token}",
                    "Accept": "application/vnd.github+json",
                    "X-GitHub-Api-Version": "2022-11-28",
                }
                res = requests.get(installations_url, headers=headers, timeout=10)
                res.raise_for_status()
                for inst in res.json():
                    installation_id = inst["id"]
                    break
            except Exception as e:
                logger.error(f"Auto-discovery of GitHub App Installation ID failed: {e}")
                raise RuntimeError("No GitHub installation_id provided or discovered.")

        token = self.get_installation_access_token(installation_id)

        def _run_github_ops() -> str:
            from github import Github
            g = Github(token)
            repo = g.get_repo(repo_name)
            
            # Create a unique branch
            branch_name = f"reposhield/patch-{uuid.uuid4().hex[:8]}"
            sb = repo.get_branch(base_branch)
            repo.create_git_ref(ref=f"refs/heads/{branch_name}", sha=sb.commit.sha)
            
            # Get existing file to update or create it
            try:
                contents = repo.get_contents(file_path, ref=branch_name)
                file_sha = contents.sha
                repo.update_file(
                    path=file_path,
                    message="🔒 RepoShield: remediate security vulnerability",
                    content=patched_code,
                    sha=file_sha,
                    branch=branch_name
                )
            except Exception:
                repo.create_file(
                    path=file_path,
                    message="🔒 RepoShield: create file for security remediation",
                    content=patched_code,
                    branch=branch_name
                )
                
            # Create pull request
            pr = repo.create_pull(
                title="🔒 RepoShield: Autonomous Security Patch",
                body="Autonomous security patch generated by RepoShield DevSecOps Agent.",
                head=branch_name,
                base=base_branch
            )
            return pr.html_url

        return await asyncio.to_thread(_run_github_ops)

# Alias for backwards compatibility with any existing imports
GitHubAppAuthService = GitHubAppManager
