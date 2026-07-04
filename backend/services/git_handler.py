"""
GitHub App authentication service — services/git_handler.py

Manages stateless, short-lived GitHub App authentication:
  1. Generate a 10-minute RS256 JWT signed with the App's RSA private key.
  2. Exchange the JWT for an ephemeral installation access token (≈1 h)
     scoped to a specific repository installation.

No long-lived PATs are ever used or stored.

Dependencies:
    pip install PyJWT[cryptography] requests

Configuration (via config/settings.py):
    GITHUB_APP_ID        — numeric App ID
    GITHUB_PRIVATE_KEY   — full PEM RSA private key (newlines as \\n in .env)

Formerly: services/github_app_auth.py
"""

import time
import logging
from typing import Optional

import jwt
import requests

from config.settings import settings

logger = logging.getLogger("reposhield.git_handler")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
GITHUB_API_BASE_URL:    str = "https://api.github.com"
JWT_ALGORITHM:          str = "RS256"
JWT_EXPIRY_SECONDS:     int = 10 * 60   # 10 minutes — GitHub maximum
JWT_CLOCK_SKEW_SECONDS: int = 60        # backdated to absorb clock drift


class GitHubAppAuthService:
    """
    Authenticates as a GitHub App using RS256-signed JWTs and exchanges
    them for short-lived installation access tokens.

    Usage
    -----
    >>> auth  = GitHubAppAuthService()
    >>> token = auth.get_installation_access_token(installation_id=12345678)
    >>> headers = {"Authorization": f"Bearer {token}"}
    """

    def __init__(self) -> None:
        """
        Reads credentials from the validated Pydantic settings singleton
        instead of calling os.getenv() directly.
        """
        self.app_id:         str = str(settings.github_app_id)
        self.private_key_pem: str = settings.github_private_key.replace("\\n", "\n")

    # -----------------------------------------------------------------------
    # Internal: JWT generation
    # -----------------------------------------------------------------------
    def _generate_app_jwt(self) -> str:
        """
        Sign and return a compact RS256 JWT for GitHub App API calls.

        Payload
        -------
        iss : App ID
        iat : now − 60 s  (absorbs clock drift)
        exp : now + 600 s (10-minute GitHub maximum)
        """
        now: int = int(time.time())
        payload: dict = {
            "iss": self.app_id,
            "iat": now - JWT_CLOCK_SKEW_SECONDS,
            "exp": now + JWT_EXPIRY_SECONDS,
        }
        token: str = jwt.encode(payload, self.private_key_pem, algorithm=JWT_ALGORITHM)
        logger.debug(f"Generated GitHub App JWT for App ID {self.app_id}.")
        return token

    # -----------------------------------------------------------------------
    # Public: exchange for installation access token
    # -----------------------------------------------------------------------
    def get_installation_access_token(self, installation_id: int) -> str:
        """
        POST to the GitHub installations endpoint and return the ephemeral
        access token scoped to the given installation.

        Args:
            installation_id: Numeric GitHub App installation ID for the target repo.

        Returns:
            Ephemeral installation access token string (e.g., "ghs_xxxxx…").

        Raises:
            RuntimeError:        On network timeouts or missing token field.
            requests.HTTPError:  On any non-2xx GitHub API response.
        """
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
        except requests.exceptions.Timeout:
            raise RuntimeError(
                f"GitHub API timed out after 15 s (installation_id={installation_id})."
            )
        except requests.exceptions.ConnectionError as exc:
            raise RuntimeError(f"Network error reaching GitHub API: {exc}") from exc

        try:
            response.raise_for_status()
        except requests.HTTPError:
            logger.error(
                f"GitHub API HTTP {response.status_code} for installation_id="
                f"{installation_id}: {response.text}"
            )
            raise requests.HTTPError(
                f"Failed to obtain installation access token "
                f"(HTTP {response.status_code}): {response.text}"
            )

        payload      = response.json()
        access_token: Optional[str] = payload.get("token")

        if not access_token:
            raise RuntimeError(
                f"GitHub API returned 200 but 'token' field is missing. "
                f"Full response: {payload}"
            )

        logger.info(
            f"Installation token obtained (installation_id={installation_id}), "
            f"expires={payload.get('expires_at')}."
        )
        return access_token
