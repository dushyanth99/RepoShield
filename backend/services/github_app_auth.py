"""
GitHub App Authentication Service for RepoShield.

Implements stateless, short-lived authentication for the GitHub App integration
using RS256-signed JWTs and ephemeral installation access tokens — eliminating
the need for long-lived personal access tokens (PATs).

Authentication Flow
-------------------
1. Generate a short-lived JWT (10 min) signed with the App's RSA private key.
2. Exchange the JWT for an even shorter-lived installation access token (1 hr)
   scoped to a specific repository installation.
3. Use the installation token exclusively when performing Git operations (PR creation).

Dependencies:
    pip install PyJWT[cryptography] requests

Environment Variables:
    GITHUB_APP_ID        : Numeric App ID from GitHub App settings.
    GITHUB_APP_PRIVATE_KEY : Full PEM-encoded RSA private key content.
"""

import os
import time
import logging
from typing import Optional

import jwt
import requests

logger = logging.getLogger("reposhield.github_app_auth")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
GITHUB_API_BASE_URL: str = "https://api.github.com"
JWT_ALGORITHM: str = "RS256"
JWT_EXPIRY_SECONDS: int = 10 * 60   # 10 minutes — GitHub maximum
JWT_ISSUED_AT_SKEW_SECONDS: int = 60 # Safety skew to absorb minor clock drift


class GitHubAppAuthService:
    """
    Manages GitHub App authentication by generating RS256-signed JWTs and
    exchanging them for ephemeral installation access tokens.

    Usage
    -----
    >>> auth = GitHubAppAuthService()
    >>> token = auth.get_installation_access_token(installation_id=12345678)
    >>> headers = {"Authorization": f"Bearer {token}"}
    """

    def __init__(
        self,
        app_id: Optional[str] = None,
        private_key_pem: Optional[str] = None,
    ) -> None:
        """
        Initialize the service using environment variables.

        Args:
            app_id: GitHub App numeric ID. Defaults to GITHUB_APP_ID env var.
            private_key_pem: Full PEM-encoded RSA private key string.
                             Defaults to GITHUB_APP_PRIVATE_KEY env var.

        Raises:
            EnvironmentError: If either the App ID or private key is missing.
        """
        self.app_id: str = app_id or os.environ.get("GITHUB_APP_ID", "")
        self.private_key_pem: str = private_key_pem or os.environ.get(
            "GITHUB_APP_PRIVATE_KEY", ""
        )

        if not self.app_id:
            raise EnvironmentError(
                "GITHUB_APP_ID is not set. Add it to your environment variables."
            )
        if not self.private_key_pem:
            raise EnvironmentError(
                "GITHUB_APP_PRIVATE_KEY is not set. Add the full PEM-encoded RSA "
                "private key to your environment variables."
            )

        # Normalise the key: env vars passed via shell sometimes strip newlines
        self.private_key_pem = self.private_key_pem.replace("\\n", "\n")

    # -----------------------------------------------------------------------
    # Internal: JWT Generation
    # -----------------------------------------------------------------------
    def _generate_app_jwt(self) -> str:
        """
        Generate an RS256-signed JSON Web Token for GitHub App authentication.

        The payload follows GitHub's documented JWT requirements:
          - `iss` : App ID identifying the issuing GitHub App.
          - `iat` : Issued-at time, slightly backdated by 60 s to absorb clock
                    drift between the issuing machine and GitHub's servers.
          - `exp` : Expiry set to exactly 10 minutes from issuance.

        Returns:
            A compact, URL-safe RS256 JWT string.

        Raises:
            jwt.exceptions.PyJWTError: If signing fails due to a malformed key.
        """
        now: int = int(time.time())

        payload: dict = {
            "iss": self.app_id,
            "iat": now - JWT_ISSUED_AT_SKEW_SECONDS,
            "exp": now + JWT_EXPIRY_SECONDS,
        }

        token: str = jwt.encode(
            payload=payload,
            key=self.private_key_pem,
            algorithm=JWT_ALGORITHM,
        )

        logger.debug(
            f"Generated GitHub App JWT for App ID {self.app_id}. "
            f"Expires at epoch {payload['exp']}."
        )
        return token

    # -----------------------------------------------------------------------
    # Public: Installation Access Token Exchange
    # -----------------------------------------------------------------------
    def get_installation_access_token(self, installation_id: int) -> str:
        """
        Exchange a short-lived App JWT for an ephemeral installation access token.

        The returned token is scoped to the given installation and is valid for
        approximately 1 hour. It should be cached and reused for that window —
        never persisted to disk or a database.

        Args:
            installation_id: The numeric GitHub App installation ID for the
                             target repository.

        Returns:
            Ephemeral installation access token string (e.g., "ghs_xxxxx...").

        Raises:
            requests.HTTPError: On any non-2xx response from the GitHub API,
                                with the full error body forwarded.
            RuntimeError: If the API response is missing the expected token field.
        """
        app_jwt: str = self._generate_app_jwt()

        url: str = (
            f"{GITHUB_API_BASE_URL}/app/installations/{installation_id}/access_tokens"
        )
        headers: dict = {
            "Authorization": f"Bearer {app_jwt}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

        logger.info(
            f"Requesting installation access token for installation ID {installation_id}."
        )

        try:
            response = requests.post(url, headers=headers, timeout=15)
        except requests.exceptions.Timeout:
            raise RuntimeError(
                f"GitHub API request timed out after 15 s while fetching installation "
                f"access token for installation ID {installation_id}."
            )
        except requests.exceptions.ConnectionError as conn_err:
            raise RuntimeError(
                f"Network connectivity error reaching GitHub API: {conn_err}"
            )

        # Aggressively raise on any HTTP error (4xx / 5xx)
        try:
            response.raise_for_status()
        except requests.HTTPError as http_err:
            logger.error(
                f"GitHub API returned HTTP {response.status_code} for installation "
                f"ID {installation_id}. Response body: {response.text}"
            )
            raise requests.HTTPError(
                f"Failed to obtain GitHub installation access token "
                f"(HTTP {response.status_code}): {response.text}"
            ) from http_err

        payload: dict = response.json()
        access_token: Optional[str] = payload.get("token")

        if not access_token:
            raise RuntimeError(
                f"GitHub API responded with HTTP 200 but the 'token' field is missing "
                f"in the response payload. Full response: {payload}"
            )

        logger.info(
            f"Installation access token obtained for installation ID {installation_id}. "
            f"Expires at: {payload.get('expires_at', 'unknown')}."
        )
        return access_token
