"""
Centralised settings — config/settings.py

Single source of truth for every environment variable the RepoShield
backend requires. Validated at startup by Pydantic V2 BaseSettings so
a missing or malformed variable fails fast with a clear error message
before the server accepts any traffic.

Dependencies:
    pip install pydantic-settings
"""

from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Pydantic V2 settings model.
    All fields map to environment variables via their `alias`.
    Required fields (no default) raise ValidationError on startup if absent.
    """

    # Runtime environment
    env: Literal["development", "staging", "production"] = Field(
        default="development",
        alias="ENV",
        description="Runtime environment tier.",
    )

    # -----------------------------------------------------------------------
    # Database
    # -----------------------------------------------------------------------
    database_url: str = Field(
        ...,
        alias="DATABASE_URL",
        description="Full async SQLAlchemy connection string. "
                    "Example: mysql+aiomysql://user:pass@localhost:3306/reposhield",
    )

    # -----------------------------------------------------------------------
    # Security / JWT
    # -----------------------------------------------------------------------
    jwt_secret_key: str = Field(
        ...,
        alias="JWT_SECRET_KEY",
        description="Strong random secret used to sign HS256 access tokens. "
                    "Minimum 32 characters recommended.",
    )
    jwt_algorithm: str = Field(
        default="HS256",
        alias="JWT_ALGORITHM",
        description="JWT signing algorithm.",
    )
    jwt_expiry_hours: int = Field(
        default=24,
        alias="JWT_EXPIRY_HOURS",
        description="Access token validity window in hours.",
    )

    # -----------------------------------------------------------------------
    # Google Cloud — Model Armor
    # -----------------------------------------------------------------------
    model_armor_project_location: str = Field(
        ...,
        alias="MODEL_ARMOR_PROJECT_LOCATION",
        description="GCP project/location for Model Armor. "
                    "Example: projects/my-project/locations/us-central1",
    )

    # -----------------------------------------------------------------------
    # GitHub App
    # -----------------------------------------------------------------------
    github_app_id: int = Field(
        ...,
        alias="GITHUB_APP_ID",
        description="Numeric GitHub App ID from the App settings page.",
    )
    github_private_key: str = Field(
        ...,
        alias="GITHUB_PRIVATE_KEY",
        description="Full PEM-encoded RSA private key for the GitHub App. "
                    "Newlines may be escaped as \\n in .env files.",
    )

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",          # silently ignore any extra env vars
        populate_by_name=True,   # allow field name OR alias to populate the field
    )


# Module-level singleton — import this everywhere instead of os.getenv()
settings = Settings()
