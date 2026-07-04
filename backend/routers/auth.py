"""
Authentication router — routers/auth.py

Exposes two public endpoints:
  POST /auth/register — create a new user account
  POST /auth/login    — verify credentials and issue a JWT access token

All database operations use async SQLAlchemy 2.0 patterns.
Passwords are stored as bcrypt hashes; plain-text passwords never touch
the database layer.
"""

import uuid
import logging
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr, Field, field_validator
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from backend.config.database import get_db
from backend.config.security import hash_password, verify_password, create_access_token
from backend.models.user_repository import User

logger = logging.getLogger("reposhield.auth")

router = APIRouter(prefix="/auth", tags=["Authentication"])


# ---------------------------------------------------------------------------
# Pydantic Request / Response Schemas
# ---------------------------------------------------------------------------

class RegisterRequest(BaseModel):
    """Strict validation schema for the /register endpoint."""

    full_name: str = Field(
        ...,
        min_length=2,
        max_length=255,
        description="Display name of the user.",
        examples=["Alice Nguyen"],
    )
    email: EmailStr = Field(
        ...,
        description="Valid email address used as the login identifier.",
        examples=["alice@example.com"],
    )
    password: str = Field(
        ...,
        min_length=8,
        max_length=128,
        description="Plain-text password (minimum 8 characters). Stored as bcrypt hash.",
        examples=["S3cur3P@ssw0rd!"],
    )

    @field_validator("password")
    @classmethod
    def password_complexity(cls, v: str) -> str:
        """Enforce at least one uppercase letter, one digit, and one special character."""
        has_upper   = any(c.isupper() for c in v)
        has_digit   = any(c.isdigit() for c in v)
        has_special = any(c in "!@#$%^&*()-_=+[]{}|;:',.<>?/`~" for c in v)
        if not (has_upper and has_digit and has_special):
            raise ValueError(
                "Password must contain at least one uppercase letter, "
                "one digit, and one special character."
            )
        return v

    model_config = {"json_schema_extra": {"example": {
        "full_name": "Alice Nguyen",
        "email": "alice@example.com",
        "password": "S3cur3P@ssw0rd!",
    }}}


class RegisterResponse(BaseModel):
    """Minimal response returned after successful registration."""

    user_id: str = Field(..., description="UUID of the newly created user account.")
    email:   str = Field(..., description="Email address of the registered account.")
    message: str = Field(..., description="Human-readable confirmation message.")


class LoginRequest(BaseModel):
    """Strict validation schema for the /login endpoint."""

    email: EmailStr = Field(
        ...,
        description="Registered email address.",
        examples=["alice@example.com"],
    )
    password: str = Field(
        ...,
        min_length=1,
        max_length=128,
        description="Plain-text password to verify against the stored hash.",
        examples=["S3cur3P@ssw0rd!"],
    )

    model_config = {"json_schema_extra": {"example": {
        "email": "alice@example.com",
        "password": "S3cur3P@ssw0rd!",
    }}}


class LoginResponse(BaseModel):
    """Token payload returned on successful authentication."""

    access_token: str  = Field(..., description="Signed JWT access token. Valid for 24 hours.")
    token_type:   str  = Field(default="bearer", description="OAuth2 token type.")
    user_id:      str  = Field(..., description="UUID of the authenticated user.")
    email:        str  = Field(..., description="Email address of the authenticated user.")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post(
    "/register",
    response_model=RegisterResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user account",
    description=(
        "Validates the request body, checks for email uniqueness, "
        "hashes the password with bcrypt (cost=12), persists the new User record, "
        "and returns the generated UUID."
    ),
)
async def register(
    body: RegisterRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> RegisterResponse:
    """
    POST /auth/register

    1. Check whether the email already exists (409 Conflict if so).
    2. Hash the plain-text password with bcrypt.
    3. Generate a UUID v4 for the new user.
    4. Insert the User row and flush to the database.
    5. Return the new user's UUID and email.
    """
    # 1. Uniqueness check — async SELECT
    stmt = select(User).where(User.email == body.email)
    result = await db.execute(stmt)
    existing_user: User | None = result.scalar_one_or_none()

    if existing_user is not None:
        logger.warning(f"Registration attempt with already-registered email: {body.email}")
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"An account with the email '{body.email}' already exists.",
        )

    # 2. Hash password
    hashed: str = hash_password(body.password)

    # 3. Generate UUID
    new_id: str = str(uuid.uuid4())

    # 4. Persist new user
    new_user = User(
        id=new_id,
        email=body.email,
        full_name=body.full_name,
        hashed_password=hashed,
        is_active=True,
    )
    db.add(new_user)

    try:
        await db.flush()   # write to DB within the current transaction
        await db.commit()
        logger.info(f"New user registered: id={new_id} email={body.email}")
    except Exception as exc:
        await db.rollback()
        logger.error(f"Failed to persist new user {body.email}: {exc}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Account creation failed due to a database error. Please try again.",
        ) from exc

    # 5. Return UUID
    return RegisterResponse(
        user_id=new_id,
        email=body.email,
        message="Account created successfully. You can now log in.",
    )


@router.post(
    "/login",
    response_model=LoginResponse,
    status_code=status.HTTP_200_OK,
    summary="Authenticate and obtain a JWT access token",
    description=(
        "Looks up the user by email, verifies the supplied password against "
        "the stored bcrypt hash, and returns a signed 24-hour JWT access token."
    ),
)
async def login(
    body: LoginRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> LoginResponse:
    """
    POST /auth/login

    1. Fetch the User record by email (404 → generic 401 to avoid user enumeration).
    2. Run constant-time bcrypt verification.
    3. Reject inactive accounts.
    4. Issue and return a signed JWT access token.
    """
    # 1. Look up user — deliberately return 401 (not 404) to prevent enumeration
    stmt = select(User).where(User.email == body.email)
    result = await db.execute(stmt)
    user: User | None = result.scalar_one_or_none()

    if user is None:
        logger.warning(f"Login attempt for non-existent email: {body.email}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # 2. Constant-time password verification
    if not verify_password(body.password, user.hashed_password):
        logger.warning(f"Failed login attempt (wrong password) for: {body.email}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # 3. Reject disabled accounts
    if not user.is_active:
        logger.warning(f"Login attempt by deactivated account: {body.email}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This account has been deactivated. Please contact support.",
        )

    # 4. Issue JWT access token
    token: str = create_access_token(user_id=user.id, email=user.email)
    logger.info(f"Successful login: user_id={user.id} email={user.email}")

    return LoginResponse(
        access_token=token,
        token_type="bearer",
        user_id=user.id,
        email=user.email,
    )
