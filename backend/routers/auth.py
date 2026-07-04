"""
Authentication router — routers/auth.py

POST /auth/register  — create a new user account
POST /auth/login     — verify credentials, return signed JWT

Uses:
  - Passlib bcrypt (cost=12) for password hashing
  - PyJWT HS256 for access token signing
  - Async SQLAlchemy 2.0 for all DB operations
  - Pydantic V2 for strict request validation
"""

import uuid
import logging
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr, Field, field_validator
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from config.database import get_db
from config.security import hash_password, verify_password, create_access_token
from models.user import User

logger = logging.getLogger("reposhield.auth")

router = APIRouter(prefix="/auth", tags=["Authentication"])


# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------

class RegisterRequest(BaseModel):
    full_name: str      = Field(..., min_length=2, max_length=255,
                               examples=["Alice Nguyen"])
    email:     EmailStr = Field(..., examples=["alice@example.com"])
    password:  str      = Field(..., min_length=8, max_length=128,
                               examples=["S3cur3P@ssw0rd!"])

    @field_validator("password")
    @classmethod
    def password_complexity(cls, v: str) -> str:
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
        "email":     "alice@example.com",
        "password":  "S3cur3P@ssw0rd!",
    }}}


class RegisterResponse(BaseModel):
    user_id: str
    email:   str
    message: str


class LoginRequest(BaseModel):
    email:    EmailStr = Field(..., examples=["alice@example.com"])
    password: str      = Field(..., min_length=1, max_length=128,
                               examples=["S3cur3P@ssw0rd!"])

    model_config = {"json_schema_extra": {"example": {
        "email":    "alice@example.com",
        "password": "S3cur3P@ssw0rd!",
    }}}


class LoginResponse(BaseModel):
    access_token: str
    token_type:   str = "bearer"
    user_id:      str
    email:        str


# ---------------------------------------------------------------------------
# POST /auth/register
# ---------------------------------------------------------------------------

@router.post(
    "/register",
    response_model=RegisterResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user account",
)
async def register(
    body: RegisterRequest,
    db:   Annotated[AsyncSession, Depends(get_db)],
) -> RegisterResponse:
    # 1. Email uniqueness check
    result = await db.execute(select(User).where(User.email == body.email))
    if result.scalar_one_or_none() is not None:
        logger.warning(f"Register conflict: email already exists — {body.email}")
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"An account with email '{body.email}' already exists.",
        )

    # 2. Hash password + generate UUID
    new_id:  str = str(uuid.uuid4())
    hashed:  str = hash_password(body.password)

    # 3. Persist new User
    new_user = User(
        id=new_id,
        email=body.email,
        full_name=body.full_name,
        hashed_password=hashed,
        is_active=True,
    )
    db.add(new_user)

    try:
        await db.flush()
        await db.commit()
        logger.info(f"User registered: id={new_id} email={body.email}")
    except Exception as exc:
        await db.rollback()
        logger.error(f"Failed to create user {body.email}: {exc}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Account creation failed. Please try again.",
        ) from exc

    return RegisterResponse(
        user_id=new_id,
        email=body.email,
        message="Account created successfully. You can now log in.",
    )


# ---------------------------------------------------------------------------
# POST /auth/login
# ---------------------------------------------------------------------------

@router.post(
    "/login",
    response_model=LoginResponse,
    status_code=status.HTTP_200_OK,
    summary="Authenticate and obtain a JWT access token",
)
async def login(
    body: LoginRequest,
    db:   Annotated[AsyncSession, Depends(get_db)],
) -> LoginResponse:
    # 1. Lookup by email — return generic 401 to prevent user enumeration
    result = await db.execute(select(User).where(User.email == body.email))
    user: User | None = result.scalar_one_or_none()

    if user is None:
        logger.warning(f"Login: non-existent email attempted — {body.email}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # 2. Constant-time password verification
    if not verify_password(body.password, user.hashed_password):
        logger.warning(f"Login: wrong password for {body.email}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # 3. Reject deactivated accounts
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This account has been deactivated. Please contact support.",
        )

    # 4. Issue JWT
    token: str = create_access_token(user_id=user.id, email=user.email)
    logger.info(f"Successful login: user_id={user.id}")

    return LoginResponse(
        access_token=token,
        token_type="bearer",
        user_id=user.id,
        email=user.email,
    )
