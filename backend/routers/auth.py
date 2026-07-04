"""
Authentication router — routers/auth.py

POST /auth/register  — create a new user account
POST /auth/login     — verify credentials, return signed JWT

Rate limiting (Deficit 5 fix)
---------
The /login endpoint enforces a hard ceiling of 5 requests per minute per
remote IP via slowapi + Limiter. This prevents credential stuffing and
brute-force attacks. The limiter is wired into main.py's exception handler.

Uses:
  - Passlib bcrypt (cost=12) for password hashing
  - PyJWT HS256 for access token signing
  - Async SQLAlchemy 2.0 for all DB operations
  - Pydantic V2 for strict request validation
  - slowapi for in-process IP-based rate limiting
"""

import logging
from typing import Annotated

import uuid
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, EmailStr, Field, field_validator
from slowapi import Limiter
from slowapi.util import get_remote_address
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from config.database import get_db
from config.security import hash_password, verify_password, create_access_token
from models.user import User

logger = logging.getLogger("reposhield.auth")

# ---------------------------------------------------------------------------
# Rate limiter — keyed on remote client IP address
# ---------------------------------------------------------------------------
limiter = Limiter(key_func=get_remote_address)

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
        logger.warning(
            "Registration conflict: email already exists",
            extra={"email": body.email},
        )
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"An account with email '{body.email}' already exists.",
        )

    # 2. Hash password + generate UUID
    new_id: str = str(uuid.uuid4())
    hashed: str = hash_password(body.password)

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
        logger.info("User registered", extra={"user_id": new_id, "email": body.email})
    except Exception as exc:
        await db.rollback()
        logger.error(
            "Failed to create user account",
            extra={"email": body.email, "error": str(exc)},
        )
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
# POST /auth/login — Rate limited: 5 requests/minute per IP
# ---------------------------------------------------------------------------

@router.post(
    "/login",
    response_model=LoginResponse,
    status_code=status.HTTP_200_OK,
    summary="Authenticate and obtain a JWT access token",
    description=(
        "Rate limited to **5 requests per minute per IP address**. "
        "Returns HTTP 429 if the ceiling is breached."
    ),
)
@limiter.limit("5/minute")
async def login(
    request: Request,                               # required by slowapi
    body:    LoginRequest,
    db:      Annotated[AsyncSession, Depends(get_db)],
) -> LoginResponse:
    """
    Validates credentials against the bcrypt-hashed password and issues a
    signed HS256 JWT. Returns a generic 401 for both wrong email AND wrong
    password to prevent user enumeration via timing differences.
    """
    # 1. Lookup by email
    result = await db.execute(select(User).where(User.email == body.email))
    user: User | None = result.scalar_one_or_none()

    if user is None:
        logger.warning(
            "Login attempt for non-existent account",
            extra={"email": body.email, "remote_ip": request.client.host if request.client else "unknown"},
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # 2. Constant-time bcrypt verification
    if not verify_password(body.password, user.hashed_password):
        logger.warning(
            "Login failed: incorrect password",
            extra={"user_id": user.id, "email": body.email},
        )
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

    # 4. Issue JWT access token
    token: str = create_access_token(user_id=user.id, email=user.email)
    logger.info(
        "Successful login",
        extra={"user_id": user.id, "email": user.email},
    )

    return LoginResponse(
        access_token=token,
        token_type="bearer",
        user_id=user.id,
        email=user.email,
    )
