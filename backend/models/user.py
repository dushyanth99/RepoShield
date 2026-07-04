"""
User and Repository ORM models — models/user.py

User  1 ──────< Repository  (one-to-many, cascade delete)
Repository 1 ──────< VulnerabilityJob  (relationship ready, commented-in below)

Formerly: models/user_repository.py
"""

import uuid
from typing import List, Optional

from sqlalchemy import Boolean, CHAR, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from config.database import Base


def generate_uuid() -> str:
    return str(uuid.uuid4())


# ---------------------------------------------------------------------------
# User
# ---------------------------------------------------------------------------
class User(Base):
    """
    Authenticated RepoShield user account.

    Columns
    -------
    id              : CHAR(36) UUID primary key
    email           : unique login identifier (RFC-5321 max 320 chars)
    full_name       : display name
    hashed_password : bcrypt hash (cost=12) — plain-text never stored
    is_active       : soft-disable flag
    github_token    : encrypted GitHub PAT for PR creation (nullable)
    """

    __tablename__ = "users"

    id: Mapped[str] = mapped_column(
        CHAR(36),
        primary_key=True,
        default=generate_uuid,
        nullable=False,
        comment="UUID v4 — CHAR(36) for optimal MySQL B-tree indexing",
    )
    email: Mapped[str] = mapped_column(
        String(320),
        unique=True,
        nullable=False,
        index=True,
        comment="RFC-5321 max email length; used as login identifier",
    )
    full_name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        comment="Display name shown in the UI",
    )
    hashed_password: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        comment="bcrypt hash (cost=12) of the user's password. Never store plain-text.",
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        comment="Soft-disable flag; False blocks login without deleting data",
    )
    github_token: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
        default=None,
        comment="Encrypted GitHub PAT for PR creation; NULL if not connected",
    )

    # -----------------------------------------------------------------------
    # One-to-many: User → Repository
    # cascade="all, delete-orphan" : ORM deletes child Repository rows on User delete
    # passive_deletes=True         : lets DB-level FK CASCADE handle external deletions
    # -----------------------------------------------------------------------
    repositories: Mapped[List["Repository"]] = relationship(
        "Repository",
        back_populates="owner",
        cascade="all, delete-orphan",
        passive_deletes=True,
        lazy="selectin",
    )

    def __repr__(self) -> str:
        return f"<User id={self.id!r} email={self.email!r} active={self.is_active}>"


# ---------------------------------------------------------------------------
# Repository
# ---------------------------------------------------------------------------
class Repository(Base):
    """
    A GitHub repository connected to a RepoShield user account.

    Columns
    -------
    id              : CHAR(36) UUID primary key
    user_id         : CHAR(36) FK → users.id  (CASCADE DELETE)
    repo_name       : GitHub repository name  (e.g., "octocat/Hello-World")
    installation_id : numeric GitHub App installation ID for this repo
    default_branch  : branch scanned by default
    is_private      : mirrors GitHub visibility flag
    github_repo_url : canonical HTTPS clone URL
    description     : optional repo description (nullable)
    """

    __tablename__ = "repositories"

    id: Mapped[str] = mapped_column(
        CHAR(36),
        primary_key=True,
        default=generate_uuid,
        nullable=False,
        comment="UUID v4 — CHAR(36) for optimal MySQL B-tree indexing",
    )
    user_id: Mapped[str] = mapped_column(
        CHAR(36),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        comment="FK → users.id; CASCADE DELETE prevents orphaned repos",
    )
    repo_name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        comment="GitHub repository name, e.g. 'owner/repo'",
    )
    installation_id: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        comment="Numeric GitHub App installation ID for this repository",
    )
    default_branch: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        default="main",
        comment="Branch targeted by RepoShield scans",
    )
    is_private: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        comment="Mirrors GitHub repo visibility; affects token requirements",
    )
    github_repo_url: Mapped[str] = mapped_column(
        String(2048),
        nullable=False,
        default="",
        comment="Canonical HTTPS URL of the GitHub repository",
    )
    description: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
        default=None,
        comment="Optional repository description pulled from GitHub API",
    )

    # Back-reference to owning user
    owner: Mapped["User"] = relationship(
        "User",
        back_populates="repositories",
    )

    # Relationship to VulnerabilityJob — activate when audit FK is ready
    vulnerability_jobs: Mapped[List["VulnerabilityJob"]] = relationship(  # type: ignore[name-defined]
        "VulnerabilityJob",
        back_populates="repository",
        cascade="all, delete-orphan",
        passive_deletes=True,
        lazy="selectin",
    )

    def __repr__(self) -> str:
        return (
            f"<Repository id={self.id!r} name={self.repo_name!r} "
            f"branch={self.default_branch!r}>"
        )
