"""
User and Repository models for RepoShield.

Relationship
------------
User  1 ──────< Repository  (one-to-many)

SQLAlchemy-level cascade="all, delete-orphan" plus the DB-level
ondelete="CASCADE" ensure that purging a User record atomically removes all
associated Repository rows — preventing orphaned data regardless of whether
the deletion is triggered from Python or directly via raw SQL.
"""

from typing import List, Optional

from sqlalchemy import CHAR, ForeignKey, String, Text, Boolean
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.config.database import Base


# ---------------------------------------------------------------------------
# User
# ---------------------------------------------------------------------------
class User(Base):
    """
    Represents an authenticated RepoShield user.

    Columns
    -------
    id          : CHAR(36) UUID primary key
    email       : unique login identifier
    full_name   : display name
    is_active   : soft-disable flag (default True)
    github_token: encrypted PAT used for PR operations (nullable)
    """

    __tablename__ = "users"

    id: Mapped[str] = mapped_column(
        CHAR(36),
        primary_key=True,
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
    # Relationship — cascade delete
    # cascade="all, delete-orphan" : ORM deletes child Repository rows when
    #                                 a User is deleted via the session.
    # passive_deletes=True          : lets the DB-level FK CASCADE handle
    #                                 deletions triggered outside the ORM.
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
    user_id         : CHAR(36) FK → users.id (CASCADE DELETE)
    github_repo_url : canonical HTTPS clone URL
    default_branch  : branch scanned by default (usually 'main')
    is_private      : mirrors GitHub visibility flag
    description     : optional repo description (nullable)
    """

    __tablename__ = "repositories"

    id: Mapped[str] = mapped_column(
        CHAR(36),
        primary_key=True,
        nullable=False,
        comment="UUID v4 — CHAR(36) for optimal MySQL B-tree indexing",
    )

    # FK with DB-level CASCADE DELETE so raw SQL deletions are also safe
    user_id: Mapped[str] = mapped_column(
        CHAR(36),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        comment="FK → users.id; CASCADE DELETE prevents orphaned repos",
    )

    github_repo_url: Mapped[str] = mapped_column(
        String(2048),
        nullable=False,
        comment="Canonical HTTPS URL of the GitHub repository",
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

    description: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
        default=None,
        comment="Optional repository description pulled from GitHub API",
    )

    # Back-reference to parent user
    owner: Mapped["User"] = relationship(
        "User",
        back_populates="repositories",
    )

    def __repr__(self) -> str:
        return (
            f"<Repository id={self.id!r} url={self.github_repo_url!r} "
            f"branch={self.default_branch!r}>"
        )
