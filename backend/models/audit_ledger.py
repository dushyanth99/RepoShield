"""
Audit Ledger model for RepoShield vulnerability jobs.

Each row represents a single scan/patch job executed by the self-healing
engine. CHAR(36) is used for all UUID columns because MySQL can index fixed-
width character columns more efficiently than variable-length VARCHAR.
"""

import enum
from typing import Optional

from sqlalchemy import (
    CHAR,
    Enum as SAEnum,
    Float,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column

from backend.config.database import Base


# ---------------------------------------------------------------------------
# Enum: patch lifecycle states
# ---------------------------------------------------------------------------
class PatchStatus(str, enum.Enum):
    PENDING = "PENDING"
    IN_PROGRESS = "IN_PROGRESS"
    PATCHED = "PATCHED"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------
class AuditLedger(Base):
    """
    Tracks every vulnerability scan / self-healing job.

    Columns
    -------
    id                      : CHAR(36) UUID primary key (MySQL-index friendly)
    user_id                 : CHAR(36) FK referencing the owning user
    target_file_path        : full repo-relative path of the scanned file
    business_risk_score     : 0.0–1.0 float produced by Model Armor
    patch_status            : lifecycle state of the patch attempt
    model_armor_blocked     : count of requests blocked by Model Armor
    self_healing_count      : count of automatic fix interventions applied
    pull_request_url        : nullable; set once a remediation PR is opened
    """

    __tablename__ = "audit_ledger"

    # Primary key
    id: Mapped[str] = mapped_column(
        CHAR(36),
        primary_key=True,
        nullable=False,
        comment="UUID v4 — CHAR(36) for optimal MySQL B-tree indexing",
    )

    # Foreign key to users table
    user_id: Mapped[str] = mapped_column(
        CHAR(36),
        nullable=False,
        index=True,
        comment="FK → users.id (CHAR 36)",
    )

    # Scan target
    target_file_path: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        comment="Repo-relative path of the file under analysis",
    )

    # Risk scoring
    business_risk_score: Mapped[float] = mapped_column(
        Float,
        nullable=False,
        default=0.0,
        comment="Normalised risk score [0.0, 1.0] from Model Armor",
    )

    # Patch lifecycle
    patch_status: Mapped[PatchStatus] = mapped_column(
        SAEnum(PatchStatus, name="patch_status_enum"),
        nullable=False,
        default=PatchStatus.PENDING,
        comment="Current state in the self-healing patch pipeline",
    )

    # Security counters
    model_armor_blocked: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        comment="Number of requests blocked by Model Armor for this job",
    )

    self_healing_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        comment="Number of automatic fix interventions applied",
    )

    # Remediation PR reference
    pull_request_url: Mapped[Optional[str]] = mapped_column(
        String(2048),
        nullable=True,
        default=None,
        comment="GitHub PR URL opened for this patch; NULL until PR is created",
    )

    def __repr__(self) -> str:
        return (
            f"<AuditLedger id={self.id!r} file={self.target_file_path!r} "
            f"status={self.patch_status!r} risk={self.business_risk_score}>"
        )
