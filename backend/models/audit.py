"""
Audit / VulnerabilityJob ORM model — models/audit.py

Tracks every vulnerability scan and autonomous remediation job produced
by the RepoShield pipeline.

Formerly: models/audit_ledger.py  (AuditLedger / PatchStatus)
Renamed to align with the canonical architectural blueprint.
"""

import enum
from typing import Optional

from sqlalchemy import (
    CHAR,
    Enum as SAEnum,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from config.database import Base


# ---------------------------------------------------------------------------
# Enum: patch lifecycle states
# ---------------------------------------------------------------------------
class PatchStatusEnum(str, enum.Enum):
    """Canonical lifecycle states for a vulnerability remediation job."""
    PENDING     = "PENDING"
    IN_PROGRESS = "IN_PROGRESS"
    PATCHED     = "PATCHED"
    FAILED      = "FAILED"
    SKIPPED     = "SKIPPED"


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------
class VulnerabilityJob(Base):
    """
    Persists the full audit trail for a single scan/patch execution.

    Columns
    -------
    id                   : CHAR(36) UUID primary key
    user_id              : CHAR(36) FK → users.id
    repository_id        : CHAR(36) nullable FK → repositories.id
    target_file_path     : repo-relative path of the scanned file
    business_risk_score  : normalised 0.0–1.0 risk score from Model Armor
    patch_status         : lifecycle state (PatchStatusEnum)
    model_armor_blocked  : count of commands blocked by Model Armor
    self_healing_count   : count of autonomous fix interventions applied
    pull_request_url     : nullable GitHub PR URL opened for this fix
    """

    __tablename__ = "vulnerability_jobs"

    # Primary key
    id: Mapped[str] = mapped_column(
        CHAR(36),
        primary_key=True,
        nullable=False,
        comment="UUID v4 — CHAR(36) for optimal MySQL B-tree indexing",
    )

    # Owner user
    user_id: Mapped[str] = mapped_column(
        CHAR(36),
        nullable=False,
        index=True,
        comment="FK → users.id (CHAR 36)",
    )

    # Parent repository (nullable so anonymous/CLI scans are also supported)
    repository_id: Mapped[Optional[str]] = mapped_column(
        CHAR(36),
        ForeignKey("repositories.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
        comment="FK → repositories.id; SET NULL on repo deletion",
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
        comment="Normalised risk score [0.0, 1.0] from Model Armor / static scan",
    )

    # Lifecycle state
    patch_status: Mapped[PatchStatusEnum] = mapped_column(
        SAEnum(PatchStatusEnum, name="patch_status_enum"),
        nullable=False,
        default=PatchStatusEnum.PENDING,
        comment="Current state in the self-healing patch pipeline",
    )

    # Security counters
    model_armor_blocked: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        comment="Commands blocked by Model Armor for this job",
    )
    self_healing_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        comment="Autonomous fix interventions applied during this job",
    )

    # Remediation PR
    pull_request_url: Mapped[Optional[str]] = mapped_column(
        String(2048),
        nullable=True,
        default=None,
        comment="GitHub PR URL for the remediation patch; NULL until PR is created",
    )

    # Relationship back to Repository (uncomment when Repository FK is active)
    # repository = relationship("Repository", back_populates="vulnerability_jobs")

    def __repr__(self) -> str:
        return (
            f"<VulnerabilityJob id={self.id!r} file={self.target_file_path!r} "
            f"status={self.patch_status!r} risk={self.business_risk_score}>"
        )
