from __future__ import annotations

from datetime import datetime
from typing import Literal, Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.user_settings import EncryptionSetupSchema


class ChangePasswordStartRequest(BaseModel):
    backup_key_acknowledged: bool = Field(
        ...,
        description=(
            "Must be True. The wizard's first step gates the next on "
            "this checkbox so the user explicitly opts into the "
            "irreversible rotation."
        ),
    )
    new_kek_version: int = Field(
        ...,
        ge=1,
        description=(
            "Monotonically incrementing version stamp the client will "
            "embed in every re-encrypted note's ``encryption_metadata``. "
            "Computed client-side as ``current + 1``; the server stores "
            "it on the rotation session for the recovery banner."
        ),
    )

    model_config = ConfigDict(extra="forbid")


class ChangePasswordStartResponse(BaseModel):
    rotation_id: UUID
    encrypted_note_count: int
    estimated_seconds: int
    new_kek_version: int
    expires_at: datetime = Field(
        ...,
        description=(
            "Rotation session TTL — 1h. After expiry the client must "
            "restart the wizard."
        ),
    )


class ChangePasswordDryRunRequest(BaseModel):
    rotation_id: UUID
    sample_notes_tested: int = Field(..., ge=0, le=50)
    sample_notes_succeeded: int = Field(..., ge=0, le=50)
    errors: list[str] = Field(
        default_factory=list,
        max_length=50,
        description=(
            "Truncated error messages from failed sample re-encrypts. "
            "Each entry is at most 200 chars — the UI shows them in "
            "an expandable details section."
        ),
    )

    model_config = ConfigDict(extra="forbid")


class ChangePasswordDryRunResponse(BaseModel):
    rotation_id: UUID
    sample_notes_tested: int
    sample_notes_succeeded: int
    can_proceed: bool


class ChangePasswordCommitRequest(BaseModel):
    rotation_id: UUID
    notes_total: int = Field(..., ge=0)
    notes_re_encrypted: int = Field(..., ge=0)
    notes_failed: int = Field(..., ge=0)
    duration_seconds: float = Field(..., ge=0)
    new_encryption_setup: Optional[EncryptionSetupSchema] = Field(
        default=None,
        description=(
            "Rotated unlock material (salt + wrappedDek + dekIv) the "
            "client built after a successful batch-reencrypt. When "
            "present the server persists it onto "
            "``user_preferences.encryption_setup`` inside the same DB "
            "transaction as the commit audit log entry — closing the "
            "split-brain window where the DB carried new wrapped DEKs "
            "but the setup still pointed at the pre-rotation KEK."
        ),
    )

    model_config = ConfigDict(extra="forbid")


class ChangePasswordCommitResponse(BaseModel):
    rotation_id: UUID
    notes_total: int
    notes_re_encrypted: int
    notes_failed: int
    completed_at: datetime
    new_kek_version: int


class ChangePasswordRecoveryResponse(BaseModel):
    in_flight: bool
    rotation_id: Optional[UUID] = None
    started_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    new_kek_version: Optional[int] = None
    phase: Optional[Literal["started", "dry-run", "phase1", "phase2"]] = None


class ChangePasswordRateLimitedResponse(BaseModel):
    code: Literal["encryption_change_password_rate_limited"] = (
        "encryption_change_password_rate_limited"
    )
    message: str
    retry_after_seconds: int = Field(
        ...,
        ge=0,
        description=(
            "Seconds until the rate limit window expires. The UI "
            "surfaces it as a relative duration (`in 17h`)."
        ),
    )


class ChangePasswordSessionMissingResponse(BaseModel):
    code: Literal["encryption_change_password_session_missing"] = (
        "encryption_change_password_session_missing"
    )
    message: str


class ChangePasswordReconcileBatchRequest(BaseModel):
    rotation_id: UUID
    expected_new_salt: str = Field(
        ...,
        min_length=20,
        max_length=32,
        description=(
            "Base64 salt the wizard already pushed to the server "
            "during ``batch-reencrypt``. Notes whose persisted salt "
            "matches are reported as ``already_done``; the rest go "
            "into ``pending`` for re-firing."
        ),
    )
    note_ids: list[UUID] = Field(
        ...,
        min_length=1,
        max_length=500,
        description=(
            "Subset of note ids the wizard intended to rotate in the "
            "chunk. The reconciler scopes the SELECT to the current "
            "user's notes only — passing notes the user does not own "
            "is a silent skip (the row simply does not appear in "
            "``already_done`` or ``pending``)."
        ),
    )

    model_config = ConfigDict(extra="forbid")


class ChangePasswordReconcileBatchResponse(BaseModel):
    rotation_id: UUID
    already_done: list[UUID]
    pending: list[UUID]
