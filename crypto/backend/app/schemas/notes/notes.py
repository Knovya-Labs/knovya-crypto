from datetime import datetime
from typing import Any, Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.schemas.notes.tags import TagResponse


class NoteCreate(BaseModel):
    title: str = Field(..., min_length=1, max_length=500)
    content_md: str = Field(default="")
    content_json: Optional[list[dict[str, Any]]] = None
    folder_id: Optional[UUID] = None
    tags: list[str] = Field(default_factory=list)
    source_module: Optional[str] = Field(None, max_length=50)
    source_context: Optional[str] = Field(None, max_length=255)
    source_agent: Optional[str] = Field(None, max_length=100)
    source: Optional[str] = Field(None, max_length=30)
    source_url: Optional[str] = None
    metadata: Optional[dict[str, Any]] = None
    is_encrypted: bool = False
    encryption_metadata: Optional[dict[str, Any]] = None

    @field_validator("encryption_metadata")
    @classmethod
    def check_create_metadata(cls, v: Optional[dict[str, Any]], info) -> Optional[dict[str, Any]]:
        if v is not None:
            return _validate_encryption_metadata(v)
        return v


class NoteUpdate(BaseModel):
    title: Optional[str] = Field(None, min_length=1, max_length=500)
    content_md: Optional[str] = None
    content_json: Optional[list[dict[str, Any]]] = None
    folder_id: Optional[UUID] = None
    version: int = Field(..., ge=1)
    metadata: Optional[dict[str, Any]] = None
    tags: Optional[list[str]] = None
    encryption_metadata: Optional[dict[str, Any]] = None
    is_suggestion_apply: bool = Field(
        default=False,
        exclude=True,
        description=(
            "When ``True`` the snapshot produced by this update is "
            "classified as ``ChangeKind.SUGGESTION_APPLY`` via "
            "``NoteService._detect_change_kind``. Excluded from "
            "``model_dump`` so it never reaches the SQL UPDATE payload."
        ),
    )
    mutation_id: Optional[UUID] = Field(
        default=None,
        exclude=True,
        description=(
            "Client-generated UUID v4 for Stripe-style idempotent "
            "retries. The offline mutation queue replays POSTs with "
            "the same id after network recovery; the backend caches "
            "the response under "
            "``notes:mutation:{user_id}:{mutation_id}`` for 24h so a "
            "duplicate replay returns the cached result without "
            "re-applying the update. Excluded from ``model_dump`` so "
            "it never reaches the SQL UPDATE payload."
        ),
    )


class QuickNoteCreate(BaseModel):
    title: str = Field(..., min_length=1, max_length=500)
    content_md: str = Field(default="")
    content_json: Optional[list[dict[str, Any]]] = None
    folder_id: Optional[UUID] = None
    folder_path: Optional[str] = Field(None, max_length=200, description="Folder path like 'Quick Notes' — auto-creates if missing")
    tags: list[str] = Field(default_factory=list)
    source_module: Optional[str] = Field(None, max_length=50)
    source_context: Optional[str] = Field(None, max_length=255)
    source_agent: Optional[str] = Field(None, max_length=100)


class NoteTagAdd(BaseModel):
    name: str = Field(..., min_length=1, max_length=50)


class NoteMoveRequest(BaseModel):
    folder_id: Optional[UUID] = None




class NoteResponse(BaseModel):
    id: UUID
    title: str
    content_md: str
    content_json: Optional[list[dict[str, Any]]] = None
    status: str
    is_pinned: bool
    is_favorited: bool
    is_locked: bool
    locked_by: Optional[UUID] = None
    version: int
    folder_id: Optional[UUID] = None
    folder_name: Optional[str] = None
    checklist_total: int
    checklist_done: int
    source_module: Optional[str] = None
    source_context: Optional[str] = None
    source_agent: Optional[str] = None
    source: Optional[str] = None
    source_url: Optional[str] = None
    language: str = "turkish"
    meta: dict[str, Any] = Field(default_factory=dict)
    attachment_count: int = 0
    is_shared: bool = False
    is_encrypted: bool = False
    encryption_metadata: Optional[dict[str, Any]] = None
    last_editor_id: Optional[UUID] = None
    last_editor_name: Optional[str] = None
    link_count: int = 0
    backlink_count: int = 0
    snapshot_count: int = 0
    noterank: Optional[float] = None
    tags: list[TagResponse] = Field(default_factory=list)
    effective_permission: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class NoteRankSignalReason(BaseModel):
    key: str
    value: float
    label_key: str


class NoteRankSignals(BaseModel):
    score: float = 0.0
    top_reasons: list[NoteRankSignalReason] = Field(default_factory=list)
    staleness_days: Optional[float] = None
    is_stale: bool = False


class NoteListItemResponse(BaseModel):
    id: UUID
    title: str
    preview: str = ""
    status: str
    is_pinned: bool
    is_favorited: bool
    is_locked: bool
    locked_by: Optional[UUID] = None
    version: int
    folder_id: Optional[UUID] = None
    folder_name: Optional[str] = None
    checklist_total: int
    checklist_done: int
    source_module: Optional[str] = None
    source_context: Optional[str] = None
    source_agent: Optional[str] = None
    meta: dict[str, Any] = Field(default_factory=dict)
    attachment_count: int = 0
    is_shared: bool = False
    is_encrypted: bool = False
    last_editor_id: Optional[UUID] = None
    last_editor_name: Optional[str] = None
    backlink_count: int = 0
    noterank_signals: Optional[NoteRankSignals] = None
    tags: list[TagResponse] = Field(default_factory=list)
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class NoteListResponse(BaseModel):
    items: list[NoteListItemResponse]
    total: int
    has_more: bool


class ArchiveStats(BaseModel):
    completed: int = 0
    precedent: int = 0
    by_type: dict[str, int] = Field(default_factory=dict)
    by_outcome: dict[str, int] = Field(default_factory=dict)


class SectionCountsResponse(BaseModel):
    all: int = 0
    pinned: int = 0
    favorites: int = 0
    encrypted: int = 0
    shared: int = 0
    archive: int = 0
    trash: int = 0
    ai_workspace: int = 0
    jsx: int = 0
    archive_stats: Optional[ArchiveStats] = None


class StorageUsageResponse(BaseModel):
    used_bytes: int = 0
    quota_bytes: int = 0


_ENCRYPTION_META_REQUIRED = {"v", "alg", "kdf", "iter", "hash", "salt", "iv", "wrappedDek", "dekIv"}
_MIN_PBKDF2_ITERATIONS = 600_000
_ALLOWED_ENCRYPTION_VERSIONS = (1, 2, 3)
_ALLOWED_HASH = "SHA-256"
_ALLOWED_ALG = "AES-256-GCM"
_ALLOWED_KDF = "PBKDF2"


def _validate_encryption_metadata(v: dict[str, Any]) -> dict[str, Any]:
    missing = _ENCRYPTION_META_REQUIRED - v.keys()
    if missing:
        raise ValueError(f"Missing required fields: {missing}")
    if v["alg"] != _ALLOWED_ALG:
        raise ValueError("Unsupported algorithm")
    if v["kdf"] != _ALLOWED_KDF:
        raise ValueError("Unsupported KDF")
    if v["hash"] != _ALLOWED_HASH:
        raise ValueError("Unsupported hash")
    if not isinstance(v["v"], int) or v["v"] not in _ALLOWED_ENCRYPTION_VERSIONS:
        raise ValueError(
            f"Encryption version must be one of {_ALLOWED_ENCRYPTION_VERSIONS}"
        )
    if not isinstance(v["iter"], int) or v["iter"] < _MIN_PBKDF2_ITERATIONS:
        raise ValueError(f"Iteration count must be >= {_MIN_PBKDF2_ITERATIONS}")
    return v


class NoteEncryptRequest(BaseModel):
    encrypted_content_md: str = Field(
        ..., min_length=1,
        description="Base64-encoded AES-256-GCM ciphertext of the note content",
    )
    encryption_metadata: dict[str, Any] = Field(
        ...,
        description="Crypto params: {v, alg, kdf, iter, hash, salt, iv, wrappedDek, dekIv}",
    )
    version: int = Field(..., ge=1)

    @field_validator("encryption_metadata")
    @classmethod
    def check_metadata(cls, v: dict[str, Any]) -> dict[str, Any]:
        return _validate_encryption_metadata(v)


class NoteDecryptRequest(BaseModel):
    content_md: str = Field(
        ..., min_length=1,
        description="Decrypted plaintext markdown content",
    )
    content_json: Optional[list[dict[str, Any]]] = None
    version: int = Field(..., ge=1)


class NoteReEncryptRequest(BaseModel):
    encrypted_content_md: str = Field(
        ..., min_length=1,
        description="Re-encrypted ciphertext with new key",
    )
    encryption_metadata: dict[str, Any] = Field(
        ...,
        description="New crypto params for the re-encrypted content",
    )
    version: int = Field(..., ge=1)

    @field_validator("encryption_metadata")
    @classmethod
    def check_metadata(cls, v: dict[str, Any]) -> dict[str, Any]:
        return _validate_encryption_metadata(v)


class BatchReEncryptItem(BaseModel):
    note_id: UUID
    encryption_metadata: dict[str, Any] = Field(...)
    version: int = Field(..., ge=1)

    @field_validator("encryption_metadata")
    @classmethod
    def check_metadata(cls, v: dict[str, Any]) -> dict[str, Any]:
        return _validate_encryption_metadata(v)


class BatchReEncryptRequest(BaseModel):
    items: list[BatchReEncryptItem] = Field(
        ..., min_length=1, max_length=500,
        description="Notes to re-encrypt in a single atomic transaction",
    )


class BatchReEncryptResponse(BaseModel):
    success: bool
    updated_count: int
    updated_note_ids: list[str]


class ArchiveEnrichmentRequest(BaseModel):
    enrichment: Optional[dict[str, Any]] = None


class EnrichmentSuggestion(BaseModel):
    field: str
    current: Optional[str] = None
    suggested: Optional[str] = None
    confidence: float = 0.0
    reason: str = ""
    source: str = ""


class ArchiveWarning(BaseModel):
    type: str
    message: str
    dependent_notes: list[dict[str, str]] = Field(default_factory=list)


class ArchiveImpact(BaseModel):
    will_gain_maturity_boost: bool = False
    will_enable_experience_matching: bool = False
    estimated_precedent_value: str = "low"


class PreArchiveAnalysisResponse(BaseModel):
    note_id: UUID
    ready_to_archive: bool = True
    enrichment_suggestions: list[EnrichmentSuggestion] = Field(default_factory=list)
    warnings: list[ArchiveWarning] = Field(default_factory=list)
    archive_impact: ArchiveImpact = Field(default_factory=ArchiveImpact)
