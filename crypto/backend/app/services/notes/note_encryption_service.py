from __future__ import annotations

import logging
from typing import TYPE_CHECKING
from uuid import UUID

from sqlalchemy import delete, select

from app.core.enums import NoteSharePermission, PlanTier
from app.core.exceptions import (
    NoteLockedException,
    NoteVersionConflictException,
)

if TYPE_CHECKING:
    from app.services.notes.note_service import NoteService

logger = logging.getLogger(__name__)


class NoteEncryptionService:

    def __init__(self, note_service: NoteService):
        self._svc = note_service
        self._db = note_service._db
        self._workspace_id = note_service._workspace_id
        self._user_id = note_service._user_id

    async def encrypt_note(
        self,
        note_id: UUID,
        encrypted_content_md: str,
        encryption_metadata: dict,
        version: int,
    ):
        from app.core.exceptions import NoteEncryptedException, PlanLimitException
        from app.models.workspace import Workspace

        ws_result = await self._db.execute(
            select(Workspace.plan).where(Workspace.id == self._workspace_id),
        )
        ws_plan = ws_result.scalar() or PlanTier.FREE
        if ws_plan == PlanTier.FREE:
            raise PlanLimitException(
                resource="encryption",
                limit=0,
                plan="free",
                upgrade_hint="Upgrade to Pro to use E2E encryption.",
            )

        note = await self._svc._check_note_access(note_id, NoteSharePermission.EDITOR)

        if note.is_encrypted:
            raise NoteEncryptedException(message="Bu not zaten şifreli")

        if note.is_locked and (self._svc._agent_name or note.locked_by != self._user_id):
            raise NoteLockedException(locked_by=note.locked_by)

        if version != note.version:
            raise NoteVersionConflictException(
                server_version=note.version, your_version=version,
            )

        note.content_md = encrypted_content_md
        note.content_json = []
        note.content_text = ""
        note.search_vector = None
        note.is_encrypted = True
        note.encryption_metadata = encryption_metadata
        note.embedding = None
        note.embedding_updated_at = None
        note.content_hash = None
        note.checklist_total = 0
        note.checklist_done = 0
        note.version = note.version + 1

        await self._db.flush()

        await self._delete_plaintext_versions(note_id)

        await self._svc._activity.log(note_id, "encrypted")
        await self._svc._invalidate_note_caches(note_id)

        self._svc._queue_feed("note_updated", {
            "note_id": str(note_id),
            "version": note.version,
            "user_id": self._user_id,
        })

        try:
            await self._delete_note_chunks(note_id)
        except Exception as exc:
            logger.warning("Chunk cleanup after encrypt failed for %s: %s", note_id, exc)

        return note

    async def decrypt_note(
        self,
        note_id: UUID,
        content_md: str,
        content_json: list | None,
        version: int,
    ):
        from app.core.exceptions import NoteNotEncryptedException
        from app.services.notes.note_service import (
            _strip_title_from_content,
            _sync_content_formats,
        )

        note = await self._svc._check_note_access(note_id, NoteSharePermission.EDITOR)

        if not note.is_encrypted:
            raise NoteNotEncryptedException()

        if note.is_locked and (self._svc._agent_name or note.locked_by != self._user_id):
            raise NoteLockedException(locked_by=note.locked_by)

        if version != note.version:
            raise NoteVersionConflictException(
                server_version=note.version, your_version=version,
            )

        note.content_md = content_md
        note.content_json = content_json
        note.is_encrypted = False
        note.encryption_metadata = None

        has_md = bool(content_md)
        has_json = bool(content_json)
        _strip_title_from_content(note)
        _sync_content_formats(note, content_md_changed=has_md, content_json_changed=has_json)

        note.version = note.version + 1
        await self._db.flush()

        if note.content_json:
            await self._svc._sync_mention_links(note)

        await self._svc._activity.log(note_id, "decrypted")
        await self._svc._invalidate_note_caches(note_id)

        self._svc._queue_feed("note_updated", {
            "note_id": str(note_id),
            "version": note.version,
            "user_id": self._user_id,
        })

        await self._svc._schedule_embedding(note_id)
        await self._svc._schedule_inference(note_id)

        return note

    async def reencrypt_note(
        self,
        note_id: UUID,
        encrypted_content_md: str,
        encryption_metadata: dict,
        version: int,
    ):
        from app.core.exceptions import NoteNotEncryptedException

        note = await self._svc._check_note_access(note_id, NoteSharePermission.EDITOR)

        if not note.is_encrypted:
            raise NoteNotEncryptedException()

        if note.is_locked and (self._svc._agent_name or note.locked_by != self._user_id):
            raise NoteLockedException(locked_by=note.locked_by)

        if version != note.version:
            raise NoteVersionConflictException(
                server_version=note.version, your_version=version,
            )

        note.content_md = encrypted_content_md
        note.encryption_metadata = encryption_metadata
        note.version = note.version + 1
        await self._db.flush()

        await self._svc._activity.log(note_id, "reencrypted")
        await self._svc._invalidate_note_caches(note_id)

        return note

    async def batch_reencrypt_note(
        self,
        note_id: UUID,
        encryption_metadata: dict,
        version: int,
    ) -> None:
        from app.core.exceptions import NoteNotEncryptedException

        note = await self._svc._check_note_access(note_id, NoteSharePermission.EDITOR)

        if not note.is_encrypted:
            raise NoteNotEncryptedException()

        if version != note.version:
            raise NoteVersionConflictException(
                server_version=note.version, your_version=version,
            )

        note.encryption_metadata = encryption_metadata
        note.version = note.version + 1
        await self._db.flush()

        await self._svc._invalidate_note_caches(note_id)

    async def _delete_plaintext_versions(self, note_id: UUID) -> None:
        from app.models.notes.version import NoteVersion
        await self._db.execute(
            delete(NoteVersion).where(NoteVersion.note_id == note_id)
        )

    async def _delete_note_chunks(self, note_id: UUID) -> None:
        from app.models.notes.note_chunk import NoteChunk
        await self._db.execute(
            delete(NoteChunk).where(NoteChunk.note_id == note_id)
        )
