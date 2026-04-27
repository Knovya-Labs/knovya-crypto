from __future__ import annotations

import logging
from typing import Optional
from uuid import UUID

from sqlalchemy import delete, func, select
from sqlalchemy.exc import IntegrityError

from app.core.enums import NoteSharePermission
from app.core.exceptions import NoteEncryptedException, NoteNotFoundException
from app.models.notes.note import Note
from app.models.notes.version import NoteVersion
from app.services.notes.base_service import NoteBaseService
from app.services.notes.diff_utils import calculate_diff, generate_unified_diff
from app.services.notes.markdown_utils import md_to_text

logger = logging.getLogger(__name__)

MAX_VERSIONS_PER_NOTE = 50
MAX_LIST_LIMIT = 200
DEFAULT_LIST_LIMIT = 20


class VersionService(NoteBaseService):

    def __init__(self, db, workspace_id: int, user_id: int, *, agent_name: str | None = None):
        super().__init__(db, workspace_id, user_id)
        self._agent_name = agent_name

    async def create_snapshot(
        self,
        note_id: UUID,
        snapshot_type: str = "manual",
        _retry: int = 0,
        *,
        change_kind: str | None = None,
        changed_block_ids: list[str] | None = None,
    ) -> NoteVersion:
        from app.core.enums import ChangeKind
        from app.core.timeouts import PROVENANCE_CHANGED_BLOCKS_MAX

        note = await self._get_note_for_snapshot(note_id)

        last_version = (await self._db.execute(
            select(func.coalesce(func.max(NoteVersion.version_number), 0))
            .where(NoteVersion.note_id == note_id)
        )).scalar()
        new_version_number = last_version + 1

        prev_content = (await self._db.execute(
            select(NoteVersion.content_md)
            .where(NoteVersion.note_id == note_id)
            .order_by(NoteVersion.version_number.desc())
            .limit(1)
        )).scalar()

        diff_result = calculate_diff(prev_content or "", note.content_md or "")

        if (
            snapshot_type == "auto"
            and prev_content is not None
            and diff_result["lines_added"] == 0
            and diff_result["lines_removed"] == 0
        ):
            return None

        effective_type = snapshot_type
        if self._agent_name and snapshot_type == "manual":
            effective_type = f"agent:{self._agent_name}"

        if change_kind is None:
            if snapshot_type == "initial":
                change_kind = (
                    ChangeKind.AGENT_WRITE if self._agent_name
                    else ChangeKind.HUMAN_EDIT
                )
            elif self._agent_name:
                change_kind = ChangeKind.AGENT_EDIT
            else:
                change_kind = ChangeKind.HUMAN_EDIT

        meta_payload = dict(note.meta or {})
        if changed_block_ids:
            truncated = list(changed_block_ids)[:PROVENANCE_CHANGED_BLOCKS_MAX]
            provenance_meta = dict(meta_payload.get("_provenance") or {})
            provenance_meta["changed_block_ids"] = truncated
            provenance_meta["truncated"] = (
                len(changed_block_ids) > PROVENANCE_CHANGED_BLOCKS_MAX
            )
            meta_payload["_provenance"] = provenance_meta

        version = NoteVersion(
            workspace_id=self._workspace_id,
            note_id=note_id,
            version_number=new_version_number,
            title=note.title,
            content_md=note.content_md or "",
            meta=meta_payload,
            snapshot_type=effective_type,
            created_by=self._user_id,
            lines_added=diff_result["lines_added"],
            lines_removed=diff_result["lines_removed"],
            agent_name=self._agent_name,
            change_kind=str(change_kind) if change_kind is not None else None,
            is_encrypted=bool(note.is_encrypted),
            encryption_metadata=(
                dict(note.encryption_metadata)
                if note.is_encrypted and note.encryption_metadata
                else None
            ),
        )
        self._db.add(version)
        try:
            await self._db.flush()
        except IntegrityError:
            await self._db.rollback()
            if _retry < 1:
                return await self.create_snapshot(
                    note_id,
                    snapshot_type,
                    _retry=_retry + 1,
                    change_kind=change_kind,
                    changed_block_ids=changed_block_ids,
                )
            logger.warning("Duplicate version_number race for note %s after retry", note_id)
            return None

        await self._cleanup_if_needed(note_id)
        return version

    async def list(
        self,
        note_id: UUID,
        *,
        limit: int = DEFAULT_LIST_LIMIT,
        offset: int = 0,
    ) -> dict:
        await self._check_note_access(note_id, NoteSharePermission.VIEWER)

        limit = min(max(limit, 1), MAX_LIST_LIMIT)
        offset = max(offset, 0)

        base = select(NoteVersion).where(NoteVersion.note_id == note_id)

        count_stmt = select(func.count()).select_from(base.subquery())
        total = (await self._db.execute(count_stmt)).scalar_one()

        items_stmt = (
            base
            .order_by(NoteVersion.version_number.desc())
            .limit(limit)
            .offset(offset)
        )
        versions = (await self._db.execute(items_stmt)).scalars().all()

        user_ids = list({v.created_by for v in versions if v.created_by is not None})
        user_names: dict[int, str] = {}
        if user_ids:
            from app.models.user import User
            u_stmt = select(User.id, User.name).where(User.id.in_(user_ids))
            u_result = await self._db.execute(u_stmt)
            user_names = {r.id: (r.name or "").strip() for r in u_result.all()}

        items = []
        for v in versions:
            name = user_names.get(v.created_by) if v.created_by else None
            agent_name = v.agent_name
            if not agent_name and v.snapshot_type and v.snapshot_type.startswith("agent:"):
                agent_name = v.snapshot_type.split(":", 1)[1]
            if agent_name and not name:
                name = agent_name
            d = {
                "id": v.id,
                "note_id": v.note_id,
                "version_number": v.version_number,
                "title": v.title,
                "snapshot_type": v.snapshot_type,
                "meta": v.meta or {},
                "created_by": v.created_by,
                "created_by_name": name,
                "change_summary": None,
                "lines_added": v.lines_added,
                "lines_removed": v.lines_removed,
                "created_at": v.created_at,
                "agent_name": agent_name,
                "change_kind": v.change_kind,
            }
            items.append(d)

        return {
            "items": items,
            "total": total,
            "has_more": (offset + limit) < total,
        }

    async def get(self, note_id: UUID, version_id: UUID) -> NoteVersion:
        await self._check_note_access(note_id, NoteSharePermission.VIEWER)
        return await self._get_version(note_id, version_id)

    async def find_id_by_version_number(
        self, note_id: UUID, version_number: int,
    ) -> UUID | None:
        stmt = select(NoteVersion.id).where(
            NoteVersion.note_id == note_id,
            NoteVersion.version_number == version_number,
        )
        return (await self._db.execute(stmt)).scalar()

    async def get_diff(self, note_id: UUID, version_id: UUID) -> dict:
        await self._check_note_access(note_id, NoteSharePermission.VIEWER)

        current_version = await self._get_version(note_id, version_id)

        prev_stmt = (
            select(NoteVersion.content_md)
            .where(
                NoteVersion.note_id == note_id,
                NoteVersion.version_number < current_version.version_number,
            )
            .order_by(NoteVersion.version_number.desc())
            .limit(1)
        )
        prev_content = (await self._db.execute(prev_stmt)).scalar()

        diff_text = generate_unified_diff(
            prev_content or "",
            current_version.content_md or "",
            old_label=f"v{current_version.version_number - 1}",
            new_label=f"v{current_version.version_number}",
        )
        diff_stats = calculate_diff(prev_content or "", current_version.content_md or "")

        return {
            "version_number": current_version.version_number,
            "diff": diff_text,
            "lines_added": diff_stats["lines_added"],
            "lines_removed": diff_stats["lines_removed"],
        }

    async def get_diff_between(
        self, note_id: UUID, version_id_a: UUID, version_id_b: UUID,
    ) -> dict:
        await self._check_note_access(note_id, NoteSharePermission.VIEWER)

        version_a = await self._get_version(note_id, version_id_a)
        version_b = await self._get_version(note_id, version_id_b)

        a, b = version_a, version_b
        if a.version_number > b.version_number:
            a, b = b, a

        diff_text = generate_unified_diff(
            a.content_md or "", b.content_md or "",
            old_label=f"v{a.version_number}", new_label=f"v{b.version_number}",
        )
        diff_stats = calculate_diff(a.content_md or "", b.content_md or "")

        return {
            "from_version": a.version_number,
            "to_version": b.version_number,
            "diff": diff_text,
            "lines_added": diff_stats["lines_added"],
            "lines_removed": diff_stats["lines_removed"],
        }

    async def get_diff_with_current(self, note_id: UUID, version_id: UUID) -> dict:
        note = await self._check_note_access(note_id, NoteSharePermission.VIEWER)
        version = await self._get_version(note_id, version_id)

        diff_text = generate_unified_diff(
            version.content_md or "", note.content_md or "",
            old_label=f"v{version.version_number}", new_label="current",
        )
        diff_stats = calculate_diff(version.content_md or "", note.content_md or "")

        return {
            "version_number": version.version_number,
            "diff": diff_text,
            "lines_added": diff_stats["lines_added"],
            "lines_removed": diff_stats["lines_removed"],
        }

    async def restore(self, note_id: UUID, version_id: UUID) -> tuple[Note, int]:
        from app.services.notes.markdown_utils import count_checklists

        note = await self._check_note_access(note_id, NoteSharePermission.EDITOR)
        version = await self._get_version(note_id, version_id)

        from app.core.enums import ChangeKind

        live_encrypted = bool(note.is_encrypted)
        snap_encrypted = bool(getattr(version, "is_encrypted", False))

        if live_encrypted and not snap_encrypted:
            raise NoteEncryptedException(
                message=(
                    "Encrypted not pre-encryption snapshot'a restore "
                    "edilemez. Önce notu decrypt edin."
                ),
            )
        if snap_encrypted and not live_encrypted:
            raise NoteEncryptedException(
                message=(
                    "Plaintext not encrypted snapshot'a restore "
                    "edilemez. Önce notu yeniden şifreleyin."
                ),
            )

        note.title = version.title

        if live_encrypted and snap_encrypted:
            note.content_md = version.content_md
            note.encryption_metadata = (
                dict(version.encryption_metadata)
                if version.encryption_metadata
                else note.encryption_metadata
            )
            note.content_text = ""
            note.checklist_total = 0
            note.checklist_done = 0
        else:
            note.content_md = version.content_md
            note.content_text = md_to_text(version.content_md)
            note.checklist_total, note.checklist_done = count_checklists(version.content_md)

        note.version = note.version + 1
        await self._db.flush()

        await self.create_snapshot(
            note_id,
            snapshot_type="manual",
            change_kind=ChangeKind.RESTORE,
        )
        return note, version.version_number

    async def cleanup_old_versions(self, note_id: UUID) -> int:
        count_stmt = (
            select(func.count(NoteVersion.id))
            .where(NoteVersion.note_id == note_id)
        )
        total = (await self._db.execute(count_stmt)).scalar()

        if total <= MAX_VERSIONS_PER_NOTE:
            return 0

        excess = total - MAX_VERSIONS_PER_NOTE
        oldest_stmt = (
            select(NoteVersion.id)
            .where(NoteVersion.note_id == note_id)
            .order_by(NoteVersion.version_number.asc())
            .limit(excess)
        )
        oldest_ids = (await self._db.execute(oldest_stmt)).scalars().all()

        if oldest_ids:
            await self._db.execute(
                delete(NoteVersion).where(NoteVersion.id.in_(oldest_ids))
            )

        return len(oldest_ids)


    async def _get_version(self, note_id: UUID, version_id: UUID) -> NoteVersion:
        stmt = select(NoteVersion).where(
            NoteVersion.id == version_id,
            NoteVersion.note_id == note_id,
        )
        result = await self._db.execute(stmt)
        version = result.scalar_one_or_none()
        if version is None:
            raise NoteNotFoundException(
                message="Versiyon bulunamadı", note_id=version_id,
            )
        return version

    async def _get_note_for_snapshot(self, note_id: UUID) -> Note:
        if self._user_id == 0:
            stmt = select(Note).where(
                Note.id == note_id,
                Note.workspace_id == self._workspace_id,
            )
            result = await self._db.execute(stmt)
            note = result.scalar_one_or_none()
            if note is None:
                raise NoteNotFoundException(note_id=note_id)
            return note
        return await self._check_note_access(note_id, NoteSharePermission.VIEWER)

    async def _cleanup_if_needed(self, note_id: UUID) -> None:
        count = (await self._db.execute(
            select(func.count(NoteVersion.id))
            .where(NoteVersion.note_id == note_id)
        )).scalar()
        if count > MAX_VERSIONS_PER_NOTE:
            await self.cleanup_old_versions(note_id)
