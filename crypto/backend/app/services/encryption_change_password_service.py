from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional
from uuid import UUID, uuid4

from fastapi import HTTPException, Request, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession


class EncryptionRateLimitedError(RuntimeError):

    def __init__(self, retry_after_seconds: int) -> None:
        super().__init__(
            f"Encryption rotation rate limited; "
            f"retry after {retry_after_seconds}s"
        )
        self.retry_after_seconds = retry_after_seconds


class EncryptionSessionMissingError(RuntimeError):

    def __init__(self, rotation_id: UUID) -> None:
        super().__init__(f"Rotation session missing: {rotation_id}")
        self.rotation_id = rotation_id

from app.core.config import settings
from app.core.redis_manager import get_redis
from app.models.notes.note import Note
from app.models.user_preferences import UserPreferences
from app.schemas.encryption_change_password import (
    ChangePasswordCommitRequest,
    ChangePasswordCommitResponse,
    ChangePasswordDryRunRequest,
    ChangePasswordDryRunResponse,
    ChangePasswordReconcileBatchRequest,
    ChangePasswordReconcileBatchResponse,
    ChangePasswordRecoveryResponse,
    ChangePasswordStartRequest,
    ChangePasswordStartResponse,
)
from app.services.user_activity_log_service import UserActivityLogService

logger = logging.getLogger(__name__)


RATE_LIMIT_WINDOW_SECONDS = 24 * 3600
RATE_LIMIT_MAX = 1

ROTATION_SESSION_TTL_SECONDS = 3600

ESTIMATED_SECONDS_PER_NOTE = 0.05


def _rotation_session_key(user_id: UUID, rotation_id: UUID) -> str:
    return f"encryption:rotation:{user_id}:{rotation_id}"


def _rotation_user_index_key(user_id: UUID) -> str:
    return f"encryption:rotation:user:{user_id}"


def _rate_limit_key(user_id: UUID) -> str:
    return f"encryption:rate:{user_id}"


class EncryptionChangePasswordService:

    def __init__(self, db: AsyncSession, user_id: UUID):
        self._db = db
        self._user_id = user_id


    async def start_rotation(
        self,
        body: ChangePasswordStartRequest,
        request: Request,
    ) -> ChangePasswordStartResponse:
        if not settings.ENCRYPTION_CHANGE_PASSWORD_ENABLED:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                "Encryption password change is currently disabled",
            )

        if not body.backup_key_acknowledged:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                "Backup key acknowledgment is required",
            )

        retry_after = await self._check_rate_limit()
        if retry_after > 0:
            raise EncryptionRateLimitedError(retry_after)

        encrypted_note_count = await self._count_encrypted_notes()

        rotation_id = uuid4()
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(seconds=ROTATION_SESSION_TTL_SECONDS)

        session_state = {
            "rotation_id": str(rotation_id),
            "user_id": str(self._user_id),
            "new_kek_version": body.new_kek_version,
            "started_at": now.isoformat(),
            "expires_at": expires_at.isoformat(),
            "phase": "started",
            "encrypted_note_count": encrypted_note_count,
        }

        await self._persist_session(rotation_id, session_state)

        await self._bump_rate_limit()

        await UserActivityLogService(self._db, self._user_id).log_event(
            "encryption_kek_rotation_started",
            action_detail={
                "rotation_id": str(rotation_id),
                "encrypted_note_count": encrypted_note_count,
                "new_kek_version": body.new_kek_version,
            },
            request=request,
        )
        await self._db.commit()

        logger.info(
            "Encryption rotation started user=%s rotation_id=%s notes=%d",
            self._user_id,
            rotation_id,
            encrypted_note_count,
        )

        return ChangePasswordStartResponse(
            rotation_id=rotation_id,
            encrypted_note_count=encrypted_note_count,
            estimated_seconds=int(
                encrypted_note_count * ESTIMATED_SECONDS_PER_NOTE
            ),
            new_kek_version=body.new_kek_version,
            expires_at=expires_at,
        )


    async def record_dry_run(
        self,
        body: ChangePasswordDryRunRequest,
        request: Request,
    ) -> ChangePasswordDryRunResponse:
        session = await self._load_session(body.rotation_id)
        await self._mark_phase(body.rotation_id, session, "dry-run")

        can_proceed = (
            body.sample_notes_tested > 0
            and body.sample_notes_succeeded == body.sample_notes_tested
            and len(body.errors) == 0
        )

        await UserActivityLogService(self._db, self._user_id).log_event(
            "encryption_kek_rotation_dry_run",
            action_detail={
                "rotation_id": str(body.rotation_id),
                "sample_notes_tested": body.sample_notes_tested,
                "sample_notes_succeeded": body.sample_notes_succeeded,
                "errors_count": len(body.errors),
                "can_proceed": can_proceed,
            },
            request=request,
        )
        await self._db.commit()

        logger.info(
            "Encryption rotation dry-run user=%s rotation_id=%s tested=%d "
            "succeeded=%d can_proceed=%s",
            self._user_id,
            body.rotation_id,
            body.sample_notes_tested,
            body.sample_notes_succeeded,
            can_proceed,
        )

        return ChangePasswordDryRunResponse(
            rotation_id=body.rotation_id,
            sample_notes_tested=body.sample_notes_tested,
            sample_notes_succeeded=body.sample_notes_succeeded,
            can_proceed=can_proceed,
        )


    async def commit_rotation(
        self,
        body: ChangePasswordCommitRequest,
        request: Request,
    ) -> ChangePasswordCommitResponse:
        session = await self._load_session(body.rotation_id)

        if body.notes_re_encrypted < 0 or body.notes_total < 0:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                "Negative note counts are not allowed",
            )

        await self._mark_phase(body.rotation_id, session, "phase2")

        completed_at = datetime.now(timezone.utc)

        if body.new_encryption_setup is not None:
            setup_blob = body.new_encryption_setup.model_dump(
                mode="json", exclude_none=True,
            )
            await self._persist_encryption_setup(setup_blob)

        await UserActivityLogService(self._db, self._user_id).log_event(
            "encryption_kek_rotation_complete",
            action_detail={
                "rotation_id": str(body.rotation_id),
                "notes_total": body.notes_total,
                "notes_re_encrypted": body.notes_re_encrypted,
                "notes_failed": body.notes_failed,
                "duration_seconds": body.duration_seconds,
                "new_kek_version": session.get("new_kek_version"),
                "encryption_setup_persisted": (
                    body.new_encryption_setup is not None
                ),
            },
            request=request,
        )
        await self._db.commit()

        await self._clear_session(body.rotation_id)

        logger.info(
            "Encryption rotation completed user=%s rotation_id=%s total=%d "
            "succeeded=%d failed=%d",
            self._user_id,
            body.rotation_id,
            body.notes_total,
            body.notes_re_encrypted,
            body.notes_failed,
        )

        return ChangePasswordCommitResponse(
            rotation_id=body.rotation_id,
            notes_total=body.notes_total,
            notes_re_encrypted=body.notes_re_encrypted,
            notes_failed=body.notes_failed,
            completed_at=completed_at,
            new_kek_version=session.get("new_kek_version") or 0,
        )


    async def get_recovery_state(self) -> ChangePasswordRecoveryResponse:
        rotation_id = await self._load_user_rotation_id()
        if rotation_id is None:
            return ChangePasswordRecoveryResponse(in_flight=False)

        session = await self._load_session_optional(rotation_id)
        if session is None:
            return ChangePasswordRecoveryResponse(in_flight=False)

        return ChangePasswordRecoveryResponse(
            in_flight=True,
            rotation_id=rotation_id,
            started_at=datetime.fromisoformat(session["started_at"]),
            expires_at=datetime.fromisoformat(session["expires_at"]),
            new_kek_version=session.get("new_kek_version"),
            phase=session.get("phase", "started"),
        )


    async def reconcile_batch(
        self, body: ChangePasswordReconcileBatchRequest,
    ) -> ChangePasswordReconcileBatchResponse:
        await self._load_session(body.rotation_id)

        result = await self._db.execute(
            select(
                Note.id,
                Note.encryption_metadata,
            )
            .where(
                Note.id.in_(body.note_ids),
                Note.user_id == self._user_id,
                Note.is_encrypted.is_(True),
            )
        )

        already_done: list[UUID] = []
        pending: list[UUID] = []
        for row in result.all():
            metadata = row.encryption_metadata or {}
            persisted_salt = metadata.get("salt")
            if persisted_salt == body.expected_new_salt:
                already_done.append(row.id)
            else:
                pending.append(row.id)

        return ChangePasswordReconcileBatchResponse(
            rotation_id=body.rotation_id,
            already_done=already_done,
            pending=pending,
        )


    async def cancel_rotation(
        self,
        rotation_id: UUID,
        request: Request,
    ) -> None:
        session = await self._load_session_optional(rotation_id)
        if session is None:
            return

        await UserActivityLogService(self._db, self._user_id).log_event(
            "encryption_kek_rotation_failed",
            action_detail={
                "rotation_id": str(rotation_id),
                "phase_at_cancel": session.get("phase"),
                "reason": "user_cancelled",
            },
            request=request,
        )
        await self._db.commit()
        await self._clear_session(rotation_id)

        logger.info(
            "Encryption rotation cancelled user=%s rotation_id=%s phase=%s",
            self._user_id,
            rotation_id,
            session.get("phase"),
        )


    async def _check_rate_limit(self) -> int:
        try:
            redis = await get_redis()
            count = await redis.get(_rate_limit_key(self._user_id))
            if count is None:
                return 0
            count = int(count)
            if count < RATE_LIMIT_MAX:
                return 0
            ttl = await redis.ttl(_rate_limit_key(self._user_id))
            return max(ttl, 1)
        except Exception as exc:
            logger.warning(
                "Rate limit check failed for encryption rotation user=%s: %s",
                self._user_id,
                exc,
            )
            return 0

    async def _bump_rate_limit(self) -> None:
        try:
            redis = await get_redis()
            key = _rate_limit_key(self._user_id)
            new_count = await redis.incr(key)
            if new_count == 1:
                await redis.expire(key, RATE_LIMIT_WINDOW_SECONDS)
        except Exception as exc:
            logger.warning(
                "Rate limit bump failed for encryption rotation user=%s: %s",
                self._user_id,
                exc,
            )


    async def _persist_session(
        self, rotation_id: UUID, state: dict,
    ) -> None:
        try:
            redis = await get_redis()
            await redis.setex(
                _rotation_session_key(self._user_id, rotation_id),
                ROTATION_SESSION_TTL_SECONDS,
                json.dumps(state),
            )
            await redis.setex(
                _rotation_user_index_key(self._user_id),
                ROTATION_SESSION_TTL_SECONDS,
                str(rotation_id),
            )
        except Exception as exc:
            logger.warning(
                "Rotation session persist failed user=%s rotation_id=%s: %s",
                self._user_id,
                rotation_id,
                exc,
            )

    async def _load_session(self, rotation_id: UUID) -> dict:
        session = await self._load_session_optional(rotation_id)
        if session is None:
            raise EncryptionSessionMissingError(rotation_id)
        return session

    async def _load_session_optional(
        self, rotation_id: UUID,
    ) -> Optional[dict]:
        try:
            redis = await get_redis()
            raw = await redis.get(
                _rotation_session_key(self._user_id, rotation_id),
            )
            if raw is None:
                return None
            return json.loads(raw)
        except Exception as exc:
            logger.warning(
                "Rotation session load failed user=%s rotation_id=%s: %s",
                self._user_id,
                rotation_id,
                exc,
            )
            return None

    async def _load_user_rotation_id(self) -> Optional[UUID]:
        try:
            redis = await get_redis()
            raw = await redis.get(_rotation_user_index_key(self._user_id))
            if raw is None:
                return None
            return UUID(raw if isinstance(raw, str) else raw.decode())
        except Exception as exc:
            logger.warning(
                "Rotation user-index load failed user=%s: %s",
                self._user_id,
                exc,
            )
            return None

    async def _mark_phase(
        self, rotation_id: UUID, session: dict, phase: str,
    ) -> None:
        session["phase"] = phase
        await self._persist_session(rotation_id, session)

    async def _clear_session(self, rotation_id: UUID) -> None:
        try:
            redis = await get_redis()
            await redis.delete(
                _rotation_session_key(self._user_id, rotation_id),
                _rotation_user_index_key(self._user_id),
            )
        except Exception as exc:
            logger.warning(
                "Rotation session clear failed user=%s rotation_id=%s: %s",
                self._user_id,
                rotation_id,
                exc,
            )


    async def _count_encrypted_notes(self) -> int:
        result = await self._db.execute(
            select(func.count())
            .select_from(Note)
            .where(
                Note.user_id == self._user_id,
                Note.is_encrypted.is_(True),
            )
        )
        return int(result.scalar() or 0)

    async def _has_encryption_setup(self) -> bool:
        result = await self._db.execute(
            select(UserPreferences.encryption_setup).where(
                UserPreferences.user_id == self._user_id,
            )
        )
        row = result.first()
        return row is not None and row[0] is not None

    async def _persist_encryption_setup(self, setup_blob: dict) -> None:
        prefs = await self._db.scalar(
            select(UserPreferences).where(
                UserPreferences.user_id == self._user_id,
            )
        )
        if prefs is None:
            prefs = UserPreferences(
                user_id=self._user_id,
                encryption_setup=setup_blob,
            )
            self._db.add(prefs)
        else:
            prefs.encryption_setup = setup_blob
        await self._db.flush()
