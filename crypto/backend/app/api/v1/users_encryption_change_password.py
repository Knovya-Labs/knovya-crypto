from __future__ import annotations

import logging
from uuid import UUID

from fastapi import APIRouter, Depends, Request, status
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user
from app.core.database import get_db
from app.models.user import User
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
from app.services.encryption_change_password_service import (
    EncryptionChangePasswordService,
    EncryptionRateLimitedError,
    EncryptionSessionMissingError,
)

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/users/me/encryption/change-password",
    tags=["users", "encryption"],
)


def _service(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> EncryptionChangePasswordService:
    return EncryptionChangePasswordService(db, user.id)


def _rate_limited_response(exc: EncryptionRateLimitedError) -> JSONResponse:
    return JSONResponse(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        content={
            "code": "encryption_change_password_rate_limited",
            "message": (
                "Master password can be changed at most once per 24 hours. "
                "Please wait and try again."
            ),
            "retry_after_seconds": exc.retry_after_seconds,
        },
    )


def _session_missing_response(
    exc: EncryptionSessionMissingError,
) -> JSONResponse:
    return JSONResponse(
        status_code=status.HTTP_404_NOT_FOUND,
        content={
            "code": "encryption_change_password_session_missing",
            "message": (
                "Rotation session is missing or expired. "
                "Please restart the wizard."
            ),
            "rotation_id": str(exc.rotation_id),
        },
    )


@router.post("/start", response_model=ChangePasswordStartResponse)
async def start_change_password(
    body: ChangePasswordStartRequest,
    request: Request,
    service: EncryptionChangePasswordService = Depends(_service),
):
    try:
        return await service.start_rotation(body, request)
    except EncryptionRateLimitedError as exc:
        return _rate_limited_response(exc)


@router.post("/dry-run", response_model=ChangePasswordDryRunResponse)
async def dry_run_change_password(
    body: ChangePasswordDryRunRequest,
    request: Request,
    service: EncryptionChangePasswordService = Depends(_service),
):
    try:
        return await service.record_dry_run(body, request)
    except EncryptionSessionMissingError as exc:
        return _session_missing_response(exc)


@router.post("/commit", response_model=ChangePasswordCommitResponse)
async def commit_change_password(
    body: ChangePasswordCommitRequest,
    request: Request,
    service: EncryptionChangePasswordService = Depends(_service),
):
    try:
        return await service.commit_rotation(body, request)
    except EncryptionSessionMissingError as exc:
        return _session_missing_response(exc)


@router.get("/recovery", response_model=ChangePasswordRecoveryResponse)
async def get_recovery_state(
    service: EncryptionChangePasswordService = Depends(_service),
):
    return await service.get_recovery_state()


@router.post("/cancel", status_code=204)
async def cancel_rotation(
    rotation_id: UUID,
    request: Request,
    service: EncryptionChangePasswordService = Depends(_service),
):
    await service.cancel_rotation(rotation_id, request)
    return None


@router.post(
    "/reconcile-batch",
    response_model=ChangePasswordReconcileBatchResponse,
)
async def reconcile_batch(
    body: ChangePasswordReconcileBatchRequest,
    service: EncryptionChangePasswordService = Depends(_service),
):
    try:
        return await service.reconcile_batch(body)
    except EncryptionSessionMissingError as exc:
        return _session_missing_response(exc)
