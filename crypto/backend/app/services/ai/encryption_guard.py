from __future__ import annotations

from typing import Any, Protocol
from uuid import UUID


class NoteEncryptedError(Exception):

    def __init__(self, *, note_id: UUID | None = None) -> None:
        super().__init__("AI editing is disabled for end-to-end encrypted notes.")
        self.note_id = note_id


class _Note(Protocol):

    is_encrypted: bool


class _NoteRepo(Protocol):

    async def get(self, note_id: UUID) -> _Note | None: ...


async def assert_note_not_encrypted(repo: _NoteRepo, note_id: UUID) -> None:
    note = await repo.get(note_id)
    if note is not None and getattr(note, "is_encrypted", False):
        raise NoteEncryptedError(note_id=note_id)


async def return_empty_if_encrypted(
    repo: _NoteRepo,
    note_id: UUID,
    empty_value: Any,
) -> Any | None:
    try:
        note = await repo.get(note_id)
    except Exception:
        note = None
    if note is not None and getattr(note, "is_encrypted", False):
        return empty_value
    return None


__all__ = [
    "NoteEncryptedError",
    "assert_note_not_encrypted",
    "return_empty_if_encrypted",
]
