"""Reusable immutable JSON row repository primitives."""

from __future__ import annotations

import sqlite3
from typing import Generic, TypeVar

from pydantic import BaseModel

from redteam_agent.canonical import canonical_loads, canonicalize
from redteam_agent.canonical.digest import model_payload
from redteam_agent.errors import DigestIntegrityError, RepositoryConflictError
from redteam_agent.storage import Database

ModelT = TypeVar("ModelT", bound=BaseModel)


def model_json(model: BaseModel) -> str:
    return canonicalize(model_payload(model)).decode("utf-8")


def parse_model_json(model_type: type[ModelT], payload: str | bytes) -> ModelT:
    """Duplicate-aware parser for persisted security artifacts."""

    try:
        duplicate_free = canonical_loads(payload)
        return model_type.model_validate_json(canonicalize(duplicate_free))
    except (TypeError, ValueError) as exc:
        raise DigestIntegrityError(f"invalid persisted {model_type.__name__} payload") from exc


class ImmutableJsonRepository(Generic[ModelT]):
    table: str
    id_column: str
    model_type: type[ModelT]

    def __init__(self, database: Database) -> None:
        self.database = database

    def _get_payload(self, identifier: str | int) -> str | None:
        row = self.database.connection.execute(
            f"SELECT payload_json FROM {self.table} WHERE {self.id_column} = ?",  # noqa: S608
            (identifier,),
        ).fetchone()
        return None if row is None else str(row["payload_json"])

    def get(self, identifier: str | int) -> ModelT | None:
        payload = self._get_payload(identifier)
        if payload is None:
            return None
        try:
            model = parse_model_json(self.model_type, payload)
            self.verify_integrity(model)
            self.verify_row_binding(identifier, model)
        except DigestIntegrityError:
            raise
        except (TypeError, ValueError) as exc:
            raise DigestIntegrityError(
                f"invalid persisted {self.model_type.__name__} payload"
            ) from exc
        return model

    def verify_integrity(self, model: ModelT) -> None:
        """Subclasses must override when a model carries an integrity digest."""

    def verify_row_binding(self, identifier: str | int, model: ModelT) -> None:
        """Subclasses may verify denormalized SQL columns against the envelope."""

    @staticmethod
    def ensure_same_payload(existing: str, incoming: str) -> None:
        if existing != incoming:
            raise DigestIntegrityError("immutable identifier reused with different payload")

    def _insert_or_same(self, statement: str, parameters: tuple[object, ...], payload: str) -> None:
        try:
            self.database.connection.execute(statement, parameters)
        except sqlite3.IntegrityError as exc:
            identifier = parameters[0]
            existing = self._get_payload(identifier)
            if existing is None:
                raise RepositoryConflictError(str(exc)) from exc
            self.ensure_same_payload(existing, payload)
