"""Ephemeral, non-serializable secret bindings (SystemDesign §10.2).

An ``EphemeralSecretBinding`` is a *temporary borrow* of a decrypted secret into
a bounded mutable buffer, valid only inside the executor's single dispatch call
stack. It is deliberately not a pydantic model, dataclass-for-storage, JSON
object, graph state or callback payload: it cannot be serialized, logged,
pickled or copied, and its buffer is zeroized when the enclosing call ends.

The adapter reads the borrowed bytes to build its provider request but must not
copy the value anywhere; the binding exposes only the value length as non-secret
control metadata plus a one-shot ``consume`` for the adapter's own use.
"""

from __future__ import annotations

from typing import NoReturn, Protocol, runtime_checkable


@runtime_checkable
class EphemeralSecretBinding(Protocol):
    """A borrow of one decrypted secret for a single dispatch call.

    Must never be implemented as a serializable / loggable / repository-storable
    model (SystemDesign §10.2).
    """

    @property
    def secret_argument_path(self) -> str: ...

    @property
    def secret_version_id(self) -> str: ...

    def length(self) -> int: ...

    def consume(self) -> bytes: ...


class _EphemeralSecretBinding:
    """The concrete borrow. Constructed only inside the dispatch continuation."""

    __slots__ = ("_buffer", "_invalidated", "_path", "_version_id")

    def __init__(self, *, secret_argument_path: str, secret_version_id: str, buffer: bytearray) -> None:
        self._buffer = buffer
        self._path = secret_argument_path
        self._version_id = secret_version_id
        self._invalidated = False

    @property
    def secret_argument_path(self) -> str:
        return self._path

    @property
    def secret_version_id(self) -> str:
        return self._version_id

    def length(self) -> int:
        if self._invalidated:
            return 0
        return len(self._buffer)

    def consume(self) -> bytes:
        """Return an immutable snapshot of the borrowed bytes for the adapter.

        This is intended only for the trusted adapter to build its provider
        request within the same call; the adapter must not persist the result.
        """
        if self._invalidated:
            raise RuntimeError("ephemeral secret binding already invalidated")
        return bytes(self._buffer)

    def zeroize(self) -> None:
        for index in range(len(self._buffer)):
            self._buffer[index] = 0
        self._invalidated = True

    # --- anti-leak guards -------------------------------------------------

    def __repr__(self) -> str:  # pragma: no cover - trivial
        return f"<EphemeralSecretBinding path={self._path!r} version={self._version_id!r} redacted>"

    def __reduce__(self) -> NoReturn:
        raise TypeError("EphemeralSecretBinding is not serializable")

    def __copy__(self) -> NoReturn:
        raise TypeError("EphemeralSecretBinding is not copyable")

    def __deepcopy__(self, memo: object) -> NoReturn:
        raise TypeError("EphemeralSecretBinding is not copyable")
