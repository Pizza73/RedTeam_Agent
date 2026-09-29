"""Composition-owned trusted secret plaintext source (SystemDesign §10.2 / §34).

This boundary intentionally exposes no generic ``resolve(reference, execution_id)``
and no method that accepts a consumed claim or a reusable token: it is not a
standalone resolver. It exposes only ``open_version(secret_version_id)``, a
low-level decrypt primitive keyed by an *exact* version id. The composition root
injects it solely into the executor's :class:`SecretDispatchTransaction`; it is
never returned to an application caller as a public service.

Phase 0B ships an in-memory test-double source (fixed version -> plaintext). The
production key provider (domain KEK + resource DEK envelope encryption, TPM
witness) is Phase 0C; the ``open_version`` boundary keeps that swap possible.
"""

from __future__ import annotations

from typing import Protocol

from redteam_agent.errors import EncryptionKeyUnavailableError


class TrustedSecretSource(Protocol):
    def open_version(self, secret_version_id: str) -> bytearray:
        """Return a fresh bounded mutable buffer with the version's plaintext.

        Raises :class:`EncryptionKeyUnavailableError` if the version's key or
        plaintext is unavailable. The caller (the executor continuation) owns and
        zeroizes the returned buffer.
        """
        ...


class StaticTrustedSecretSource:
    """An in-memory plaintext source installed by the composition root (test double)."""

    def __init__(self, plaintext: dict[str, bytes] | None = None) -> None:
        self._plaintext = dict(plaintext or {})

    def put(self, secret_version_id: str, value: bytes) -> None:
        self._plaintext[secret_version_id] = value

    def revoke(self, secret_version_id: str) -> None:
        self._plaintext.pop(secret_version_id, None)

    def open_version(self, secret_version_id: str) -> bytearray:
        try:
            value = self._plaintext[secret_version_id]
        except KeyError:
            raise EncryptionKeyUnavailableError("secret version plaintext is unavailable") from None
        return bytearray(value)
