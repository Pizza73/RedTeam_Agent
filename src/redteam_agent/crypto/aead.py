"""Standard authenticated encryption (AES-256-GCM) through the ``cryptography`` package.

This module is the *only* cipher entry point. It performs no key management and no
homegrown cryptography: it delegates to
``cryptography.hazmat.primitives.ciphers.aead.AESGCM`` for a single versioned
algorithm in an allowlist. If ``cryptography`` is not installed the module still
imports (so the authorization kernel keeps working), but any attempt to encrypt or
decrypt fails closed with :class:`EncryptionUnavailableError`. There is never a
silent downgrade to plaintext or to a non-standard construction.

Design (SystemDesign §34.1 / §34.1.1): AES-256-GCM, 256-bit keys, unique 96-bit
nonces, a 128-bit authentication tag, and the domain/mission/execution/resource
binding carried in the Additional Authenticated Data (AAD). Nonce uniqueness and
AAD construction are enforced by the key provider, not here.
"""

from __future__ import annotations

from dataclasses import dataclass

from redteam_agent.errors import EncryptionUnavailableError

# Guarded import: the kernel must import without ``cryptography`` present. The real
# dependency is pinned in pyproject; the parent environment installs it. Until then
# every cipher call fails closed.
try:  # pragma: no cover - import guard exercised via _CRYPTOGRAPHY_IMPORT_ERROR
    from cryptography.exceptions import InvalidTag as _InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM as _AESGCM

    _CRYPTOGRAPHY_IMPORT_ERROR: str | None = None
except Exception as exc:
    _AESGCM = None  # type: ignore[assignment,misc]
    _InvalidTag = Exception  # type: ignore[assignment,misc]
    _CRYPTOGRAPHY_IMPORT_ERROR = type(exc).__name__


@dataclass(frozen=True)
class AeadAlgorithm:
    """A versioned, allowlisted authenticated-encryption algorithm."""

    algorithm_id: str
    key_length: int
    nonce_length: int
    tag_length: int


# The single allowlisted algorithm. Adding another requires a new versioned id and a
# catalog/migration; a mission/caller/config value cannot select the algorithm.
AES_256_GCM_V1 = AeadAlgorithm(algorithm_id="aes_256_gcm_v1", key_length=32, nonce_length=12, tag_length=16)
_ALGORITHMS: dict[str, AeadAlgorithm] = {AES_256_GCM_V1.algorithm_id: AES_256_GCM_V1}


def cryptography_available() -> bool:
    """Return whether the standard AEAD backend is importable.

    Isolated so a fail-closed test can force absence deterministically regardless of
    the environment, and so the composition self-check has a single probe point.
    """
    return _AESGCM is not None


def require_aead() -> None:
    """Raise :class:`EncryptionUnavailableError` if the standard AEAD backend is absent."""
    if not cryptography_available():
        detail = _CRYPTOGRAPHY_IMPORT_ERROR or "not installed"
        raise EncryptionUnavailableError(
            f"standard AEAD backend (cryptography / AES-256-GCM) is unavailable ({detail}); "
            "fail closed with no plaintext or non-standard fallback"
        )


def get_algorithm(algorithm_id: str) -> AeadAlgorithm:
    algorithm = _ALGORITHMS.get(algorithm_id)
    if algorithm is None:
        raise EncryptionUnavailableError(f"unsupported AEAD algorithm: {algorithm_id}")
    return algorithm


def _check_lengths(algorithm: AeadAlgorithm, *, key: bytes, nonce: bytes) -> None:
    if len(key) != algorithm.key_length:
        raise EncryptionUnavailableError(
            f"{algorithm.algorithm_id}: key must be {algorithm.key_length} bytes"
        )
    if len(nonce) != algorithm.nonce_length:
        raise EncryptionUnavailableError(
            f"{algorithm.algorithm_id}: nonce must be {algorithm.nonce_length} bytes"
        )


def aead_encrypt(*, algorithm_id: str, key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
    """Encrypt with the allowlisted algorithm; returns ciphertext with the appended tag."""
    require_aead()
    algorithm = get_algorithm(algorithm_id)
    _check_lengths(algorithm, key=key, nonce=nonce)
    return bytes(_AESGCM(bytes(key)).encrypt(bytes(nonce), bytes(plaintext), bytes(aad)))


def aead_decrypt(*, algorithm_id: str, key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    """Decrypt/verify; raises :class:`EncryptionUnavailableError` on auth failure.

    An authentication failure includes a wrong key, a corrupted ciphertext, or an
    AAD (domain/resource binding) that does not match. The caller performs its own
    explicit domain/binding checks first, so a raised auth failure here is a hard
    fail-closed stop, never a downgrade.
    """
    require_aead()
    algorithm = get_algorithm(algorithm_id)
    _check_lengths(algorithm, key=key, nonce=nonce)
    try:
        return bytes(_AESGCM(bytes(key)).decrypt(bytes(nonce), bytes(ciphertext), bytes(aad)))
    except _InvalidTag:
        raise EncryptionUnavailableError("AEAD authentication failed (key/aad/ciphertext mismatch)") from None
