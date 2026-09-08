"""Durable store for live server attestations (SystemDesign §6.2 / §36.E1).

Only ``direct_network`` attestations are persisted: a test-double attestation is
returned to its caller for inspection but can never become the stored evidence that a
real capability result or 300-run binding references.
"""

from __future__ import annotations

from redteam_agent.errors import LLMAttestationError, RepositoryIntegrityError
from redteam_agent.llm.attestation import ServerAttestation
from redteam_agent.storage.repositories import _BaseRepository

_NS = "llm_server_attestations"


class ServerAttestationRepository(_BaseRepository):
    def save(self, attestation: ServerAttestation) -> None:
        if attestation.provenance != "direct_network":
            raise LLMAttestationError("only direct_network attestations are persisted")
        self._db.put_idempotent(_NS, attestation.attestation_digest, self._dump(attestation))

    def get(self, attestation_digest: str) -> ServerAttestation | None:
        raw = self._db.get(_NS, attestation_digest)
        if raw is None:
            return None
        attestation = self._load(
            ServerAttestation, raw, row_key=attestation_digest, payload_key=attestation_digest
        )
        if attestation.attestation_digest != attestation_digest:
            raise RepositoryIntegrityError("stored row key does not match payload identity")
        return attestation


__all__ = ["ServerAttestationRepository"]
