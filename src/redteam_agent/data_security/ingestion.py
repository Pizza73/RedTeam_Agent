"""Deterministic quarantine-to-redacted-artifact ingestion pipeline."""

from __future__ import annotations

import re
from datetime import datetime

from redteam_agent.canonical import sha256_digest, stable_id
from redteam_agent.errors import SecretDetectionError, SecureIngestionError

from .models import (
    ArtifactReference,
    QuarantineReference,
    RedactionMetadata,
    SecretDiscoveryReference,
    SecureIngestionResult,
)
from .stores import ArtifactStore, EncryptedRawResultQuarantine, SecretStore

_SECRET_PATTERN = re.compile(
    rb"(?i)\b(password|passwd|token|api[_-]?key|secret)\s*([:=])\s*([^\s,;]+)"
)


class SecureIngestor:
    def __init__(
        self,
        *,
        quarantine: EncryptedRawResultQuarantine,
        artifacts: ArtifactStore,
        secrets: SecretStore,
        rule_version: str = "phase0c-redaction-v1",
    ) -> None:
        if not rule_version:
            raise ValueError("redaction rule version is required")
        self._quarantine = quarantine
        self._artifacts = artifacts
        self._secrets = secrets
        self._rule_version = rule_version

    def ingest(
        self,
        reference: QuarantineReference,
        *,
        now: datetime,
        retain_encrypted_raw: bool = False,
    ) -> SecureIngestionResult:
        try:
            raw = self._quarantine.resume(reference, now=now)
            detections: list[SecretDiscoveryReference] = []

            def redact(match: re.Match[bytes]) -> bytes:
                credential_type = match.group(1).decode("ascii").lower().replace("-", "_")
                secret = self._secrets.create(
                    mission_id=reference.mission_id,
                    secret_value=match.group(3),
                    credential_type=credential_type,
                    associated_principal_ref=None,
                    source_execution_id=reference.execution_id,
                    created_at=now,
                )
                detections.append(
                    SecretDiscoveryReference(
                        secret_reference_id=secret.secret_reference_id,
                        credential_type=secret.credential_type,
                        associated_principal_ref=secret.associated_principal_ref,
                        source_execution_id=reference.execution_id,
                        verification_state=secret.verification_state,
                    )
                )
                return match.group(1) + match.group(2) + b"[REDACTED]"

            try:
                redacted = _SECRET_PATTERN.sub(redact, raw)
            except (UnicodeError, ValueError) as exc:
                del exc
                raise SecretDetectionError("secret detection failed closed") from None
            redacted_reference = self._artifacts.put(
                mission_id=reference.mission_id,
                content=redacted,
                media_type="application/octet-stream",
                classification="sensitive" if detections else "normal",
                variant="redacted",
                created_at=now,
                derived_from_artifact_id=None,
            )
            encrypted_raw: tuple[ArtifactReference, ...] = ()
            if retain_encrypted_raw:
                encrypted_raw = (
                    self._artifacts.put(
                        mission_id=reference.mission_id,
                        content=raw,
                        media_type="application/octet-stream",
                        classification="secret",
                        variant="encrypted_raw",
                        created_at=now,
                        derived_from_artifact_id=redacted_reference.artifact_id,
                    ),
                )
            ingestion_id = stable_id(
                "secureingestion",
                {
                    "quarantine_id": reference.quarantine_id,
                    "quarantine_sha256": reference.sha256,
                    "rule_version": self._rule_version,
                },
            )
            redaction_metadata = RedactionMetadata(
                rule_version=self._rule_version,
                redaction_count=len(detections),
                secret_detection_count=len(detections),
            )
            digest_payload = {
                "ingestion_id": ingestion_id,
                "redacted_artifacts": (redacted_reference,),
                "encrypted_raw_artifacts": encrypted_raw,
                "detected_secrets": tuple(detections),
                "redaction_metadata": redaction_metadata,
            }
            result = SecureIngestionResult(
                ingestion_id=ingestion_id,
                ingestion_digest=sha256_digest(digest_payload),
                redacted_artifacts=(redacted_reference,),
                encrypted_raw_artifacts=encrypted_raw,
                detected_secrets=tuple(detections),
                redaction_metadata=redaction_metadata,
            )
            self._quarantine.delete(reference)
            return result
        except SecureIngestionError:
            raise
        except Exception as exc:
            del exc
            raise SecureIngestionError("secure ingestion failed closed") from None
