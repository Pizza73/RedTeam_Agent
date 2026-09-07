"""Fixed output publication rule, bounded parser and redaction (SystemDesign §33.0).

Secret detection and LLM publication are separate decisions. Only fields explicitly
allowlisted by a release-fixed :class:`OutputPublicationRule` are published, as freshly
built redacted records; secret fields are diverted to the secret store and replaced by a
fixed redaction marker. Non-publishable input (unknown media/encoding, duplicate key,
unknown field, type mismatch, oversize record, too-deep nesting) is not published. The
caller/LLM cannot pick the parser or the public fields.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

from pydantic import Field

from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.canonical.json_boundary import parse_json_no_duplicate_keys
from redteam_agent.errors import (
    DuplicateJsonKeyError,
    OutputPublicationError,
    PydanticBoundaryValidationError,
)
from redteam_agent.models.base import StrictImmutableBoundaryModel

_REDACTION_MARKER = "[REDACTED-SECRET]"


class OutputPublicationRule(StrictImmutableBoundaryModel):
    rule_id: str = Field(min_length=1)
    rule_revision: str = Field(min_length=1)
    parser_id: Literal["json_object_v1", "ndjson_v1"]
    parser_code_digest: str = Field(min_length=1)
    input_schema_digest: str = Field(min_length=1)
    allowed_media_types: tuple[str, ...]
    public_field_types: dict[str, Literal["string", "integer", "boolean"]]
    secret_field_pointers: tuple[str, ...]
    credential_type: str = Field(min_length=1)
    max_record_bytes: int = Field(gt=0)
    max_nesting_depth: int = Field(gt=0)
    max_public_artifacts: int = Field(gt=0)
    max_secret_versions: int = Field(ge=0)
    rule_digest: str = Field(min_length=1)


@dataclass(frozen=True)
class DetectedSecretValue:
    pointer: str
    credential_type: str
    value: bytes


@dataclass
class ParsedOutput:
    redacted_records: tuple[dict[str, Any], ...]
    detected_secrets: tuple[DetectedSecretValue, ...]
    omitted_reason_codes: tuple[str, ...]
    redaction_count: int


class OutputPublicationRuleCatalog:
    """Release-fixed catalog of publication rules (no runtime override)."""

    def __init__(self, digest_service: DigestService) -> None:
        self._ds = digest_service
        self._rules: dict[str, OutputPublicationRule] = {}

    def register(
        self, *, rule_id: str, parser_id: Literal["json_object_v1", "ndjson_v1"],
        public_field_types: dict[str, Literal["string", "integer", "boolean"]],
        secret_field_pointers: tuple[str, ...], credential_type: str = "password",
        max_record_bytes: int = 64 * 1024, max_nesting_depth: int = 16,
        max_public_artifacts: int = 8, max_secret_versions: int = 4,
    ) -> OutputPublicationRule:
        media = ("application/json",) if parser_id == "json_object_v1" else ("application/x-ndjson",)
        fields = {
            "rule_id": rule_id, "rule_revision": "1", "parser_id": parser_id,
            "parser_code_digest": self._ds.compute("publication_rule_digest", {"code": parser_id}),
            "input_schema_digest": self._ds.compute("publication_rule_digest", {"schema": rule_id}),
            "allowed_media_types": media,
            "public_field_types": public_field_types, "secret_field_pointers": secret_field_pointers,
            "credential_type": credential_type, "max_record_bytes": max_record_bytes,
            "max_nesting_depth": max_nesting_depth, "max_public_artifacts": max_public_artifacts,
            "max_secret_versions": max_secret_versions,
        }
        rule = OutputPublicationRule(
            **fields,  # type: ignore[arg-type]
            rule_digest=self._ds.compute("publication_rule_digest", fields),
        )
        self._rules[rule_id] = rule
        return rule

    def get(self, rule_id: str) -> OutputPublicationRule:
        rule = self._rules.get(rule_id)
        if rule is None:
            raise OutputPublicationError(f"unregistered output publication rule: {rule_id}")
        return rule

    def verify(self, rule: OutputPublicationRule) -> None:
        current = self.get(rule.rule_id)
        if current.rule_digest != rule.rule_digest or current.parser_code_digest != rule.parser_code_digest:
            raise OutputPublicationError("publication rule / parser code digest mismatch")


def _depth(value: Any, limit: int, current: int = 1) -> None:
    if current > limit:
        raise OutputPublicationError("record nesting exceeds the rule depth limit")
    if isinstance(value, dict):
        for item in value.values():
            _depth(item, limit, current + 1)
    elif isinstance(value, list):
        for item in value:
            _depth(item, limit, current + 1)


def _type_ok(kind: str, value: Any) -> bool:
    if kind == "string":
        return isinstance(value, str)
    if kind == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if kind == "boolean":
        return isinstance(value, bool)
    return False


class OutputPublicationParser:
    """Bounded JSON/NDJSON parser applying the fixed rule (no caller-selected code)."""

    def parse(self, rule: OutputPublicationRule, raw: bytes) -> ParsedOutput:
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise OutputPublicationError("output is not valid UTF-8; not publishable") from exc
        lines = [text] if rule.parser_id == "json_object_v1" else [ln for ln in text.splitlines() if ln.strip()]
        redacted_records: list[dict[str, Any]] = []
        detected: list[DetectedSecretValue] = []
        redaction_count = 0
        for line in lines:
            if len(line.encode("utf-8")) > rule.max_record_bytes:
                raise OutputPublicationError("record exceeds the rule byte limit; not publishable")
            try:
                record = parse_json_no_duplicate_keys(line)
            except (DuplicateJsonKeyError, PydanticBoundaryValidationError) as exc:
                raise OutputPublicationError("record failed the trust-boundary JSON parser") from exc
            if not isinstance(record, dict):
                raise OutputPublicationError("publication record must be a JSON object")
            _depth(record, rule.max_nesting_depth)
            secret_pointers = set(rule.secret_field_pointers)
            for pointer in rule.secret_field_pointers:
                token = pointer.lstrip("/")
                if token in record:
                    value = record[token]
                    if not isinstance(value, str):
                        raise OutputPublicationError("secret field must be a string")
                    detected.append(DetectedSecretValue(pointer=pointer, credential_type=rule.credential_type,
                                                        value=value.encode("utf-8")))
                    redaction_count += 1
            published: dict[str, Any] = {}
            for name, value in record.items():
                if f"/{name}" in secret_pointers:
                    published[name] = _REDACTION_MARKER
                    continue
                if name not in rule.public_field_types:
                    raise OutputPublicationError(f"unknown field '{name}' is not in the publication allowlist")
                if not _type_ok(rule.public_field_types[name], value):
                    raise OutputPublicationError(f"field '{name}' failed its allowlisted type")
                published[name] = value
            redacted_records.append(published)
        if len(redacted_records) > rule.max_public_artifacts:
            raise OutputPublicationError("too many public records for the rule quota")
        if len(detected) > rule.max_secret_versions:
            raise OutputPublicationError("too many detected secrets for the rule quota")
        return ParsedOutput(
            redacted_records=tuple(redacted_records), detected_secrets=tuple(detected),
            omitted_reason_codes=(), redaction_count=redaction_count,
        )
