"""Deterministic quarantine-to-redacted-artifact ingestion pipeline."""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable
from datetime import datetime
from typing import Literal

from redteam_agent.canonical import sha256_digest, stable_id
from redteam_agent.errors import SecretDetectionError, SecureIngestionError
from redteam_agent.models.execution import (
    ExecutionResult,
    RawResultReceipt,
    SecureIngestionSummary,
)

from .authorization import IngestionWriteEvidence
from .models import (
    ArtifactReference,
    QuarantineReference,
    RedactionMetadata,
    SecretDiscoveryReference,
    SecureIngestionResult,
)
from .stores import ArtifactStore, EncryptedRawResultQuarantine, SecretStore
from .streaming import EncryptedRawResultSink, EncryptedRawResultSinkFactory

_SECRET_KEYWORDS = (
    b"access_token",
    b"access-token",
    b"accesstoken",
    b"refresh_token",
    b"refresh-token",
    b"refreshtoken",
    b"client_secret",
    b"client-secret",
    b"clientsecret",
    b"oauth_token",
    b"oauth-token",
    b"oauthtoken",
    b"password",
    b"passwd",
    b"token",
    b"api_key",
    b"api-key",
    b"apikey",
    b"secret",
)
_AUTHORIZATION_HEADER = b"authorization"
_SUPPORTED_AUTHORIZATION_SCHEMES = (b"bearer", b"basic")
_PEM_BEGIN_PREFIX = b"-----BEGIN "
_PEM_LABEL_SUFFIX = b"-----"
_CREDENTIAL_KEY_COMPONENTS = (
    b"credential",
    b"password",
    b"passwd",
    b"privatekey",
    b"secret",
    b"sshkey",
    b"token",
    b"apikey",
)
_SECRET_TERMINATORS = frozenset(b" \t\n\r\v\f,;}]" + bytes((34, 39)))
_SECRET_WHITESPACE = frozenset(b" \t\n\r\v\f")
_QUOTE_BYTES = frozenset(b"\"'")
_ASCII_WORD_BYTES = frozenset(
    b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"
)
_AUTHORIZATION_SCHEME_BYTES = _ASCII_WORD_BYTES | frozenset(b"!#$%&'*+-.^`|~")
_URI_SCHEME_START_BYTES = frozenset(
    b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
)
_URI_SCHEME_BYTES = _URI_SCHEME_START_BYTES | frozenset(b"0123456789+.-")
_MAX_URI_SCHEME_BYTES = 256
_STRUCTURED_KEY_BYTES = _ASCII_WORD_BYTES | frozenset(b"-")
_MAX_STRUCTURED_KEY_BYTES = 256
_XML_TAG_NAME_BYTES = _STRUCTURED_KEY_BYTES | frozenset(b":.")
_MAX_PENDING_SECRET_MATCH_BYTES = 64 * 1024
_JSON_KEY_SIMPLE_ESCAPES = {
    ord('"'): ord('"'),
    ord("\\"): ord("\\"),
    ord("/"): ord("/"),
    ord("b"): 8,
    ord("f"): 12,
    ord("n"): 10,
    ord("r"): 13,
    ord("t"): 9,
}
_JSON_KEY_HEX_BYTES = frozenset(b"0123456789abcdefABCDEF")

_SecretMatch = tuple[int, int, int, int, int, bytes]


class _StreamingSecretRedactor:
    """Recognizes the Phase 0C secret grammar across arbitrary chunk boundaries."""

    def __init__(
        self,
        replace: Callable[[bytes, bytes], bytes],
    ) -> None:
        self._replace = replace
        self._pending = bytearray()
        self._previous_byte: int | None = None

    def feed(self, chunk: bytes, *, final: bool = False) -> bytes:
        if not isinstance(chunk, bytes):
            raise SecretDetectionError("secret detection failed closed")
        self._pending.extend(chunk)
        data = bytes(self._pending)
        output = bytearray()
        index = 0
        while index < len(data):
            previous = data[index - 1] if index else self._previous_byte
            candidate = None
            if data[index] == ord("<") or data[index] in _QUOTE_BYTES or (
                previous is None or previous not in _ASCII_WORD_BYTES
            ):
                candidate = self._candidate(data, index, final=final)
            if candidate == "incomplete":
                self._previous_byte = data[index - 1] if index else self._previous_byte
                self._pending = bytearray(data[index:])
                if len(self._pending) > _MAX_PENDING_SECRET_MATCH_BYTES:
                    raise SecretDetectionError("secret detection failed closed")
                return bytes(output)
            if candidate is not None:
                (
                    keyword_start,
                    keyword_end,
                    secret_start,
                    secret_end,
                    match_end,
                    keyword,
                ) = candidate
                output.extend(data[index:secret_start])
                output.extend(
                    self._replace(
                        keyword,
                        data[secret_start:secret_end],
                    )
                )
                output.extend(data[secret_end:match_end])
                index = match_end
                continue
            output.append(data[index])
            index += 1
        if data:
            self._previous_byte = data[-1]
        self._pending.clear()
        return bytes(output)

    @staticmethod
    def _candidate(
        data: bytes,
        index: int,
        *,
        final: bool,
    ) -> _SecretMatch | Literal["incomplete"] | None:
        private_key = _StreamingSecretRedactor._private_key_candidate(
            data,
            index,
            final=final,
        )
        if private_key is not None:
            return private_key
        header = _StreamingSecretRedactor._authorization_header_candidate(
            data,
            index,
            final=final,
        )
        if header is not None:
            return header
        credential_uri = _StreamingSecretRedactor._credential_uri_candidate(
            data,
            index,
            final=final,
        )
        if credential_uri is not None:
            return credential_uri
        authorization = _StreamingSecretRedactor._supported_scheme_candidate(
            data,
            index,
            final=final,
        )
        if authorization is not None:
            return authorization
        xml_element = _StreamingSecretRedactor._xml_element_candidate(
            data,
            index,
            final=final,
        )
        if xml_element is not None:
            return xml_element
        key_quote = data[index] if data[index] in _QUOTE_BYTES else None
        keyword_start = index + 1 if key_quote is not None else index
        keyword: bytes | None = None
        if key_quote is not None:
            cursor = keyword_start
            while cursor < len(data) and data[cursor] != key_quote:
                if data[cursor] == 92:
                    if cursor + 1 == len(data):
                        if final:
                            raise SecretDetectionError(
                                "secret detection failed closed"
                            )
                        return "incomplete"
                    cursor += 2
                    continue
                cursor += 1
            if cursor == len(data):
                return None if final else "incomplete"
            structured_key = _StreamingSecretRedactor._decode_structured_key(
                data[keyword_start:cursor],
                quote=key_quote,
            )
            normalized_key = structured_key.lower().replace(b"_", b"").replace(
                b"-", b""
            )
            if structured_key.lower() in _SECRET_KEYWORDS or any(
                component in normalized_key
                for component in _CREDENTIAL_KEY_COMPONENTS
            ):
                keyword = structured_key
        else:
            cursor = keyword_start
            while cursor < len(data) and data[cursor] in _STRUCTURED_KEY_BYTES:
                cursor += 1
                if cursor - keyword_start > _MAX_STRUCTURED_KEY_BYTES:
                    return None
            if cursor == len(data):
                return None if final else "incomplete"
            structured_key = data[keyword_start:cursor]
            normalized_key = structured_key.lower().replace(b"_", b"").replace(
                b"-", b""
            )
            if structured_key.lower() in _SECRET_KEYWORDS or any(
                component in normalized_key
                for component in _CREDENTIAL_KEY_COMPONENTS
            ):
                keyword = structured_key
        if keyword is None:
            return None
        keyword_end = cursor
        cursor = keyword_end
        if key_quote is not None:
            if cursor == len(data):
                return None if final else "incomplete"
            if data[cursor] != key_quote:
                return None
            cursor += 1
        delimiter_start = cursor
        while cursor < len(data) and data[cursor] in _SECRET_WHITESPACE:
            cursor += 1
        if cursor == len(data):
            return None if final else "incomplete"
        whitespace_delimited = key_quote is None and cursor > delimiter_start
        if data[cursor] in b":=":
            cursor += 1
        elif not whitespace_delimited:
            return None
        while cursor < len(data) and data[cursor] in _SECRET_WHITESPACE:
            cursor += 1
        if cursor == len(data):
            return None if final else "incomplete"
        if data[cursor] in b"|>":
            # YAML block scalars can carry an arbitrary indented body across
            # chunk boundaries.  Publishing only the scalar indicator while
            # passing that body through would expose the credential.  Until
            # this streaming boundary has a complete indentation-aware YAML
            # grammar, reject the credential construct before any part of its
            # body can become LLM-visible.
            raise SecretDetectionError("secret detection failed closed")
        value_quote = data[cursor] if data[cursor] in _QUOTE_BYTES else None
        if value_quote is not None:
            secret_start = cursor + 1
            cursor = secret_start
            while cursor < len(data):
                if data[cursor] == 92:
                    if cursor + 1 == len(data):
                        if final:
                            raise SecretDetectionError("secret detection failed closed")
                        return "incomplete"
                    cursor += 2
                    continue
                if data[cursor] == value_quote:
                    if cursor == secret_start:
                        return None
                    return (
                        keyword_start,
                        keyword_end,
                        secret_start,
                        cursor,
                        cursor + 1,
                        keyword,
                    )
                cursor += 1
            if final:
                raise SecretDetectionError("secret detection failed closed")
            return "incomplete"
        secret_start = cursor
        while cursor < len(data) and data[cursor] not in _SECRET_TERMINATORS:
            cursor += 1
        if cursor == len(data) and not final:
            return "incomplete"
        if cursor == secret_start:
            return None
        return keyword_start, keyword_end, secret_start, cursor, cursor, keyword

    @staticmethod
    def _xml_element_candidate(
        data: bytes,
        index: int,
        *,
        final: bool,
    ) -> _SecretMatch | Literal["incomplete"] | None:
        """Redact a bounded ``<credential>value</credential>`` element."""

        if data[index] != ord("<"):
            return None
        if index + 1 == len(data):
            return None if final else "incomplete"
        if data[index + 1] in b"/!?":
            return None
        open_end = data.find(b">", index + 1)
        if open_end < 0:
            candidate = data[index + 1 :]
            if not candidate or candidate[0] not in _XML_TAG_NAME_BYTES:
                return None
            if final:
                tag = candidate.split(maxsplit=1)[0].split(b":")[-1]
                normalized = tag.lower().replace(b"_", b"").replace(b"-", b"")
                if any(
                    component in normalized
                    for component in _CREDENTIAL_KEY_COMPONENTS
                ):
                    raise SecretDetectionError("secret detection failed closed")
                return None
            return "incomplete"
        raw_tag = data[index + 1 : open_end]
        if not raw_tag:
            return None
        parts = raw_tag.split(maxsplit=1)
        tag = parts[0]
        if not tag or any(value not in _XML_TAG_NAME_BYTES for value in tag):
            return None
        local_tag = tag.split(b":")[-1]
        normalized = local_tag.lower().replace(b"_", b"").replace(b"-", b"")
        is_credential = local_tag.lower() in _SECRET_KEYWORDS or any(
            component in normalized for component in _CREDENTIAL_KEY_COMPONENTS
        )
        if not is_credential:
            return None
        if len(parts) > 1 and parts[1].strip():
            raise SecretDetectionError("secret detection failed closed")
        closing = b"</" + tag.lower() + b">"
        secret_start = open_end + 1
        closing_start = data.lower().find(closing, secret_start)
        if closing_start < 0:
            if final:
                raise SecretDetectionError("secret detection failed closed")
            return "incomplete"
        if closing_start == secret_start:
            return None
        return (
            index + 1,
            index + 1 + len(tag),
            secret_start,
            closing_start,
            closing_start + len(closing),
            local_tag,
        )

    @staticmethod
    def _private_key_candidate(
        data: bytes,
        index: int,
        *,
        final: bool,
    ) -> _SecretMatch | Literal["incomplete"] | None:
        """Recognize standalone PEM/OpenSSH private-key blocks across chunks."""

        available = data[index:]
        if len(available) < len(_PEM_BEGIN_PREFIX):
            if _PEM_BEGIN_PREFIX.startswith(available) and not final:
                return "incomplete"
            return None
        if not available.startswith(_PEM_BEGIN_PREFIX):
            return None
        label_start = index + len(_PEM_BEGIN_PREFIX)
        label_end = data.find(_PEM_LABEL_SUFFIX, label_start)
        if label_end < 0:
            if final:
                if b"PRIVATE KEY" in data[label_start:].upper():
                    raise SecretDetectionError("secret detection failed closed")
                return None
            return "incomplete"
        label = data[label_start:label_end]
        if not label or b"PRIVATE KEY" not in label.upper():
            return None
        begin_end = label_end + len(_PEM_LABEL_SUFFIX)
        end = b"-----END " + label + b"-----"
        secret_end = data.find(end, begin_end)
        if secret_end < 0:
            if final:
                raise SecretDetectionError("secret detection failed closed")
            return "incomplete"
        secret_end += len(end)
        return (
            index,
            begin_end,
            index,
            secret_end,
            secret_end,
            b"private_key",
        )

    @staticmethod
    def _decode_structured_key(structured_key: bytes, *, quote: int) -> bytes:
        """Decode a quoted JSON-style key before credential-name matching."""

        decoded = bytearray()
        cursor = 0
        while cursor < len(structured_key):
            current = structured_key[cursor]
            if current != 92:
                decoded.append(current)
                cursor += 1
                continue
            if cursor + 1 >= len(structured_key):
                raise SecretDetectionError("secret detection failed closed")
            escape = structured_key[cursor + 1]
            simple = _JSON_KEY_SIMPLE_ESCAPES.get(escape)
            if simple is not None:
                decoded.append(simple)
                cursor += 2
                continue
            if escape == ord("'") and quote == ord("'"):
                decoded.append(escape)
                cursor += 2
                continue
            if escape != ord("u") or cursor + 6 > len(structured_key):
                raise SecretDetectionError("secret detection failed closed")
            digits = structured_key[cursor + 2 : cursor + 6]
            if any(value not in _JSON_KEY_HEX_BYTES for value in digits):
                raise SecretDetectionError("secret detection failed closed")
            codepoint = int(digits, 16)
            cursor += 6
            if 0xD800 <= codepoint <= 0xDBFF:
                if (
                    cursor + 6 > len(structured_key)
                    or structured_key[cursor : cursor + 2] != b"\\u"
                ):
                    raise SecretDetectionError("secret detection failed closed")
                low_digits = structured_key[cursor + 2 : cursor + 6]
                if any(value not in _JSON_KEY_HEX_BYTES for value in low_digits):
                    raise SecretDetectionError("secret detection failed closed")
                low = int(low_digits, 16)
                if not 0xDC00 <= low <= 0xDFFF:
                    raise SecretDetectionError("secret detection failed closed")
                codepoint = 0x10000 + ((codepoint - 0xD800) << 10) + (low - 0xDC00)
                cursor += 6
            elif 0xDC00 <= codepoint <= 0xDFFF:
                raise SecretDetectionError("secret detection failed closed")
            decoded.extend(chr(codepoint).encode("utf-8"))
        return bytes(decoded)

    @staticmethod
    def _credential_uri_candidate(
        data: bytes,
        index: int,
        *,
        final: bool,
    ) -> _SecretMatch | Literal["incomplete"] | None:
        """Redact the password in a supported URI authority user-info component."""

        if data[index] not in _URI_SCHEME_START_BYTES:
            return None
        scheme_end = index + 1
        while scheme_end < len(data) and data[scheme_end] in _URI_SCHEME_BYTES:
            scheme_end += 1
            if scheme_end - index > _MAX_URI_SCHEME_BYTES:
                return None
        if scheme_end == len(data):
            return None if final else "incomplete"
        delimiter = b"://"
        available_delimiter = data[scheme_end : scheme_end + len(delimiter)]
        if delimiter.startswith(available_delimiter) and len(available_delimiter) < len(
            delimiter
        ):
            return None if final else "incomplete"
        if available_delimiter != delimiter:
            return None
        authority_start = scheme_end + len(delimiter)
        cursor = authority_start
        while cursor < len(data) and data[cursor] not in b"/?# \t\r\n\v\f\"'":
            cursor += 1
        if cursor == len(data) and not final:
            return "incomplete"
        authority = data[authority_start:cursor]
        if authority.count(b"@") > 1:
            raise SecretDetectionError("secret detection failed closed")
        userinfo_end = authority.rfind(b"@")
        if userinfo_end < 0:
            return None
        password_separator = authority.find(b":", 0, userinfo_end)
        if password_separator < 0:
            return None
        if password_separator == 0:
            raise SecretDetectionError("secret detection failed closed")
        secret_start = authority_start + password_separator + 1
        secret_end = authority_start + userinfo_end
        if secret_start == secret_end:
            raise SecretDetectionError("secret detection failed closed")
        return (
            index,
            scheme_end,
            secret_start,
            secret_end,
            cursor,
            b"uri_password",
        )

    @staticmethod
    def _authorization_header_candidate(
        data: bytes,
        index: int,
        *,
        final: bool,
    ) -> _SecretMatch | Literal["incomplete"] | None:
        """Parse the header first so an unknown authorization scheme fails closed."""

        key_quote = data[index] if data[index] in _QUOTE_BYTES else None
        keyword_start = index + 1 if key_quote is not None else index
        if key_quote is not None:
            cursor = keyword_start
            while cursor < len(data) and data[cursor] != key_quote:
                if data[cursor] == 92:
                    if cursor + 1 == len(data):
                        if final:
                            raise SecretDetectionError(
                                "secret detection failed closed"
                            )
                        return "incomplete"
                    cursor += 2
                    continue
                cursor += 1
            if cursor == len(data):
                return None if final else "incomplete"
            encoded_key_end = cursor
            decoded_key = _StreamingSecretRedactor._decode_structured_key(
                data[keyword_start:encoded_key_end],
                quote=key_quote,
            )
            if decoded_key.lower() != _AUTHORIZATION_HEADER:
                return None
            cursor += 1
        else:
            cursor = keyword_start
            while cursor < len(data) and data[cursor] in _STRUCTURED_KEY_BYTES:
                cursor += 1
            candidate = data[keyword_start:cursor].lower()
            if cursor == len(data) and _AUTHORIZATION_HEADER.startswith(candidate):
                return None if final else "incomplete"
            if candidate != _AUTHORIZATION_HEADER:
                return None
            encoded_key_end = cursor
        while cursor < len(data) and data[cursor] in _SECRET_WHITESPACE:
            cursor += 1
        if cursor == len(data):
            return None if final else "incomplete"
        if data[cursor] not in b":=":
            return None
        cursor += 1
        while cursor < len(data) and data[cursor] in _SECRET_WHITESPACE:
            cursor += 1
        if cursor == len(data):
            return None if final else "incomplete"
        value_quote = data[cursor] if data[cursor] in _QUOTE_BYTES else None
        if value_quote is not None:
            cursor += 1
        scheme_start = cursor
        while cursor < len(data) and data[cursor] in _AUTHORIZATION_SCHEME_BYTES:
            cursor += 1
        if cursor == len(data):
            if final:
                raise SecretDetectionError("secret detection failed closed")
            return "incomplete"
        if cursor == scheme_start:
            raise SecretDetectionError("secret detection failed closed")
        scheme = data[scheme_start:cursor]
        if data[cursor] not in _SECRET_WHITESPACE:
            raise SecretDetectionError("secret detection failed closed")
        while cursor < len(data) and data[cursor] in _SECRET_WHITESPACE:
            cursor += 1
        if cursor == len(data):
            return None if final else "incomplete"
        secret_start = cursor
        if value_quote is not None:
            while cursor < len(data):
                if data[cursor] == 92:
                    if cursor + 1 == len(data):
                        if final:
                            raise SecretDetectionError(
                                "secret detection failed closed"
                            )
                        return "incomplete"
                    cursor += 2
                    continue
                if data[cursor] == value_quote:
                    break
                cursor += 1
            if cursor == len(data):
                if final:
                    raise SecretDetectionError("secret detection failed closed")
                return "incomplete"
        else:
            while cursor < len(data) and data[cursor] not in b"\r\n":
                cursor += 1
            if cursor == len(data) and not final:
                return "incomplete"
        if cursor == secret_start:
            raise SecretDetectionError("secret detection failed closed")
        match_end = (
            cursor + 1
            if value_quote is not None
            and cursor < len(data)
            and data[cursor] == value_quote
            else cursor
        )
        return (
            keyword_start,
            encoded_key_end,
            secret_start,
            cursor,
            match_end,
            scheme,
        )

    @staticmethod
    def _supported_scheme_candidate(
        data: bytes,
        index: int,
        *,
        final: bool,
    ) -> _SecretMatch | Literal["incomplete"] | None:
        """Recognize supported authorization credentials and preserve their scheme."""

        wrapper_quote = data[index] if data[index] in _QUOTE_BYTES else None
        keyword_start = index + 1 if wrapper_quote is not None else index
        available = data[keyword_start:].lower()
        matching_schemes = tuple(
            scheme
            for scheme in _SUPPORTED_AUTHORIZATION_SCHEMES
            if scheme.startswith(available)
        )
        if matching_schemes and all(len(available) < len(item) for item in matching_schemes):
            return None if final else "incomplete"
        scheme = next(
            (
                item
                for item in _SUPPORTED_AUTHORIZATION_SCHEMES
                if available[: len(item)] == item
            ),
            None,
        )
        if scheme is None:
            return None
        keyword_end = keyword_start + len(scheme)
        cursor = keyword_end
        if cursor == len(data):
            return None if final else "incomplete"
        if data[cursor] not in _SECRET_WHITESPACE:
            return None
        while cursor < len(data) and data[cursor] in _SECRET_WHITESPACE:
            cursor += 1
        if cursor == len(data):
            return None if final else "incomplete"
        secret_start = cursor
        while cursor < len(data) and data[cursor] not in _SECRET_TERMINATORS:
            cursor += 1
        if cursor == len(data) and not final:
            return "incomplete"
        if cursor == secret_start:
            return None
        return (
            keyword_start,
            keyword_end,
            secret_start,
            cursor,
            cursor,
            data[keyword_start:keyword_end],
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
        ingestion_evidence: IngestionWriteEvidence | None = None,
        retain_encrypted_raw: bool = False,
    ) -> SecureIngestionResult:
        try:
            return self._ingest_quarantined(
                reference,
                now=now,
                ingestion_evidence=ingestion_evidence,
                retain_encrypted_raw=retain_encrypted_raw,
            )
        except Exception as failure:
            failure.__traceback__ = None
        raise SecureIngestionError("secure ingestion failed closed")

    def _ingest_quarantined(
        self,
        reference: QuarantineReference,
        *,
        now: datetime,
        ingestion_evidence: IngestionWriteEvidence | None,
        retain_encrypted_raw: bool,
    ) -> SecureIngestionResult:
        """Run secret-bearing work outside the replacement exception frame."""

        raw = self._quarantine.resume(reference, now=now)
        detections: list[SecretDiscoveryReference] = []
        redacted = self._redact(
            raw,
            mission_id=reference.mission_id,
            source_execution_id=reference.execution_id,
            detections=detections,
            ingestion_evidence=ingestion_evidence,
            now=now,
        )
        redacted_reference = self._artifacts.put(
            mission_id=reference.mission_id,
            content=redacted,
            media_type="application/octet-stream",
            classification="sensitive" if detections else "normal",
            variant="redacted",
            source_execution_id=reference.execution_id,
            created_at=now,
            ingestion_evidence=ingestion_evidence,
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
                    source_execution_id=reference.execution_id,
                    created_at=now,
                    ingestion_evidence=ingestion_evidence,
                    derived_from_artifact_id=redacted_reference.artifact_id,
                ),
            )
        result = self._result(
            quarantine_id=reference.quarantine_id,
            quarantine_digest=reference.sha256,
            redacted_reference=redacted_reference,
            encrypted_raw=encrypted_raw,
            detections=detections,
        )
        self._quarantine.delete(reference, now=now)
        return result

    async def ingest_stream(
        self,
        sink: EncryptedRawResultSink,
        receipt: RawResultReceipt,
        *,
        now: datetime,
        retain_encrypted_raw: bool = False,
    ) -> SecureIngestionResult:
        """Decrypt and redact one committed quarantine stream with bounded raw memory."""

        try:
            return await self._ingest_committed_stream(
                sink,
                receipt,
                now=now,
                retain_encrypted_raw=retain_encrypted_raw,
            )
        except Exception as failure:
            failure.__traceback__ = None
        raise SecureIngestionError("secure ingestion failed closed")

    async def _ingest_committed_stream(
        self,
        sink: EncryptedRawResultSink,
        receipt: RawResultReceipt,
        *,
        now: datetime,
        retain_encrypted_raw: bool,
    ) -> SecureIngestionResult:
        if retain_encrypted_raw:
            raise SecureIngestionError(
                "chunked encrypted-raw retention is not configured"
            )
        durable_result = sink._durable_ingestion_result(receipt)
        if durable_result is not None:
            sink._delete_committed(now=now)
            return durable_result
        ingestion_evidence = self._artifacts.current_ingestion_evidence(
            receipt=receipt,
            now=now,
        )
        detections: list[SecretDiscoveryReference] = []

        def replace(keyword: bytes, secret_value: bytes) -> bytes:
            self._record_detection(
                keyword=keyword,
                secret_value=secret_value,
                mission_id=sink.binding.mission_id,
                source_execution_id=receipt.execution_id,
                detections=detections,
                ingestion_evidence=ingestion_evidence,
                now=now,
            )
            return b"[REDACTED]"

        redactor = _StreamingSecretRedactor(replace)

        async def redacted_chunks() -> AsyncIterator[bytes]:
            async for chunk in sink._iter_committed_chunks(receipt, now=now):
                redacted = redactor.feed(chunk)
                if redacted:
                    yield redacted
            final = redactor.feed(b"", final=True)
            if final:
                yield final

        redacted_reference = await self._artifacts.put_stream(
            mission_id=sink.binding.mission_id,
            chunks=redacted_chunks(),
            media_type="application/octet-stream",
            classification=lambda: "sensitive" if detections else "normal",
            variant="redacted",
            source_execution_id=receipt.execution_id,
            created_at=now,
            ingestion_evidence=ingestion_evidence,
            derived_from_artifact_id=None,
        )
        result = self._result(
            quarantine_id=receipt.quarantine_id,
            quarantine_digest=receipt.ciphertext_digest,
            redacted_reference=redacted_reference,
            encrypted_raw=(),
            detections=detections,
        )
        sink._commit_ingestion_result(receipt, result, now=now)
        sink._delete_committed(now=now)
        return result

    def _redact(
        self,
        raw: bytes,
        *,
        mission_id: str,
        source_execution_id: str,
        detections: list[SecretDiscoveryReference],
        ingestion_evidence: IngestionWriteEvidence | None,
        now: datetime,
    ) -> bytes:
        def replace(keyword: bytes, secret_value: bytes) -> bytes:
            self._record_detection(
                keyword=keyword,
                secret_value=secret_value,
                mission_id=mission_id,
                source_execution_id=source_execution_id,
                detections=detections,
                ingestion_evidence=ingestion_evidence,
                now=now,
            )
            return b"[REDACTED]"

        try:
            return _StreamingSecretRedactor(replace).feed(raw, final=True)
        except (SecretDetectionError, UnicodeError, ValueError) as exc:
            if isinstance(exc, SecretDetectionError):
                raise
            del exc
            raise SecretDetectionError("secret detection failed closed") from None

    def _record_detection(
        self,
        *,
        keyword: bytes,
        secret_value: bytes,
        mission_id: str,
        source_execution_id: str,
        detections: list[SecretDiscoveryReference],
        ingestion_evidence: IngestionWriteEvidence | None,
        now: datetime,
    ) -> None:
        credential_type = keyword.decode("ascii").lower().replace("-", "_")
        secret = self._secrets.create(
            mission_id=mission_id,
            secret_value=secret_value,
            credential_type=credential_type,
            associated_principal_ref=None,
            source_execution_id=source_execution_id,
            created_at=now,
            ingestion_evidence=ingestion_evidence,
        )
        detections.append(
            SecretDiscoveryReference(
                secret_reference_id=secret.secret_reference_id,
                credential_type=secret.credential_type,
                associated_principal_ref=secret.associated_principal_ref,
                source_execution_id=source_execution_id,
                verification_state=secret.verification_state,
            )
        )

    def _result(
        self,
        *,
        quarantine_id: str,
        quarantine_digest: str,
        redacted_reference: ArtifactReference,
        encrypted_raw: tuple[ArtifactReference, ...],
        detections: list[SecretDiscoveryReference],
    ) -> SecureIngestionResult:
        ingestion_id = stable_id(
            "secureingestion",
            {
                "quarantine_id": quarantine_id,
                "quarantine_sha256": quarantine_digest,
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
        return SecureIngestionResult(
            ingestion_id=ingestion_id,
            ingestion_digest=sha256_digest(digest_payload),
            redacted_artifacts=(redacted_reference,),
            encrypted_raw_artifacts=encrypted_raw,
            detected_secrets=tuple(detections),
            redaction_metadata=redaction_metadata,
        )


class EncryptedSecureResultIngester:
    """Executor ingestion adapter that resolves only the receipt-bound durable sink."""

    def __init__(
        self,
        *,
        ingestor: SecureIngestor,
        sinks: EncryptedRawResultSinkFactory,
        clock: Callable[[], datetime],
        retain_encrypted_raw: bool = False,
    ) -> None:
        self._ingestor = ingestor
        self._sinks = sinks
        self._clock = clock
        self._retain_encrypted_raw = retain_encrypted_raw

    async def ingest(self, receipt: RawResultReceipt) -> SecureIngestionSummary:
        sink = self._sinks.for_execution(receipt.execution_id)
        result = await self._ingestor.ingest_stream(
            sink,
            receipt,
            now=self._clock(),
            retain_encrypted_raw=self._retain_encrypted_raw,
        )
        return SecureIngestionSummary(
            secure_ingestion_id=result.ingestion_id,
            redacted_artifact_references=tuple(
                artifact.artifact_id for artifact in result.redacted_artifacts
            ),
        )

    async def acknowledge_persisted(
        self,
        receipt: RawResultReceipt,
        result: ExecutionResult,
    ) -> None:
        sink = self._sinks.for_execution(receipt.execution_id)
        sink._acknowledge_persisted(
            receipt,
            result,
            now=self._clock(),
        )
