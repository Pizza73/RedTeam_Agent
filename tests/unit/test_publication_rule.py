"""Fixed output publication rule: bounded parse, allowlist, secret redaction (SystemDesign §33.0)."""

from __future__ import annotations

import pytest

from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.errors import OutputPublicationError
from redteam_agent.ingestion.publication_rule import OutputPublicationParser, OutputPublicationRuleCatalog


def _rule(**kw: object):
    catalog = OutputPublicationRuleCatalog(DigestService())
    return catalog.register(
        rule_id="pub-1", parser_id="json_object_v1",
        public_field_types={"host": "string", "status": "string", "port": "integer"},
        secret_field_pointers=("/credential",), **kw,  # type: ignore[arg-type]
    )


def test_allowlisted_fields_published_secret_redacted() -> None:
    parser = OutputPublicationParser()
    parsed = parser.parse(_rule(), b'{"host": "h", "status": "open", "port": 443, "credential": "topsecretvalue"}')
    assert len(parsed.redacted_records) == 1
    record = parsed.redacted_records[0]
    assert record["credential"] == "[REDACTED-SECRET]" and "topsecretvalue" not in str(record)
    assert len(parsed.detected_secrets) == 1 and parsed.detected_secrets[0].value == b"topsecretvalue"


def test_unknown_field_not_publishable() -> None:
    parser = OutputPublicationParser()
    with pytest.raises(OutputPublicationError):
        parser.parse(_rule(), b'{"host": "h", "status": "open", "port": 443, "credential": "s", "extra": "x"}')


def test_type_mismatch_not_publishable() -> None:
    parser = OutputPublicationParser()
    with pytest.raises(OutputPublicationError):
        parser.parse(_rule(), b'{"host": "h", "status": "open", "port": "not-an-int", "credential": "s"}')


def test_invalid_utf8_not_publishable() -> None:
    parser = OutputPublicationParser()
    with pytest.raises(OutputPublicationError):
        parser.parse(_rule(), b"\xff\xfe not utf-8")


def test_duplicate_key_not_publishable() -> None:
    parser = OutputPublicationParser()
    with pytest.raises(OutputPublicationError):
        parser.parse(_rule(), b'{"host": "a", "host": "b", "status": "open", "port": 1, "credential": "s"}')


def test_oversize_record_not_publishable() -> None:
    parser = OutputPublicationParser()
    big = '{"host": "' + "h" * 200 + '", "status": "open", "port": 1, "credential": "s"}'
    with pytest.raises(OutputPublicationError):
        parser.parse(_rule(max_record_bytes=64), big.encode("utf-8"))


def test_too_many_secret_versions_not_publishable() -> None:
    parser = OutputPublicationParser()
    with pytest.raises(OutputPublicationError):
        parser.parse(_rule(max_secret_versions=0), b'{"host": "h", "status": "open", "port": 1, "credential": "s"}')


def test_unregistered_rule_fails_closed() -> None:
    catalog = OutputPublicationRuleCatalog(DigestService())
    with pytest.raises(OutputPublicationError):
        catalog.get("nope")
