from __future__ import annotations

import os

import pytest

from redteam_agent.errors import LLMTransportError
from redteam_agent.llm.secrets import FileAPIKeySource, authorization_headers


def test_file_api_key_source_reads_owner_only_file(tmp_path) -> None:
    path = tmp_path / "key"
    path.write_text("secret-value\n")
    path.chmod(0o600)
    source = FileAPIKeySource(path)
    assert authorization_headers(source) == {"Authorization": "Bearer secret-value"}
    assert repr(source).__contains__("secret-value") is False


def test_file_api_key_source_rejects_broad_permissions_and_symlink(tmp_path) -> None:
    path = tmp_path / "key"
    path.write_text("secret")
    path.chmod(0o644)
    with pytest.raises(LLMTransportError):
        FileAPIKeySource(path).read()
    path.chmod(0o600)
    link = tmp_path / "link"
    os.symlink(path, link)
    with pytest.raises(LLMTransportError):
        FileAPIKeySource(link).read()


@pytest.mark.parametrize("body", ["", " leading", "trailing ", "one\ntwo"])
def test_file_api_key_source_rejects_malformed_body(tmp_path, body: str) -> None:
    path = tmp_path / "key"
    path.write_text(body)
    path.chmod(0o600)
    with pytest.raises(LLMTransportError):
        FileAPIKeySource(path).read()
