from __future__ import annotations

from datetime import timedelta

import pytest

import support
from redteam_agent.ui.auth import (
    OperatorSessionAuthenticator,
    UIAuthenticationError,
    read_operator_token,
)


def test_operator_session_uses_one_time_login_exchange_and_expiry() -> None:
    current = [support.T0]
    raw = bytearray(b"a" * 32)
    authenticator = OperatorSessionAuthenticator(
        principal_id="redteam-operator",
        operator_token=raw,
        session_ttl_seconds=60,
        clock=lambda: current[0],
        token_factory=lambda: "s" * 32,
    )
    assert raw == bytearray(32)

    session_id, session = authenticator.login("a" * 32)
    assert session_id == "s" * 32
    assert session.principal_id == "redteam-operator"
    assert authenticator.authenticate(session_id) == session

    current[0] = support.T0 + timedelta(seconds=60)
    assert authenticator.authenticate(session_id) is None


def test_operator_session_rejects_wrong_token_without_retaining_it() -> None:
    authenticator = OperatorSessionAuthenticator(
        principal_id="redteam-operator",
        operator_token=bytearray(b"a" * 32),
    )
    with pytest.raises(UIAuthenticationError, match="credential is invalid"):
        authenticator.login("b" * 32)


def test_operator_token_file_must_be_owner_private_and_not_a_symlink(tmp_path) -> None:
    token_path = tmp_path / "operator.token"
    token_path.write_bytes(b"a" * 32 + b"\n")
    token_path.chmod(0o600)
    value = read_operator_token(token_path)
    assert value == bytearray(b"a" * 32)

    token_path.chmod(0o644)
    with pytest.raises(UIAuthenticationError, match="mode is unsafe"):
        read_operator_token(token_path)

    token_path.chmod(0o600)
    link = tmp_path / "operator-link"
    link.symlink_to(token_path)
    with pytest.raises(UIAuthenticationError, match="unavailable"):
        read_operator_token(link)


def test_operator_token_file_rejects_non_textual_credentials(tmp_path) -> None:
    token_path = tmp_path / "operator.token"
    token_path.write_bytes(bytes(range(32)))
    token_path.chmod(0o600)
    with pytest.raises(UIAuthenticationError, match="printable ASCII"):
        read_operator_token(token_path)
