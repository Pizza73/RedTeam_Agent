import base64

import pytest

from ad_mcp.auth import AUTH_META_KEY, SECRET_META_KEY, authorize_meta, zeroize_all
from ad_mcp.catalog import CATALOG_REVISION
from ad_mcp.config import ScopeConfig
from ad_mcp.errors import AuthorizationError, ScopeError
from ad_mcp.scope import ScopePolicy


def _meta(token: str = "x" * 32) -> dict[str, object]:
    return {
        AUTH_META_KEY: {
            "client_id": "redteam-agent",
            "actor_id": "operator-1",
            "mission_id": "mission-1",
            "execution_id": "execution-1",
            "approval_id": None,
            "catalog_revision": CATALOG_REVISION,
            "token": token,
        }
    }


def test_project_auth_and_secret_zeroization() -> None:
    meta = _meta()
    meta[SECRET_META_KEY] = [
        {
            "argumentName": "credential",
            "secretVersionId": "secret-v1",
            "encoding": "base64",
            "material": base64.b64encode(b"temporary-password").decode(),
        }
    ]
    auth, secrets = authorize_meta(
        meta, expected_client_id="redteam-agent", expected_token="x" * 32
    )
    assert auth.execution_id == "execution-1"
    assert bytes(secrets[0].material) == b"temporary-password"
    zeroize_all(secrets)
    assert not any(secrets[0].material)


def test_direct_or_wrong_client_is_rejected() -> None:
    with pytest.raises(AuthorizationError, match="PROJECT_AUTH_MISSING"):
        authorize_meta(None, expected_client_id="redteam-agent", expected_token="x" * 32)
    with pytest.raises(AuthorizationError, match="PROJECT_AUTH_REJECTED"):
        authorize_meta(_meta("y" * 32), expected_client_id="redteam-agent", expected_token="x" * 32)


def test_scope_accepts_only_canonical_in_range_ips_and_approved_domains() -> None:
    policy = ScopePolicy(
        ScopeConfig(
            schema_version="ad-mcp-scope-v1",
            cidrs=("192.0.2.0/24",),
            domains=("lab.example",),
            hosts=("dc.external.example",),
        )
    )
    assert policy.authorize_targets(("192.0.2.10",), required=True, maximum=2) == (
        "192.0.2.10",
    )
    assert policy.authorize_domain("child.lab.example") == "child.lab.example"
    with pytest.raises(ScopeError, match="TARGET_IP_REQUIRED"):
        policy.authorize_targets(("dc01.lab.example",), required=True, maximum=2)
    with pytest.raises(ScopeError, match="TARGET_OUT_OF_SCOPE"):
        policy.authorize_targets(("198.51.100.10",), required=True, maximum=2)
    with pytest.raises(ScopeError, match="DOMAIN_OUT_OF_SCOPE"):
        policy.authorize_domain("example.net")
