"""Project-only caller and ephemeral-secret validation."""

from __future__ import annotations

import base64
import binascii
import hmac
from collections.abc import Mapping
from typing import Any, NoReturn

from ad_mcp.catalog import CATALOG_REVISION
from ad_mcp.errors import AuthorizationError
from ad_mcp.models import ProjectAuthorization

AUTH_META_KEY = "io.redteam-agent/projectAuthorization"
SECRET_META_KEY = "io.redteam-agent/ephemeralSecretBindings"
MAX_SECRET_BYTES = 64 * 1024


class EphemeralSecret:
    __slots__ = ("argument_name", "material", "secret_version_id")

    def __init__(self, argument_name: str, secret_version_id: str, material: bytearray) -> None:
        self.argument_name = argument_name
        self.secret_version_id = secret_version_id
        self.material = material

    def zeroize(self) -> None:
        for index in range(len(self.material)):
            self.material[index] = 0

    def __repr__(self) -> str:
        return "<EphemeralSecret material=<redacted>>"

    def __reduce__(self) -> NoReturn:
        raise TypeError("ephemeral secrets are not serializable")


def authorize_meta(
    meta: Mapping[str, Any] | None, *, expected_client_id: str, expected_token: str
) -> tuple[ProjectAuthorization, tuple[EphemeralSecret, ...]]:
    if meta is None:
        raise AuthorizationError("PROJECT_AUTH_MISSING")
    raw_auth = meta.get(AUTH_META_KEY)
    if not isinstance(raw_auth, dict):
        raise AuthorizationError("PROJECT_AUTH_MISSING")
    try:
        auth = ProjectAuthorization.model_validate(raw_auth)
    except ValueError as exc:
        raise AuthorizationError("PROJECT_AUTH_INVALID") from exc
    if (
        auth.client_id != expected_client_id
        or auth.catalog_revision != CATALOG_REVISION
        or not hmac.compare_digest(auth.token.get_secret_value(), expected_token)
    ):
        raise AuthorizationError("PROJECT_AUTH_REJECTED")
    return auth, _parse_secrets(meta.get(SECRET_META_KEY, []))


def _parse_secrets(value: object) -> tuple[EphemeralSecret, ...]:
    if not isinstance(value, list) or len(value) > 8:
        raise AuthorizationError("SECRET_BINDINGS_INVALID")
    parsed: list[EphemeralSecret] = []
    try:
        for item in value:
            if not isinstance(item, dict) or set(item) != {
                "argumentName",
                "secretVersionId",
                "encoding",
                "material",
            }:
                raise AuthorizationError("SECRET_BINDING_INVALID")
            if (
                not isinstance(item["argumentName"], str)
                or not isinstance(item["secretVersionId"], str)
                or item["encoding"] != "base64"
                or not isinstance(item["material"], str)
            ):
                raise AuthorizationError("SECRET_BINDING_INVALID")
            try:
                material = bytearray(base64.b64decode(item["material"], validate=True))
            except (ValueError, binascii.Error) as exc:
                raise AuthorizationError("SECRET_BINDING_ENCODING_INVALID") from exc
            if not material or len(material) > MAX_SECRET_BYTES:
                material[:] = b"\x00" * len(material)
                raise AuthorizationError("SECRET_BINDING_SIZE_INVALID")
            parsed.append(
                EphemeralSecret(item["argumentName"], item["secretVersionId"], material)
            )
    except Exception:
        for secret in parsed:
            secret.zeroize()
        raise
    return tuple(parsed)


def zeroize_all(secrets: tuple[EphemeralSecret, ...]) -> None:
    for secret in secrets:
        secret.zeroize()
