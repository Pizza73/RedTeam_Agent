"""Bounded, read-only Fortra Impacket operations used by the MCP server."""

from __future__ import annotations

import importlib
import re
from contextlib import suppress
from typing import Any, NoReturn, Protocol


class ImpacketBackendError(RuntimeError):
    """Content-free provider failure safe to return across the MCP boundary."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class ImpacketCredential:
    """One-request credential value with redacted diagnostics."""

    __slots__ = ("credential_type", "domain", "lmhash", "nthash", "password", "username")

    def __init__(
        self,
        *,
        credential_type: str,
        username: str,
        domain: str,
        password: str = "",
        lmhash: str = "",
        nthash: str = "",
    ) -> None:
        self.credential_type = credential_type
        self.username = username
        self.domain = domain
        self.password = password
        self.lmhash = lmhash
        self.nthash = nthash

    def __repr__(self) -> str:
        return "<ImpacketCredential redacted>"

    def __reduce__(self) -> NoReturn:
        raise TypeError("ImpacketCredential is not serializable")


class ImpacketBackend(Protocol):
    def smb_negotiate(self, target: str, port: int, timeout: int) -> dict[str, object]: ...

    def smb_authenticate(
        self, target: str, port: int, timeout: int, credential: ImpacketCredential
    ) -> dict[str, object]: ...

    def smb_list_shares(
        self, target: str, port: int, timeout: int, credential: ImpacketCredential
    ) -> dict[str, object]: ...

    def rpc_endpoint_map(self, target: str, port: int, timeout: int) -> dict[str, object]: ...


class FortraImpacketBackend:
    """Lazy-loaded Impacket 0.13.1 backend.

    Only protocol negotiation, authentication validation, share enumeration,
    and endpoint-mapper enumeration are reachable.  No example script, shell,
    service creation, registry access, relay, or credential-dump primitive is
    imported or dispatched.
    """

    _MAX_SHARES = 256
    _MAX_ENDPOINTS = 512

    @staticmethod
    def _smb_class() -> Any:
        try:
            module = importlib.import_module("impacket.smbconnection")
            return module.SMBConnection
        except (ImportError, AttributeError) as exc:
            raise ImpacketBackendError("IMPACKET_UNAVAILABLE") from exc

    def _connect_smb(self, target: str, port: int, timeout: int) -> Any:
        try:
            connection = self._smb_class()(
                remoteName=target,
                remoteHost=target,
                sess_port=port,
                timeout=timeout,
            )
            dialect = connection.getDialect()
            if type(dialect) is not int or dialect < 0x0202:
                self._close_smb(connection)
                raise ImpacketBackendError("SMB1_NOT_ALLOWED")
            return connection
        except ImpacketBackendError:
            raise
        except TimeoutError as exc:
            raise ImpacketBackendError("TARGET_TIMEOUT") from exc
        except (ConnectionError, OSError) as exc:
            raise ImpacketBackendError("TARGET_UNREACHABLE") from exc
        except Exception as exc:
            raise ImpacketBackendError("SMB_NEGOTIATION_FAILED") from exc

    @staticmethod
    def _close_smb(connection: Any) -> None:
        with suppress(Exception):
            connection.close()

    @staticmethod
    def _login(connection: Any, credential: ImpacketCredential) -> None:
        try:
            connection.login(
                credential.username,
                credential.password,
                credential.domain,
                credential.lmhash,
                credential.nthash,
            )
        except Exception as exc:
            raise ImpacketBackendError("AUTHENTICATION_FAILED") from exc

    @staticmethod
    def _safe_provider_text(value: object, *, limit: int = 256) -> str:
        result = value.decode("utf-8", errors="replace") if isinstance(value, bytes) else str(value)
        result = "".join(
            character for character in result if ord(character) >= 32 or character == "\t"
        ).strip("\x00 ")
        return result[:limit]

    def smb_negotiate(self, target: str, port: int, timeout: int) -> dict[str, object]:
        connection = self._connect_smb(target, port, timeout)
        try:
            dialect = connection.getDialect()
            return {
                "target": target,
                "port": port,
                "dialect": f"0x{dialect:04x}",
                "server_name": self._safe_provider_text(connection.getServerName()),
                "server_domain": self._safe_provider_text(connection.getServerDomain()),
                "server_dns_domain": self._safe_provider_text(
                    connection.getServerDNSDomainName()
                ),
                "server_dns_host": self._safe_provider_text(
                    connection.getServerDNSHostName()
                ),
                "server_os": self._safe_provider_text(connection.getServerOS()),
                "signing_required": bool(connection.isSigningRequired()),
            }
        finally:
            self._close_smb(connection)

    def smb_authenticate(
        self, target: str, port: int, timeout: int, credential: ImpacketCredential
    ) -> dict[str, object]:
        connection = self._connect_smb(target, port, timeout)
        try:
            self._login(connection, credential)
            return {
                "target": target,
                "port": port,
                "authenticated": True,
                "credential_type": credential.credential_type,
            }
        finally:
            self._close_smb(connection)

    def smb_list_shares(
        self, target: str, port: int, timeout: int, credential: ImpacketCredential
    ) -> dict[str, object]:
        connection = self._connect_smb(target, port, timeout)
        try:
            self._login(connection, credential)
            raw_shares = list(connection.listShares())
            shares: list[dict[str, object]] = []
            for raw in raw_shares[: self._MAX_SHARES]:
                name = self._safe_provider_text(raw["shi1_netname"], limit=128)
                remark = self._safe_provider_text(raw["shi1_remark"], limit=512)
                share_type = int(raw["shi1_type"])
                shares.append({"name": name, "type": share_type, "remark": remark})
            return {
                "target": target,
                "port": port,
                "share_count": len(shares),
                "truncated": len(raw_shares) > self._MAX_SHARES,
                "shares": shares,
            }
        except ImpacketBackendError:
            raise
        except Exception as exc:
            raise ImpacketBackendError("SHARE_ENUMERATION_FAILED") from exc
        finally:
            self._close_smb(connection)

    def rpc_endpoint_map(self, target: str, port: int, timeout: int) -> dict[str, object]:
        dce: Any = None
        try:
            epm = importlib.import_module("impacket.dcerpc.v5.epm")
            transport = importlib.import_module("impacket.dcerpc.v5.transport")
            rpc_transport = transport.DCERPCTransportFactory(
                f"ncacn_ip_tcp:{target}[{port}]"
            )
            set_timeout = getattr(rpc_transport, "set_connect_timeout", None)
            if not callable(set_timeout):
                raise ImpacketBackendError("RPC_TIMEOUT_ENFORCEMENT_UNAVAILABLE")
            set_timeout(timeout)
            dce = rpc_transport.get_dce_rpc()
            dce.connect()
            entries = epm.hept_lookup(None, dce=dce)
            endpoints: list[dict[str, object]] = []
            for entry in list(entries)[: self._MAX_ENDPOINTS]:
                floors = entry["tower"]["Floors"]
                annotation = self._safe_provider_text(entry["annotation"], limit=512)
                interface = self._safe_provider_text(floors[0], limit=128) if floors else ""
                formatted_binding = epm.PrintStringBinding(floors)
                bindings = (
                    [self._safe_provider_text(formatted_binding, limit=256)]
                    if formatted_binding is not None
                    else []
                )
                endpoints.append(
                    {
                        "interface": interface,
                        "annotation": annotation,
                        "bindings": bindings[:16],
                    }
                )
            return {
                "target": target,
                "port": port,
                "endpoint_count": len(endpoints),
                "truncated": len(entries) > self._MAX_ENDPOINTS,
                "endpoints": endpoints,
            }
        except TimeoutError as exc:
            raise ImpacketBackendError("TARGET_TIMEOUT") from exc
        except (ImportError, AttributeError) as exc:
            raise ImpacketBackendError("IMPACKET_UNAVAILABLE") from exc
        except Exception as exc:
            raise ImpacketBackendError("RPC_ENDPOINT_ENUMERATION_FAILED") from exc
        finally:
            if dce is not None:
                with suppress(Exception):
                    dce.disconnect()


_NTLM_HASH_PATTERN = re.compile(r"^[0-9a-fA-F]{32}$")


def validate_ntlm_hash(value: str) -> bool:
    return _NTLM_HASH_PATTERN.fullmatch(value) is not None


__all__ = [
    "FortraImpacketBackend",
    "ImpacketBackend",
    "ImpacketBackendError",
    "ImpacketCredential",
    "validate_ntlm_hash",
]
