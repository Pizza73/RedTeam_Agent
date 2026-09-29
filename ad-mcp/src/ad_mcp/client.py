"""Persistent stdio client used by the RedTeam Agent adapter.

The shared project token is held by this client and inserted into request
metadata. It is never part of a tool argument or model-visible schema.
"""

from __future__ import annotations

import asyncio
import base64
import threading
from collections.abc import Coroutine, Mapping
from concurrent.futures import TimeoutError as FutureTimeoutError
from typing import Any, TypeVar, cast

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.types import RequestParamsMeta

from ad_mcp.auth import AUTH_META_KEY, SECRET_META_KEY
from ad_mcp.errors import ConfigurationError

T = TypeVar("T")


class ProjectStdioClient:
    def __init__(
        self,
        *,
        argv: tuple[str, ...],
        environment: Mapping[str, str],
        client_id: str,
        project_token: str,
        startup_timeout_seconds: float = 15,
    ) -> None:
        if not argv or not argv[0].startswith("/") or len(project_token) < 32:
            raise ConfigurationError("CLIENT_CONFIGURATION_INVALID")
        self._argv = argv
        self._environment = dict(environment)
        self._environment["AD_MCP_PROJECT_TOKEN"] = project_token
        self._client_id = client_id
        self._token = project_token
        self._ready = threading.Event()
        self._startup_error: BaseException | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._session: ClientSession | None = None
        self._close_event: asyncio.Event | None = None
        self._thread = threading.Thread(target=self._thread_main, daemon=True)
        self._thread.start()
        if not self._ready.wait(startup_timeout_seconds):
            raise ConfigurationError("MCP_CLIENT_START_TIMEOUT")
        if self._startup_error is not None:
            raise ConfigurationError("MCP_CLIENT_START_FAILED") from self._startup_error

    def _thread_main(self) -> None:
        try:
            asyncio.run(self._serve())
        except BaseException as exc:
            self._startup_error = exc
            self._ready.set()

    async def _serve(self) -> None:
        parameters = StdioServerParameters(
            command=self._argv[0],
            args=list(self._argv[1:]),
            env=self._environment,
        )
        async with (
            stdio_client(parameters) as (read_stream, write_stream),
            ClientSession(read_stream, write_stream) as session,
        ):
            await session.initialize()
            self._loop = asyncio.get_running_loop()
            self._session = session
            self._close_event = asyncio.Event()
            self._ready.set()
            await self._close_event.wait()

    def list_tools(self, *, timeout_seconds: float = 15) -> dict[str, dict[str, object]]:
        async def invoke() -> dict[str, dict[str, object]]:
            assert self._session is not None
            result = await self._session.list_tools()
            return {tool.name: dict(tool.input_schema) for tool in result.tools}

        return self._submit(invoke(), timeout_seconds)

    def call_tool(
        self,
        name: str,
        arguments: dict[str, object],
        authorization: dict[str, object],
        secret_bindings: tuple[dict[str, str], ...] = (),
        *,
        timeout_seconds: float = 30,
    ) -> dict[str, object]:
        meta: dict[str, object] = {
            AUTH_META_KEY: {
                **authorization,
                "client_id": self._client_id,
                "token": self._token,
            }
        }
        if secret_bindings:
            meta[SECRET_META_KEY] = list(secret_bindings)

        async def invoke() -> dict[str, object]:
            assert self._session is not None
            result = await self._session.call_tool(
                name,
                arguments=cast(dict[str, Any], arguments),
                meta=cast(RequestParamsMeta, meta),
            )
            if getattr(result, "is_error", False):
                raise ConfigurationError("MCP_TOOL_CALL_FAILED")
            structured = getattr(result, "structured_content", None)
            if not isinstance(structured, dict):
                raise ConfigurationError("MCP_STRUCTURED_RESULT_MISSING")
            return dict(structured)

        return self._submit(invoke(), timeout_seconds)

    def encode_secret(
        self, *, argument_name: str, secret_version_id: str, material: bytes
    ) -> dict[str, str]:
        return {
            "argumentName": argument_name,
            "secretVersionId": secret_version_id,
            "encoding": "base64",
            "material": base64.b64encode(material).decode("ascii"),
        }

    def close(self, *, timeout_seconds: float = 5) -> None:
        if self._loop is None or self._close_event is None:
            return
        self._loop.call_soon_threadsafe(self._close_event.set)
        self._thread.join(timeout_seconds)

    def _submit(self, coroutine: Coroutine[Any, Any, T], timeout_seconds: float) -> T:
        if self._loop is None or self._session is None:
            raise ConfigurationError("MCP_CLIENT_NOT_READY")
        future = asyncio.run_coroutine_threadsafe(coroutine, self._loop)
        try:
            return future.result(timeout_seconds)
        except FutureTimeoutError as exc:
            future.cancel()
            raise ConfigurationError("MCP_CLIENT_CALL_TIMEOUT") from exc
