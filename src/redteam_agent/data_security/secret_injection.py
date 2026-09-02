"""Purpose-bound just-in-time Secret injection for trusted adapter channels."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from typing import Protocol, final

from redteam_agent.errors import SecretAccessError
from redteam_agent.models.execution import DispatchClaim
from redteam_agent.repositories import DispatchClaimRepository

from .models import SecretReferenceMetadata
from .stores import _SECRET_INJECTION_TOKEN, SecretStore


class SecretAdapterChannel(Protocol):
    """Fixed adapter-side channel; it never returns plaintext to the caller."""

    def inject(
        self,
        *,
        execution_id: str,
        secret_reference_id: str,
        value: memoryview,
    ) -> None: ...


@final
class TrustedSecretChannelRegistry:
    """Composition-root registry keyed only by the authorized adapter identity."""

    def __init__(self, channels: dict[str, SecretAdapterChannel]) -> None:
        if not channels or any(not key or value is None for key, value in channels.items()):
            raise SecretAccessError("trusted Secret channel registry is invalid")
        self._channels = dict(channels)

    def resolve(self, adapter_id: str) -> SecretAdapterChannel:
        channel = self._channels.get(adapter_id)
        if channel is None:
            raise SecretAccessError("authorized Secret adapter channel is unavailable")
        return channel


@final
class SecretInjectionBroker:
    """Resolve and inject one Secret only under the current Dispatch Claim."""

    def __init__(
        self,
        *,
        store: SecretStore,
        claims: DispatchClaimRepository,
        channels: TrustedSecretChannelRegistry,
        clock: Callable[[], datetime],
    ) -> None:
        if (
            type(store) is not SecretStore
            or type(claims) is not DispatchClaimRepository
            or type(channels) is not TrustedSecretChannelRegistry
            or not callable(clock)
        ):
            raise SecretAccessError("trusted Secret injection dependencies are required")
        self._store = store
        self._claims = claims
        self._channels = channels
        self._clock = clock

    def inject(
        self,
        *,
        execution_id: str,
        reference: SecretReferenceMetadata,
        now: datetime,
    ) -> DispatchClaim:
        del now
        current_time = self._clock()
        if current_time.tzinfo is None or current_time.utcoffset() is None:
            raise SecretAccessError("trusted Secret injection clock is invalid")
        try:
            claim = self._claims.current_for_injection(
                execution_id,
                now=current_time,
            )
        except Exception as failure:
            failure.__traceback__ = None
            raise SecretAccessError("current Dispatch Claim is unavailable") from None
        channel = self._channels.resolve(claim.adapter_id)
        plaintext: bytearray | None = None
        attempted_resolution = False
        pending_error: SecretAccessError | None = None
        try:
            attempted_resolution = True
            plaintext = self._store._resolve_for_injection(
                reference,
                claim=claim,
                now=current_time,
                token=_SECRET_INJECTION_TOKEN,
            )
            channel.inject(
                execution_id=claim.execution_id,
                secret_reference_id=reference.secret_reference_id,
                value=memoryview(plaintext),
            )
        except SecretAccessError as failure:
            failure.__traceback__ = None
            pending_error = SecretAccessError("Secret injection was denied")
        except Exception as failure:
            failure.__traceback__ = None
            pending_error = SecretAccessError("Secret injection failed closed")
        finally:
            if plaintext is not None:
                plaintext[:] = b"\x00" * len(plaintext)
        if attempted_resolution:
            try:
                self._claims.consume(execution_id, now=current_time)
            except Exception as failure:
                failure.__traceback__ = None
                raise SecretAccessError(
                    "Dispatch Claim consumption failed closed"
                ) from None
        if pending_error is not None:
            raise pending_error
        consumed = self._claims.get_by_execution(execution_id)
        if consumed is None or consumed.consumed_at != current_time:
            raise SecretAccessError("Dispatch Claim consumption was not durable")
        return consumed
