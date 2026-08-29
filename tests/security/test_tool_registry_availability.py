from __future__ import annotations

import pytest
from pydantic import ValidationError

from redteam_agent.errors import DigestIntegrityError, TargetExtractorResolutionError
from redteam_agent.models.capabilities import AdapterCapabilities
from redteam_agent.models.tools import ToolDefinition
from redteam_agent.repositories import (
    AvailableToolSnapshotRepository,
)
from redteam_agent.seeds import (
    FIXED_TIME,
    mock_capability_snapshots,
    mock_mission,
    mock_network_tool,
)
from redteam_agent.storage import Database
from redteam_agent.tools import (
    ToolAvailabilityResolver,
    TrustedTargetExtractorRegistry,
    build_registry_revision,
)
from redteam_agent.tools.capability_snapshots import build_adapter_snapshot


def test_tool_timeout_invariant() -> None:
    data = mock_network_tool().model_dump(mode="python")
    data["default_timeout_seconds"] = 31
    data["max_timeout_seconds"] = 30
    with pytest.raises(ValidationError):
        ToolDefinition.model_validate(data)


def test_unregistered_extractor_fails_closed_and_no_dynamic_import_api() -> None:
    registry = TrustedTargetExtractorRegistry()
    with pytest.raises(TargetExtractorResolutionError):
        registry.resolve("os.system")
    assert not hasattr(registry, "import_module")
    assert not hasattr(registry, "register")


def test_unsupported_adapter_excludes_tool() -> None:
    mission = mock_mission()
    tool = mock_network_tool()
    extractors = TrustedTargetExtractorRegistry()
    registry = build_registry_revision(
        registry_revision=1, tools=(tool,), created_at=FIXED_TIME, extractors=extractors
    )
    session, _, sandbox, remote = mock_capability_snapshots(mission.mission_id)
    adapter = build_adapter_snapshot(
        adapters=(
            AdapterCapabilities(
                adapter_type="local",
                adapter_id="mock-local-adapter",
                runtime_id="mock-local-runtime",
                capabilities=frozenset(),
                provider_tool_catalog_digest="sha256:catalog",
                supported_os=frozenset({"linux"}),
                supported_architectures=frozenset({"x86_64"}),
                available=False,
            ),
        ),
        source="test",
        created_at=FIXED_TIME,
    )
    calculation = ToolAvailabilityResolver(extractors).calculate(
        mission=mission,
        registry=registry,
        session_snapshot=session,
        adapter_snapshot=adapter,
        sandbox_snapshot=sandbox,
        remote_trust_snapshot=remote,
        policy_version="policy-v1",
    )
    assert calculation.tools == ()


def test_availability_calculation_has_no_concrete_target_input() -> None:
    parameters = ToolAvailabilityResolver.calculate.__annotations__
    assert "target" not in parameters
    assert "requested_targets" not in parameters


def test_same_availability_input_has_same_id_and_digest() -> None:
    from tests.helpers import build_environment

    first = build_environment()
    second = build_environment(target="10.0.0.200")
    assert first.snapshot.snapshot_id == second.snapshot.snapshot_id
    assert first.snapshot.snapshot_digest == second.snapshot.snapshot_digest


def test_snapshot_repository_rejects_same_id_different_payload() -> None:
    from tests.helpers import build_environment

    environment = build_environment()
    with Database() as database:
        from tests.helpers import persist_environment

        persist_environment(database, environment)
        repository = AvailableToolSnapshotRepository(database)
        changed = environment.snapshot.model_copy(update={"snapshot_digest": "sha256:different"})
        with pytest.raises(DigestIntegrityError):
            repository.add(changed)
