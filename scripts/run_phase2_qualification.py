#!/usr/bin/env python3
"""Run the attested Gemma capability check and optional formal D11 qualification."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from datetime import UTC, datetime
from pathlib import Path

from redteam_agent.composition.phase2 import build_phase2_kernel
from redteam_agent.llm.artifact_manifest import load_and_verify_remote_model_artifact_manifest
from redteam_agent.llm.attestation import HttpServerMetadataProvider, SignedManifestArtifactSource
from redteam_agent.llm.client import VLLMChatClient
from redteam_agent.llm.config import LocalLLMEndpointConfig
from redteam_agent.llm.evaluation import TimedInFlightCancellation
from redteam_agent.llm.profile import build_local_llm_profile
from redteam_agent.llm.secrets import FileAPIKeySource
from redteam_agent.llm.tokenizer import HuggingFaceTokenCounter


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "mode", choices=("capability", "fixture", "qualification"), nargs="?", default="qualification"
    )
    parser.add_argument("--base-url", default="http://10.0.6.181:8100/v1")
    parser.add_argument("--model", default="gemma-4-31B-it")
    parser.add_argument("--api-key-file", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--public-key", type=Path, required=True)
    parser.add_argument("--manifest-key-id", default="llm001-gemma4-2026")
    parser.add_argument("--tokenizer-directory", type=Path, required=True)
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--profile-revision", default="gemma-4-31b-it-vllm-0.25.1-r2")
    parser.add_argument("--max-context-tokens", type=int, default=131072)
    parser.add_argument("--max-output-tokens", type=int, default=1024)
    parser.add_argument("--parallel", type=int, default=4)
    parser.add_argument("--fixture-id", default="aqp-f01-x00")
    return parser.parse_args()


def _git_commit() -> str:
    root = Path(__file__).resolve().parents[1]
    status = subprocess.run(
        ["git", "status", "--porcelain"], cwd=root, check=True, capture_output=True, text=True
    ).stdout
    if status:
        raise SystemExit("formal Phase 2 evaluation requires a clean, committed worktree")
    return subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=root, check=True, capture_output=True, text=True
    ).stdout.strip()


def _sha256(path: Path) -> str:
    return hashlib.file_digest(path.open("rb"), "sha256").hexdigest()


def main() -> int:
    args = _arguments()
    root = Path(__file__).resolve().parents[1]
    for path in (
        args.api_key_file,
        args.manifest,
        args.public_key,
        args.tokenizer_directory,
        args.database.parent,
        args.report.parent,
    ):
        if not path.is_absolute():
            raise SystemExit("all credential, artifact, database, and report paths must be absolute")
    if args.database.exists() or args.report.exists():
        raise SystemExit("database and report outputs must be new paths (existing evidence is never overwritten)")

    commit = _git_commit()
    lock_digest = _sha256(root / "requirements.lock")
    endpoint = LocalLLMEndpointConfig(
        base_url=args.base_url,
        model=args.model,
        api_key_file=str(args.api_key_file),
        request_timeout_seconds=120,
    )
    kernel = build_phase2_kernel(
        endpoint=endpoint,
        qualification_commit_id=commit,
        dependency_lock_digest=lock_digest,
        db_path=str(args.database),
    )
    ds = kernel.phase1.phase0c.phase0b.phase0a.digest_service
    manifest = load_and_verify_remote_model_artifact_manifest(
        manifest_path=args.manifest,
        public_key_path=args.public_key,
        expected_key_id=args.manifest_key_id,
        digest_service=ds,
    )
    profile = build_local_llm_profile(
        profile_revision=args.profile_revision,
        max_context_tokens=args.max_context_tokens,
        max_output_tokens=args.max_output_tokens,
        model_name=manifest.served_model_id,
        model_hash=manifest.model_hash,
        chat_template_digest=manifest.chat_template_digest,
        tokenizer_revision=manifest.tokenizer_revision,
        runtime_version=manifest.runtime_version,
        digest_service=ds,
    )
    key_source = FileAPIKeySource(args.api_key_file)
    artifact_source = SignedManifestArtifactSource(
        manifest_path=args.manifest,
        public_key_path=args.public_key,
        expected_key_id=args.manifest_key_id,
        digest_service=ds,
    )
    attestation = kernel.attest_server(
        profile=profile,
        provider=HttpServerMetadataProvider(api_key_source=key_source),
        artifact_source=artifact_source,
        timeout_seconds=60,
    )
    counter = HuggingFaceTokenCounter(
        model_directory=args.tokenizer_directory,
        tokenizer_revision=profile.tokenizer_revision,
        chat_template_digest=profile.chat_template_digest,
    )
    client = VLLMChatClient(base_url=args.base_url, api_key_source=key_source)
    probe = kernel.build_live_capability_probe(
        profile=profile,
        policy=kernel.request_budget_policy(profile),
        client=client,
        token_counter=counter,
        run_id=f"phase2-capability-{commit}",
        cancellation=TimedInFlightCancellation(delay_seconds=0.01),
        attestation=attestation,
    )
    results = kernel.run_capability_evaluation(profile=profile, probe=probe)
    binding = kernel.build_evaluation_binding(
        profile=profile, capability_results=results, attestation=attestation
    )

    payload: dict[str, object] = {
        "recorded_at": datetime.now(tz=UTC).isoformat(),
        "mode": args.mode,
        "commit_id": commit,
        "dependency_lock_digest": lock_digest,
        "profile_digest": profile.profile_digest,
        "server_attestation": attestation.model_dump(mode="json"),
        "capability_results": [result.model_dump(mode="json") for result in results],
        "evaluation_binding": binding.model_dump(mode="json"),
    }
    if args.mode != "capability":
        driver = kernel.build_isolated_workflow_quality_driver(
            profile=profile,
            policy=kernel.request_budget_policy(profile),
            client=client,
            token_counter=counter,
            evaluation_binding=binding,
            capability_results=results,
            attestation=attestation,
            max_parallel_runs=args.parallel,
        )
        if args.mode == "fixture":
            fixtures = {fixture.fixture_id: fixture for fixture in kernel.quality_corpus.all_fixtures()}
            fixture = fixtures.get(args.fixture_id)
            if fixture is None:
                raise SystemExit("unknown fixture id")
            payload["fixture_observation"] = driver.drive(fixture, 0).model_dump(mode="json")
        else:
            report = kernel.qualify_real_local_llm(
                profile=profile,
                driver=driver,
                evaluation_binding=binding,
                capability_results=results,
                attestation=attestation,
            )
            payload["quality_report"] = report.model_dump(mode="json")

    with args.report.open("x", encoding="utf-8") as handle:
        json.dump(payload, handle, sort_keys=True, indent=2)
        handle.write("\n")
    print(json.dumps({
        "mode": args.mode,
        "profile_digest": profile.profile_digest,
        "attestation_digest": attestation.attestation_digest,
        "capability_passed": all(result.passed for result in results),
        "report": str(args.report),
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
