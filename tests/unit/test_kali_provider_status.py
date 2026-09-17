from __future__ import annotations

from redteam_agent.ui.kali_provider_status import KaliProviderStatusPort


def test_kali_provider_status_is_fail_closed_and_does_not_require_live_access(tmp_path) -> None:
    credential = tmp_path / "sliver.cfg"
    credential.write_text("not-read-by-status-port", encoding="utf-8")
    executable = tmp_path / "redteam-impacket-mcp"
    executable.write_text("placeholder", encoding="utf-8")
    executable.chmod(0o700)
    status = KaliProviderStatusPort(
        sliver_credential=credential,
        impacket_executable=executable,
        impacket_allowed_targets=("10.0.10.212/32",),
    )()

    assert status["runtime"]["missionExecutionEnabled"] is False
    assert status["runtime"]["tpmKeyProviderAttested"] is False
    assert status["sliver"]["credentialPresent"] is True
    assert status["sliver"]["identityAttested"] is False
    assert status["sliver"]["beaconPresent"] is False
    assert status["impacket"]["executablePresent"] is True
    assert status["impacket"]["sandboxAttested"] is False
    assert status["impacket"]["allowedTargets"] == ["10.0.10.212/32"]
