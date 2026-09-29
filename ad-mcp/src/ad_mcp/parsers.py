"""Fixed public-result parsers that never return raw provider text."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from ad_mcp.models import DetectionFinding, JobState, PublicResult, ToolDefinition, utc_now

_MARKERS: dict[str, tuple[bytes, ...]] = {
    "AD.SMB_SIGNING": (b"message_signing: disabled", b"signing:false", b"signing:disabled"),
    "AD.LDAP_SIGNING": (b"ldap signing: disabled", b"signing not required"),
    "AD.LDAP_CHANNEL_BINDING": (b"channel binding: disabled", b"channel binding not required"),
    "AD.SMB_ANONYMOUS": (b"anonymous login successful", b"guest session"),
    "AD.LDAP_ANONYMOUS": (b"anonymous bind successful",),
    "AD.ASREP_ROAST": (b"krb5asrep", b"doesn't require preauthentication"),
    "AD.KERBEROAST": (b"krb5tgs", b"serviceprincipalname"),
    "AD.ADCS_ESC1": (b"esc1",),
    "AD.ADCS_ESC2": (b"esc2",),
    "AD.ADCS_ESC3": (b"esc3",),
    "AD.ADCS_ESC4": (b"esc4",),
    "AD.ADCS_ESC5": (b"esc5",),
    "AD.ADCS_ESC6": (b"esc6",),
    "AD.ADCS_ESC7": (b"esc7",),
    "AD.ADCS_ESC8": (b"esc8",),
    "AD.COERCION_EXPOSURE": (b"vulnerable", b"coercion method"),
    "AD.MACHINE_ACCOUNT_QUOTA": (b"ms-ds-machineaccountquota",),
    "AD.DELEGATION": (b"unconstrained", b"constrained delegation", b"resource-based"),
    "AD.LAPS": (b"ms-mcs-admpwd", b"mslaps-password"),
    "AD.PASSWORD_POLICY": (b"password history", b"minimum password", b"lockout"),
    "AD.EXCESSIVE_ACL": (b"genericall", b"writedacl", b"writeowner"),
    "AD.PRIVILEGED_GROUPS": (b"domain admins", b"enterprise admins"),
}


def parse_public_result(
    tool: ToolDefinition,
    *,
    state: JobState,
    exit_code: int | None,
    stdout_path: Path,
    stderr_path: Path,
    raw_result_ref: str,
) -> PublicResult:
    stdout_size = stdout_path.stat().st_size if stdout_path.exists() else 0
    stderr_size = stderr_path.stat().st_size if stderr_path.exists() else 0
    limitations: list[str] = []
    findings: list[DetectionFinding] = []
    if state is not JobState.SUCCEEDED:
        limitations.append("Provider output is incomplete or the operation did not succeed.")
    try:
        output = stdout_path.read_bytes().lower()
    except OSError:
        output = b""
        limitations.append("Raw stdout could not be read by the fixed parser.")
    for detection_id in tool.detection_ids:
        markers = _MARKERS.get(detection_id)
        observed = markers is not None and any(marker in output for marker in markers)
        status: Literal["observed", "not_observed", "unknown"] = (
            "observed"
            if observed
            else ("not_observed" if state is JobState.SUCCEEDED else "unknown")
        )
        findings.append(
            DetectionFinding(
                detection_id=detection_id,
                target=None,
                status=status,
                summary=(
                    "The fixed parser observed a registered indicator."
                    if observed
                    else "No registered indicator was observed in the available output."
                ),
            )
        )
    if not tool.detection_ids:
        limitations.append(
            "This operation has no registered detection rule; only execution status is public."
        )
    return PublicResult(
        operation_id=tool.operation_id,
        status=state,
        exit_code=exit_code,
        parser_id=tool.parser_id,
        findings=tuple(findings),
        coverage=tool.detection_ids,
        limitations=tuple(limitations),
        raw_result_ref=raw_result_ref,
        stdout_bytes=stdout_size,
        stderr_bytes=stderr_size,
        completed_at=utc_now(),
    )
