"""Secret-on-stdin worker for the fixed, read-only Certipy ``find`` action."""

from __future__ import annotations

import contextlib
import io
import json
import re
import sys
import tempfile
from pathlib import Path


def _contains_unknown(value: object) -> bool:
    if isinstance(value, str):
        lowered = value.casefold()
        return any(marker in lowered for marker in ("unknown", "could not", "timed out", "connection refused"))
    if isinstance(value, dict):
        return any(_contains_unknown(item) for item in value.values())
    if isinstance(value, list):
        return any(_contains_unknown(item) for item in value)
    return False


def _main() -> int:
    request = json.load(sys.stdin)
    from certipy.entry import main as certipy_main

    with tempfile.TemporaryDirectory(prefix="redteam-adcs-") as temporary:
        prefix = str(Path(temporary) / "assessment")
        sys.argv = [
            "certipy-ad",
            "find",
            "-enabled",
            "-json",
            "-hide-admins",
            "-output",
            prefix,
            "-u",
            f"{request['username']}@{request['domain']}",
            "-p",
            request["password"],
            "-dc-ip",
            request["server_ip"],
            "-target",
            request["domain"],
            "-target-ip",
            request["server_ip"],
            "-ldap-scheme",
            "ldaps",
            "-ldap-port",
            str(request["port"]),
            "-timeout",
            str(request["timeout_seconds"]),
        ]
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            certipy_main()
        output_path = Path(f"{prefix}_Certipy.json")
        if not output_path.is_file():
            return 2
        report = json.loads(output_path.read_text(encoding="utf-8"))
    counts = {f"ESC{index}": 0 for index in range(1, 9)}
    for section_name in ("Certificate Authorities", "Certificate Templates", "Issuance Policies"):
        section = report.get(section_name, {})
        if not isinstance(section, dict):
            continue
        for entry in section.values():
            if not isinstance(entry, dict):
                continue
            vulnerabilities = entry.get("[!] Vulnerabilities", {})
            if not isinstance(vulnerabilities, dict):
                continue
            matched = {
                match.group(1)
                for key in vulnerabilities
                if (match := re.match(r"^(ESC[1-8])(?:\b|$)", str(key))) is not None
            }
            for esc_id in matched:
                counts[esc_id] += 1
    print(json.dumps({"coverage_complete": not _contains_unknown(report), "exposure_counts": counts}))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(_main())
    except Exception:
        raise SystemExit(1) from None
