"""Command-line entry point for the approved Kali-local product composition."""

from __future__ import annotations

import argparse
from pathlib import Path

from redteam_agent.composition.kali_product import (
    KaliProductSettings,
    build_kali_product_application,
    serve_kali_product,
)
from redteam_agent.errors import AuthorizationKernelError


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the Kali-local RedTeam Agent control plane")
    parser.add_argument("--config", required=True, type=Path)
    args = parser.parse_args()
    try:
        raw = args.config.read_bytes()
        settings = KaliProductSettings.from_untrusted_json(raw)
        application = build_kali_product_application(settings)
        serve_kali_product(application)
    except (AuthorizationKernelError, OSError, ValueError):
        parser.error("product startup configuration or trust prerequisites are invalid")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
