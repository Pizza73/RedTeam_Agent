# RedTeam AD MCP

This package exposes a closed catalog of Active Directory assessment operations through the official Python MCP SDK v2 `MCPServer`.

Use it only on systems and networks your organization owns or has explicitly authorized for testing. The server is designed to be launched by this repository's policy, approval, executor, and secret-management path. It does not provide a general-purpose shell or a supported direct-client configuration.

## Current contract

- Python 3.11 or later; `mcp==2.2.0`.
- stdio transport only in this revision.
- Every call requires the project authorization envelope in MCP request `_meta`.
- Targets must be canonical IP addresses inside `scope.yaml`; domain parameters are checked separately.
- Executables use absolute paths and required SHA-256 values from settings.
- `asyncio.create_subprocess_exec` receives a fixed argv; no shell is used.
- Intrusive operations require both `intrusive_enabled: true` and an approval ID.
- Operations whose risk is still unclassified support dry-run only.
- Raw stdout and stderr are private plaintext files with mode `0600`. MCP returns fixed-parser JSON and an opaque raw-result reference.
- Jobs are bound to execution, actor, and mission. A server restart marks unfinished jobs `outcome_unknown` and never resubmits them.

The package does not claim an OS sandbox, encrypted raw-output storage, cryptographic deletion, or a configured Windows remote transport.

## Setup

```sh
python3.11 -m venv .venv
.venv/bin/pip install -e '.[dev]'
cp config/settings.example.yaml settings.yaml
cp config/scope.example.yaml scope.yaml
export AD_MCP_PROJECT_TOKEN='replace-with-at-least-32-random-characters'
.venv/bin/ad-mcp --settings settings.yaml --scope scope.yaml
```

Before enabling an operation, set its absolute executable path and SHA-256 digest, then add its exact operation ID to `enabled_operations`. Do not put credentials in YAML. The calling adapter supplies approved credentials in the ephemeral MCP metadata extension.

File arguments are resource IDs. Map each approved ID to an absolute file below `workspace_root` in the `resources` settings map; callers cannot submit an arbitrary path.

## Windows payloads

`payloads/manifest.json` is intentionally empty. Rubeus, PowerUp, and GodPotato operations are registered but execution remains closed until the user selects a remote transport and supplies reviewed payload files with exact versions and SHA-256 values. Digest mismatches fail closed.

## Checks

```sh
.venv/bin/ruff check .
.venv/bin/mypy src
.venv/bin/pytest
```
