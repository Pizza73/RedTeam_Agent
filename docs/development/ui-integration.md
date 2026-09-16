# Operator UI Integration

## Status

The Operator Console from [nathanhoma/RedTeam_Agent](https://github.com/nathanhoma/RedTeam_Agent), commit
`68caad5e219162f47be4fe364a87f28c805b69fb`, is integrated as `frontend/`. The source repository and this repository use GPL-3.0.

The integration is complete for offline development: the production frontend uses the local Python API, reads durable Mission / Approval / Knowledge state, stores non-authoritative drafts, and presents the Phase 4 Tuoni / Sliver and Phase 5 Impacket boundaries. No real C2, vCenter, vLLM, or Target connection is required for these functions.

## Architecture

```text
Browser on loopback
        |
        | same-origin HTTP + strict JSON
        v
redteam-ui (ThreadingHTTPServer)
        |
        +-- read projection ------> provisioned RedTeam Agent SQLite DB
        +-- draft namespaces -----> ui_mission_draft / ui_provider_policy_draft
        +-- optional write port --> existing Approval Service
        +-- optional probe port ---> existing Phase 2 Capability composition
```

`src/redteam_agent/ui/models.py` owns the strict browser boundary. `control_plane.py` projects safe data without creating a second Mission, Policy, Approval, or Knowledge authority. `server.py` serves the built SPA and the `/api/v1` API on loopback only.

## API

Read endpoints:

- `GET /api/v1/health`
- `GET /api/v1/dashboard`
- `GET /api/v1/phases`
- `GET /api/v1/activity`
- `GET /api/v1/interventions`
- `GET /api/v1/knowledge`
- `GET /api/v1/providers`

Mutation endpoints:

- `POST /api/v1/mission-drafts`
- `POST /api/v1/provider-policy-drafts`
- `POST /api/v1/interventions/{id}/decision`
- `POST /api/v1/vllm/capability`

All mutations require exact same-origin proof. Draft endpoints persist only non-authoritative UI drafts. Approval decisions are delegated to an injected `ApprovalDecisionPort`; VLLM checks are delegated to an injected `VLLMCapabilityPort`. The standalone CLI intentionally injects neither and reports both capabilities disabled.

## Provider boundary

- Tuoni: Commercial, version shown as `latest`, existing deployment, access unconfigured.
- Sliver: v1.7.3, operator `joe`, HTTP Beacon transport, no Beacon currently present. Selection exposes inventory and existing Beacon Task read/cancel only.
- Impacket: installed package version reported at runtime; MCP server `redteam-impacket-mcp`.
- Exposed operations: SMB negotiate, SMB authenticate, SMB list shares, RPC endpoint map.
- Default egress description: TCP/445 and TCP/135 only; actual OS / vCenter isolation qualification remains an Activation Blocker.
- No raw provider result, arbitrary shell, generic Impacket execution, secretsdump, upload, delete, or payload path is exposed.

## Build and run

```sh
.venv/bin/python -m pip install -r requirements.lock
.venv/bin/python -m pip install -e . --no-build-isolation
cd frontend
npm ci
npm run build
cd ..
.venv/bin/redteam-ui --database /absolute/path/to/redteam-agent.db
```

Open `http://127.0.0.1:18000/dashboard`.

For development, run `redteam-ui --api-only` and `npm run dev` separately. Vite proxies `/api` to the loopback API. Mock data is compiled only when Vitest sets `MODE=test`; production builds always use `apiGateway`.

## Safety properties

- Only loopback bind targets are accepted and Host headers are allowlisted.
- CORS and framing are denied; CSP and no-store API responses are enabled.
- Unknown JSON fields, duplicate JSON keys, invalid timestamps, oversized requests, unsafe identifiers, and stale decisions fail closed.
- UI timestamps accept RFC 3339 `Z` and numeric UTC offsets; Python emits offset-aware ISO values.
- Knowledge projections verify stored integrity digests and expose only redacted Artifact metadata.
- Static missing assets return 404 and cannot fall through to the SPA document; extensionless routes do use the SPA fallback.

## Offline verification

- Frontend: TypeScript, ESLint, 24 Vitest tests, 10 Playwright route / accessibility tests, production Vite build.
- Backend: strict boundary unit tests and SQLite / Approval Service / HTTP integration tests.
- Browser: built SPA verified against a seeded real application DB and local API. Dashboard Mission state, lifecycle, Authorization boundary, Tuoni status, Impacket operation count, and zero browser warnings / errors were confirmed.

## Remaining production-only work

The UI itself does not remove the existing Phase 4 / 5 Activation Blockers. Production requires either the real Tuoni identity and OpenAPI / image binding or the pinned Sliver operator/server identities and an approved HTTP Beacon, plus actual isolation evidence and composition of the UI with authenticated Approval and Phase 2 Capability owner services. Until then, real dispatch remains disabled.
