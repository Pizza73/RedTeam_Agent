# Operator UI Integration

## Status

The Operator Console from [nathanhoma/RedTeam_Agent](https://github.com/nathanhoma/RedTeam_Agent), commit
`68caad5e219162f47be4fe364a87f28c805b69fb`, is integrated as `frontend/`. The source repository and this repository use GPL-3.0.

The integration is complete for offline development: the production frontend uses the local Python API, authenticates a fixed local operator, reads durable Mission / Approval / Knowledge state, and presents the Phase 4 Tuoni / Sliver and Phase 5 Impacket boundaries. The Kali product composition attaches the existing Mission and Approval owner services. No real C2, vCenter, vLLM, or Target connection is required for draft and lifecycle management. When explicitly enabled at server startup, VLLM Settings additionally runs the real Phase 2 attestation and schema capability evaluation.

The provider surface also exposes a closed AD configuration-assessment catalog. Its five read-only checks cover privileged access, Kerberos service-account hardening, Kerberos preauthentication, AD CS ESC1-ESC8, and delegation. Browser-supplied evidence remains simulator-only. The server-owned live endpoint accepts an empty body and binds fixed LDAPS/credential/threshold configuration. The LLM can select a next inspection or classify all five normalized evidence sections; deterministic rules remain the finding authority.

`POST /api/v1/ad-assessment/recommendation` invokes the advisory Planner role only in the Kali product composition and only after exact passing Phase 2 Planner capability evidence exists. `POST /api/v1/ad-assessment/evaluate-with-llm` invokes five finite classifications and independently verifies all of them; completion requires five agreements and no indeterminate category. Model-authored prose is discarded in both paths. `POST /api/v1/ad-assessment/evaluate` and the browser-supplied complete LLM endpoint accept only `source_type=simulator`. `POST /api/v1/ad-assessment/collect-and-evaluate` is the only path that can create `verified_ldap_snapshot` evidence.

## Architecture

```text
Browser on loopback
        |
        | same-origin HTTP + HttpOnly session + strict JSON
        v
redteam-ui (ThreadingHTTPServer)
        |
        +-- read projection ------> provisioned RedTeam Agent SQLite DB
        +-- draft namespaces -----> ui_mission_draft / ui_provider_policy_draft
        +-- optional owner port ---> existing Mission Manager
        +-- optional write port --> existing Approval Service
        +-- optional probe port ---> existing Phase 2 Capability composition
        +-- optional AD port ------> fixed-IP LDAPS + fixed Certipy find worker
```

`src/redteam_agent/ui/models.py` owns the strict browser boundary. `control_plane.py` projects safe data without creating a second Mission, Policy, Approval, or Knowledge authority. `server.py` serves the built SPA and the `/api/v1` API on loopback only.

## API

Read endpoints:

- `GET /api/v1/health`
- `GET /api/v1/session`
- `GET /api/v1/dashboard`
- `GET /api/v1/phases`
- `GET /api/v1/activity`
- `GET /api/v1/interventions`
- `GET /api/v1/knowledge`
- `GET /api/v1/providers`
- `GET /api/v1/readiness`
- `GET /api/v1/vllm/config`

Mutation endpoints:

- `POST /api/v1/mission-drafts`
- `POST /api/v1/session`
- `DELETE /api/v1/session`
- `POST /api/v1/missions`
- `POST /api/v1/missions/{id}/transitions`
- `POST /api/v1/provider-policy-drafts`
- `POST /api/v1/interventions/{id}/decision`
- `POST /api/v1/vllm/capability`
- `POST /api/v1/ad-assessment/evaluate`
- `POST /api/v1/ad-assessment/evaluate-with-llm`
- `POST /api/v1/ad-assessment/recommendation`
- `POST /api/v1/ad-assessment/collect-and-evaluate`

All endpoints except health and the session exchange require an authenticated operator session; all mutations also require exact same-origin proof. Draft endpoints persist only reviewable inputs. Mission creation and transitions are delegated to the existing owner aggregate, and start/resume are rejected unless an attested execution runtime is attached. Approval decisions are delegated to an injected `ApprovalDecisionPort`. The standalone CLI reports VLLM checks disabled unless all trusted `--vllm-*` startup inputs are supplied. When enabled, the browser can only replay the server-published endpoint/model/mode; it cannot select an arbitrary URL, read the API key, or replace the signed artifact identity. The backend performs direct-network server attestation and the complete Phase 2 schema corpus through the bounded gateway, then durably stores only real capability evidence.

`GET /api/v1/readiness` projects the saved control-plane state as an ordered blocker list. Each blocker has a stable code, category, operator-facing explanation, and concrete next action. It distinguishes Mission draft/validation, approved session reference, provider policy, LLM evidence, Sliver credential/identity/Beacon, Impacket isolation, TPM key provider, and execution-runtime requirements. The global status links to this list, and rejected Mission commands return the same safe error-code/resolution shape instead of raw internal exceptions.

## Provider boundary

- Tuoni: Commercial, version shown as `latest`, existing deployment, access unconfigured.
- Sliver: v1.7.7, operator `joe`, HTTP Beacon transport, no Beacon currently present. Selection exposes inventory and existing Beacon Task read/cancel only.
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
.venv/bin/redteam-ui \
  --database /absolute/path/to/redteam-agent.db \
  --operator-token-file /absolute/private/path/ui-operator.token
```

Real VLLM capability integration:

```sh
.venv/bin/redteam-ui \
  --database /absolute/path/to/redteam-agent.db \
  --operator-token-file /absolute/private/path/ui-operator.token \
  --vllm-base-url http://10.0.6.181:8100/v1 \
  --vllm-model gemma-4-31B-it \
  --vllm-api-key-file /absolute/path/to/vllm-api.key \
  --vllm-manifest /absolute/path/to/gemma-4-31b.manifest.json \
  --vllm-public-key /absolute/path/to/attestation-signing-public.pem \
  --vllm-tokenizer-directory /absolute/path/to/gemma-4-31b-tokenizer
```

Open `http://127.0.0.1:18000/dashboard`.

For development, run `redteam-ui --api-only --operator-token-file /absolute/private/path/ui-operator.token` and `npm run dev` separately. Vite proxies `/api` to the loopback API. Mock data is compiled only when Vitest sets `MODE=test`; production builds always use `apiGateway`.

## Safety properties

- Only loopback bind targets are accepted and Host headers are allowlisted.
- The bootstrap token is exchanged once for a bounded, restart-ephemeral HttpOnly SameSite session and is never persisted.
- CORS and framing are denied; CSP and no-store API responses are enabled.
- Unknown JSON fields, duplicate JSON keys, invalid timestamps, oversized requests, unsafe identifiers, and stale decisions fail closed.
- UI timestamps accept RFC 3339 `Z` and numeric UTC offsets; Python emits offset-aware ISO values.
- Knowledge projections verify stored integrity digests and expose only redacted Artifact metadata.
- Static missing assets return 404 and cannot fall through to the SPA document; extensionless routes do use the SPA fallback.
- The VLLM API key remains in a mode-restricted server-side file; only the fixed public profile is returned to the browser, and capability runs are single-flight and finite.

## Offline verification

- Frontend: TypeScript, ESLint, 27 Vitest tests, 12 Playwright route / accessibility tests, production Vite build.
- Backend: strict boundary unit tests and SQLite / Approval Service / HTTP integration tests.
- Browser: built SPA verified against a seeded real application DB and local API. Dashboard Mission state, lifecycle, Authorization boundary, Tuoni status, Impacket operation count, and zero browser warnings / errors were confirmed.

## Remaining production-only work

The UI itself does not remove the existing Phase 4 / 5 Activation Blockers. Production requires either the real Tuoni identity and OpenAPI / image binding or the pinned Sliver operator/server identities and an approved HTTP Beacon, plus actual isolation evidence, a TPM-backed persistent key provider, and the Mission execution worker. Phase 2 VLLM Capability and authenticated Mission/Approval owners are available through the Kali composition, but Mission start/resume and real dispatch remain disabled until their separate gates pass.
