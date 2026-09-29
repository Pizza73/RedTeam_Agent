# Tool Provider and C2 UI Design

> Historical upstream design note: the integrated implementation is no longer a Phase 0A mock and does not expose the broad provider catalog described below. The current contract is limited to Tuoni Commercial plus the four Phase 5 Impacket MCP operations. See [UI_GUIDE.md](UI_GUIDE.md) and [../docs/development/ui-integration.md](../docs/development/ui-integration.md) for the authoritative behavior.

## Status and scope

This document defines the frontend-facing design for selecting C2 providers and controlling MCP-backed tools. The current implementation is a Phase 0A mock. It does not connect to a C2 product, MCP server, local shell, or target environment.

The design follows these boundaries:

- Provider access is not execution authorization.
- The Planner can request only registered, typed operations.
- Arbitrary commands, unrestricted argument arrays, and native provider commands are unavailable.
- A trusted backend must resolve registry records, current Mission scope, Policy Decisions, approvals, credentials, and execution state before dispatch.
- Raw provider output is never rendered directly by the frontend.

## Provider model

### C2 Selection

C2 is modeled as an `ExecutionAdapter`, not as an MCP server. A Mission revision selects at most one primary C2 adapter.

Frontend candidates:

- No C2 adapter
- Sliver
- Mythic
- Tuoni
- Cobalt Strike
- Adaptix
- Custom registered adapter

Selecting a candidate creates only a policy draft. Activation requires a product-specific Human Gate covering the exact product and version, registry identity, authentication method, isolated environment, capability mapping, and egress policy.

All C2 adapters share a bounded contract for capabilities such as session inventory, typed task submission, task status, redacted result retrieval, cancellation, and outcome reconciliation. Payload or implant generation and native C2 consoles are outside the MVP.

### Tools (MCP) Control

Kali Linux MCP is the primary tool runtime. The production adapter must expose a curated tool registry rather than `execute_command`, a shell, or an unrestricted `argv` interface.

Each registered operation defines:

- immutable operation ID and adapter route;
- strict input schema;
- target, port, protocol, session, and scope requirements;
- minimum risk and side-effect classification;
- approval requirement;
- timeout, cancellation, and reconciliation capabilities;
- output classification and redaction behavior;
- fixed executable mapping owned by the trusted adapter.

Impacket is treated as a suite of possible underlying implementations. The UI and Planner do not receive an `impacket.execute` operation. Only reviewed purpose-specific operations can be registered. The same rule applies to NetExec: an unrestricted `netexec_run(args)` operation is not acceptable.

The frontend catalog displays the concrete implementation component and fixed binding for every function:

| Tool | Function | Fixed binding | Default UI state | Constraint |
| --- | --- | --- | --- | --- |
| Nmap | Host discovery | `nmap.host-discovery.v1` | Allowed | Fixed discovery profile |
| Nmap | TCP port discovery | `nmap.tcp-ports.v1` | Approval required | Exact Mission port set |
| Impacket `rpcdump` | RPC endpoint inspection | `impacket.rpcdump.v1` | Allowed | Enumeration only |
| Impacket `smbclient` | SMB share listing | `impacket.smbclient-list.v1` | Approval required | No upload or delete |
| Impacket `GetUserSPNs` | SPN-enabled account inventory | `impacket.getuserspns-inventory.v1` | Approval required | Ticket requests fixed off |
| Impacket `secretsdump` | Credential material extraction | Not registered | Disabled | MVP prohibited capability |
| NetExec `nxc smb` | SMB host posture | `netexec.smb-posture.v1` | Allowed | Modules and arbitrary options disabled |
| NetExec `nxc smb shares` | SMB share enumeration | `netexec.smb-shares.v1` | Approval required | Read-only profile |
| NetExec execution methods | Remote command execution | Not registered | Disabled | MVP prohibited capability |
| Playwright MCP | Page structure snapshot | `playwright.snapshot.v1` | Disabled | Approved origin only |
| Playwright MCP | Browser navigation | `playwright.navigate.v1` | Disabled | Allowlisted origins and bounded redirects |
| Cloud Inventory MCP | Cloud asset inventory | `cloud.assets-read.v1` | Disabled | Read-only API profile |
| Cloud Inventory MCP | Identity relationship inventory | `cloud.identities-read.v1` | Disabled | No policy or identity mutation |
| Offline Analysis | Parse redacted artifact | `offline.artifact-parse.v1` | Allowed | Network disabled |
| Offline Analysis | Build knowledge graph | `offline.graph-build.v1` | Allowed | No target or provider access |

Each tool group is collapsed by default to keep the registry scannable. Expanding a group shows each function's required typed inputs, normalized output, safety constraint, policy state, and a read-only command or call template. For example, host discovery is presented as `nmap -sn <approved-cidr>`, while the RPC endpoint operation is presented as `impacket-rpcdump <domain>/<principal>@<target-ip>`.

These templates explain the reviewed adapter mapping; they are not a terminal, editable arguments, Planner input, or an execution control. Placeholders are resolved from trusted references only at dispatch time, and secret values are never displayed. Prohibited capabilities such as `secretsdump` and NetExec remote execution show `No command template registered` instead of an operational example.

The binding remains an adapter-owned identifier distinct from the human-readable template. Neither value may be treated as browser-submitted execution authority.

ROADrecon is not part of the baseline Kali MCP contract. It requires Entra ID authentication and cloud data collection semantics. If an authorized Mission later includes Entra ID, ROADrecon should use a dedicated constrained adapter and separate Human Gate. Its collected, redacted database may then be passed to offline analysis.

### Supplemental MCP servers

Supplemental MCP servers are disabled by default and should be enabled only when the Mission requires a capability that Kali MCP does not provide.

- Playwright MCP: browser state and single-page application interaction through registered browser operations.
- Cloud Inventory MCP: read-only cloud asset and identity metadata when an authorized cloud scope exists.

SIEM MCP is intentionally excluded. The current target environments provide no supported path to an existing SIEM, so it has no valid runtime use case.

### Offline Analysis Runtime

Offline analysis is not a terminal exposed to the agent. It is a network-disabled worker that accepts typed operations over already ingested, redacted artifacts.

Initial operations:

- parse a redacted artifact;
- validate an artifact schema;
- calculate a non-secret content digest;
- normalize collected records;
- build a knowledge graph;
- generate a redacted report.

The runtime cannot resolve credentials, contact targets, invoke C2, or execute operator-provided shell text.

## Frontend information architecture

The `C2 & Tools` page contains three tabs:

1. `C2 Selection` selects one registered C2 candidate and shows its Human Gate state.
2. `Tools (MCP) Control` shows Kali MCP, optional supplemental MCPs, offline analysis, and operation-level policy states.
3. `Review Policy` summarizes the draft before it is saved.

The page must always show that it is in Mock Mode. Saving records a frontend mock draft only and does not validate, activate, authorize, or dispatch a Mission.

## Proposed backend contracts

The frontend will eventually require documented same-origin endpoints equivalent to:

```text
GET  /api/tool-provider-policy/drafts/{mission_revision}
PUT  /api/tool-provider-policy/drafts/{mission_revision}
GET  /api/tool-registry/snapshot/{mission_revision}
GET  /api/c2-adapters/candidates/{mission_revision}
```

Responses must use strict schemas and reject unknown fields. Candidate lists and operation definitions must come from trusted registry snapshots rather than browser-submitted authority. A saved draft is not a `PolicyDecision` and must never be accepted as execution authorization.

Human Gate status is deliberately absent from the writable frontend draft. The browser may display a status obtained from a trusted read model, but it cannot submit `approved` or otherwise alter approval evidence.

## Phase limitations

- All current data is frontend-owned mock data.
- No connection testing is implemented for MCP or C2.
- No credentials, tokens, operator-entered commands, or raw output are accepted or displayed. Read-only reviewed command templates contain placeholders only.
- Phase 4 owns an approved C2 adapter after its Human Gate.
- Phase 5 owns an approved MCP adapter after its Human Gate.
