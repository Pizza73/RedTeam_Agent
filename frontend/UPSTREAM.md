# Upstream UI provenance

The frontend was imported from [nathanhoma/RedTeam_Agent](https://github.com/nathanhoma/RedTeam_Agent) at commit
`68caad5e219162f47be4fe364a87f28c805b69fb` and adapted to this repository's live, fail-closed control-plane contracts.

The upstream and this repository are licensed under GNU GPL version 3. The repository root [LICENSE](../LICENSE) applies.

Material integration changes include replacing production mock data with same-origin API calls, constraining the provider catalog to Tuoni Commercial and the four Phase 5 Impacket operations, projecting durable Mission / Approval / Knowledge state, and disabling authority-bearing actions when their trusted owner services are not injected.
