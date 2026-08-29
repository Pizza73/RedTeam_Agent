# Phase 0C: Data Security and Audit

## Preconditions

- Phase 0B Gate PASS and all earlier invariants preserved.

## Implement

- Artifact Store with mission-scoped access, internal paths, traversal/symlink defense, quota, integrity, retention and audit
- Encrypted Raw Result Quarantine with crash-safe chunk metadata and resume
- Secure ingestion: classification, secret detection, redaction and reference generation
- Secret Store interface and reference-only application model
- EncryptionKeyProvider with separated secret/quarantine/artifact domains
- Authenticated encryption metadata and AAD bindings
- Key rotation/revocation/unavailable fail-closed behavior
- Data access enforcement for artifact and secret operations
- Application-level append-only, mission-scoped audit log and hash chain
- Atomic mission sequence allocation and chain verification
- Sandbox interface/policy/capability models required for later execution

## Test

- No secret/raw output in prompt, normal DB/log, exception or traceback
- Path traversal, symlink escape, quota and digest corruption
- Quarantine streaming crash/resume and secure deletion lifecycle
- Secret/Quarantine/Artifact key ID/tag reuse rejection
- Nonce/AAD/domain mismatch and unavailable/revoked key fail-closed
- Audit deletion/reorder/content/previous-hash tamper detection
- Sequence conflict and independent mission chain verification

Do not introduce plaintext or normal-artifact fallback.
