# Phase 0A Open Issues / Safe Interpretations

Phase 0Aを阻害する未解決矛盾はない。次の点は仕様の安全側具体化として記録する。

## OI-01: CIDR Target Reference

- 問題箇所: Section 21の例では`NormalizedTarget.type`にCIDRがない一方、Phase 0A受入条件はIP / CIDRを個別に要求する。
- 仕様上の矛盾: CIDR全体を単一IPとして表現すると包含/重複判定を安全に実装できない。
- 採用した暫定方針: `CidrTargetReference(type="cidr")`と`NormalizedTarget.type="cidr"`を明示的に追加した。
- 理由: CIDRがAllowedの部分集合であること、およびProhibitedとの部分重複を決定論的にDENYするため。
- 後続で必要な確認: 次回SystemDesign改訂時にModel例へ正式反映する。

## OI-02: `artifact_target_v1`

- 問題箇所: Trusted Target Extractor IDにはArtifactがあるが、ArtifactはExecution ScopeではなくData Access PolicyのResourceである。
- 仕様上の矛盾: ArtifactをExecution Targetとして正規化するとScope/Data Access分離を破る。
- 採用した暫定方針: IDはTrusted Registryに予約登録するが、Execution Target抽出に使うと`TargetExtractorResolutionError`でDefault Denyする。
- 理由: Artifact Accessは`ResourceBinding + DataAccessGrant`だけで扱うため。
- 後続で必要な確認: Artifact用IDをData Access Resolverの別Registryへ移すか名称変更する。

## OI-03: Canonical JSON cross-language profile

- 問題箇所: 要件はRFC 8785/JCSまたは同等の固定方式を許可するが、Phase 0AはPythonのみである。
- 仕様上の矛盾: なし。ただし将来の他言語実装とNumber Serializationを共有する際に互換性確認が必要。
- 採用した暫定方針: `RedTeam Canonical JSON v1`としてUTF-8、Key Sort、最小Separator、有限Number、UTC DateTime、明示変換を固定した。NaN/Infinity/bytes/任意Objectを拒否する。
- 理由: Phase 0A内で安定したSecurity Digestを得て、曖昧な暗黙変換を避けるため。
- 後続で必要な確認: 他言語Producerを導入する前にRFC 8785の公式VectorとのCompatibility ADRを作成する。

## OI-04: Audit LogのPhase境界

- 問題箇所: Phase 0AのTable一覧に`audit_logs`がある一方、Mission Hash Chain本体はPhase 0Cである。
- 仕様上の矛盾: Phase 0AでHash Chainまで実装すると依頼範囲を越える。
- 採用した暫定方針: MigrationとUnique Sequence Constraintの拡張可能なTableだけを作成し、Audit Logger/Hash Chainは実装しない。
- 理由: Phase 0Cを先回りせずMigration互換性を確保するため。
- 後続で必要な確認: Phase 0CでTransaction採番、Hash Chain、改ざん検出Testを追加する。

