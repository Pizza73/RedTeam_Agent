from __future__ import annotations

import copy
import json
import shutil
import subprocess
import textwrap
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
HELPER = REPO_ROOT / "automation/local_review_evidence.js"
PR = "https://github.com/example/project/pull/3"
HEAD = "a" * 40
BASE = "b" * 40
RUN = "11111111-1111-4111-8111-111111111111"
SESSION = "22222222-2222-4222-8222-222222222222"
FAMILY = "secret-plaintext-boundary"
CHECKS = ["tests (3.12)", "tests (3.14)", "quality", "governance-integrity"]
START_MARKER = "redteam-local-review-start"
RESULT_MARKER = "redteam-local-review-result"
FINDING_MARKER = "redteam-local-review-finding"


def canonical(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def marker(name: str, payload: object) -> str:
    return f"<!-- {name}\n{canonical(payload)}\n-->"


def invoke(operation: str, value: Any) -> dict[str, Any]:
    node = shutil.which("node")
    assert node is not None, "Node is a required governance test dependency"
    script = """
const h = require(process.argv[1]);
const input = JSON.parse(require('fs').readFileSync(0, 'utf8'));
try {
  const result = input.operation === 'gate' ? h.isTrustedGateEvidence(...input.value)
    : input.operation === 'reference' ? h.isGateFindingReference(...input.value)
    : h[input.operation](input.value);
  process.stdout.write(JSON.stringify({ok:true,result}));
} catch (error) {
  process.stdout.write(JSON.stringify({ok:false,type:error.constructor.name,message:error.message}));
}
"""
    process = subprocess.run(  # noqa: S603 - fixed local Node helper with isolated JSON test data.
        [node, "-e", script, str(HELPER)],
        input=json.dumps({"operation": operation, "value": value}),
        text=True,
        capture_output=True,
        check=True,
    )
    return json.loads(process.stdout)  # type: ignore[no-any-return]


def comment(index: int, name: str, payload: dict[str, Any], second: int) -> dict[str, Any]:
    time = f"2026-09-06T12:00:{second:02d}Z"
    return {
        "html_url": f"{PR}#issuecomment-{index}",
        "user": {"login": "operator"},
        "body": marker(name, payload),
        "created_at": time,
        "updated_at": time,
    }


def fixture(findings: int = 0) -> dict[str, Any]:
    start = {
        "schema_version": "1.0", "phase": "phase-0c", "head_sha": HEAD,
        "base_sha": BASE, "ready_reference": f"{PR}#issuecomment-1",
        "source_digest": "c" * 64, "policy_digest": "d" * 64,
        "run_id": RUN, "started_at": "2026-09-06T12:00:01Z",
    }
    retained = [
        {
            "id": f"LOCAL-P1-{index}", "severity": "HIGH", "invariant_family": FAMILY,
            "requirement_id": "LOOP-026", "evidence": f"src/example.py:{index + 1}",
            "required_fix": "Preserve complete authorization binding.",
            "retest": ["bash scripts/ci/run_phase_gate.sh phase-0c"],
        }
        for index in range(findings)
    ]
    finding_comments = [
        comment(10 + index, FINDING_MARKER, {
            "schema_version": "1.0", "run_id": RUN, "phase": "phase-0c",
            "head_sha": HEAD, "base_sha": BASE, "finding": finding,
        }, 3 + index)
        for index, finding in enumerate(retained)
    ]
    report = {
        **start, "start_reference": f"{PR}#issuecomment-2",
        "reviewer_session_id": SESSION, "completed_at": "2026-09-06T12:00:09Z",
        "finding_references": [item["html_url"] for item in finding_comments],
        "result": {
            "schema_version": "1.0", "phase": "phase-0c", "reviewed_sha": HEAD,
            "base_sha": BASE, "verdict": "CHANGES_REQUESTED" if findings else "PASS",
            "summary": "Complete phase review.", "findings": retained,
            "required_checks": [{"name": name, "status": "PASS"} for name in CHECKS],
        },
    }
    return {
        "operatorLogin": "operator", "phase": "phase-0c", "headSha": HEAD, "baseSha": BASE,
        "readyReference": start["ready_reference"], "readyCreatedAt": "2026-09-06T12:00:00Z",
        "sourceDigest": start["source_digest"], "policyDigest": start["policy_digest"],
        "pullRequestUrl": PR, "familyIds": [FAMILY], "requiredCheckNames": CHECKS,
        "startReference": report["start_reference"], "reportReference": f"{PR}#issuecomment-3",
        "comments": [comment(2, START_MARKER, start, 2),
                     *finding_comments, comment(3, RESULT_MARKER, report, 10)],
        "timeline": [],
    }


def payload(value: dict[str, Any], index: int) -> dict[str, Any]:
    return json.loads(value["comments"][index]["body"].split("\n")[1])  # type: ignore[no-any-return]


def replace_payload(value: dict[str, Any], index: int, updated: dict[str, Any]) -> None:
    name = value["comments"][index]["body"].split("\n")[0].removeprefix("<!-- ")
    value["comments"][index]["body"] = marker(name, updated)


def reject(value: dict[str, Any]) -> None:
    result = invoke("evaluateLocalReview", value)
    assert result["ok"] is False, result
    assert result["type"] == "LocalReviewEvidenceError", result


@pytest.mark.parametrize("count", [0, 1, 3])
def test_local_review_retains_complete_independent_result(count: int) -> None:
    result = invoke("evaluateLocalReview", fixture(count))
    assert result["ok"] is True, result
    evidence = result["result"]
    assert evidence["evidenceFormat"] == "local-review-v1"
    assert evidence["reviewerLogin"] == "operator"
    assert len(evidence["currentFindings"]) == count
    assert [item["html_url"] for item in evidence["currentFindings"]] == [
        f"{PR}#issuecomment-{10 + index}" for index in range(count)
    ]


@pytest.mark.parametrize("raw", [
    '{"a":1,"a":1}', '{"a":{"b":1,"b":2}}', '{"a":1,"\\u0061":2}',
    '{"a":1, "b":2}', '{"b":2,"a":1}', '{"a":1e999}',
    '{"a":NaN}', 'null trailing', '"' + "x" * 60001 + '"',
    "[" * 34 + "0" + "]" * 34,
])
def test_local_review_json_rejects_ambiguous_unbounded_input(raw: str) -> None:
    result = invoke("strictJsonParse", raw)
    assert result["ok"] is False
    assert result["type"] == "LocalReviewEvidenceError"


def test_local_review_json_accepts_repeated_fields_in_distinct_findings() -> None:
    value = {"findings": [{"id": "A", "text": "日本語"}, {"id": "B", "text": "別件"}]}
    assert invoke("strictJsonParse", canonical(value)) == {"ok": True, "result": value}


def test_local_review_accepts_fresh_uuid7_cli_session_identity() -> None:
    value = fixture()
    record = payload(value, -1)
    record["reviewer_session_id"] = "01992000-0000-7000-8000-000000000000"
    replace_payload(value, -1, record)
    assert invoke("evaluateLocalReview", value)["ok"] is True


def test_local_review_launcher_run_identity_remains_uuid4() -> None:
    value = fixture()
    for index in [0, -1]:
        record = payload(value, index)
        record["run_id"] = "01992000-0000-7000-8000-000000000000"
        replace_payload(value, index, record)
    reject(value)


@pytest.mark.parametrize("index", [0, -1, 1])
def test_local_review_rejects_untrusted_author_or_edited_evidence(index: int) -> None:
    value = fixture(1)
    value["comments"][index]["user"]["login"] = "attacker"
    reject(value)
    value = fixture(1)
    value["comments"][index]["updated_at"] = "2026-09-06T12:00:11Z"
    reject(value)


@pytest.mark.parametrize("field,changed", [
    ("head_sha", "f" * 40), ("base_sha", "f" * 40), ("phase", "phase-1"),
    ("source_digest", "f" * 64), ("policy_digest", "f" * 64),
    ("ready_reference", f"{PR}0#issuecomment-1"), ("schema_version", "2.0"),
    ("run_id", "not-a-uuid"), ("unknown", True),
])
@pytest.mark.parametrize("index", [0, -1])
def test_local_review_rejects_stale_or_open_envelope(
    field: str, changed: object, index: int,
) -> None:
    value = fixture()
    record = payload(value, index)
    record[field] = changed
    replace_payload(value, index, record)
    reject(value)


@pytest.mark.parametrize("field,changed", [
    ("start_reference", f"{PR}#issuecomment-999"), ("reviewer_session_id", RUN),
    ("completed_at", "2026-09-06T12:00:00Z"),
    ("completed_at", "2026-09-06T12:00:11Z"),
    ("completed_at", "2026-09-06T12:00:09+00:00"),
    ("completed_at", "2026-02-31T12:00:09Z"),
])
def test_local_review_rejects_reused_session_or_invalid_time(field: str, changed: object) -> None:
    value = fixture()
    record = payload(value, -1)
    record[field] = changed
    replace_payload(value, -1, record)
    reject(value)


@pytest.mark.parametrize("index", [0, -1])
def test_local_review_rejects_duplicate_marker_and_competing_run(index: int) -> None:
    value = fixture()
    value["comments"][index]["body"] *= 2
    reject(value)
    value = fixture()
    competing = copy.deepcopy(value["comments"][index])
    competing["html_url"] = f"{PR}#issuecomment-99"
    value["comments"].append(competing)
    reject(value)


def test_local_review_rejects_changed_head_even_if_restored() -> None:
    value = fixture()
    value["timeline"] = [
        {"event": "synchronize", "created_at": "2026-09-06T12:00:04Z"},
        {"event": "synchronize", "created_at": "2026-09-06T12:00:05Z"},
    ]
    reject(value)


@pytest.mark.parametrize("field,changed", [
    ("severity", "LOW"), ("invariant_family", "unknown-family"), ("required_fix", ""),
    ("retest", []), ("id", "invalid lowercase"), ("extra", True),
])
def test_local_review_rejects_incomplete_or_unclassified_finding(
    field: str, changed: object,
) -> None:
    value = fixture(1)
    record = payload(value, -1)
    record["result"]["findings"][0][field] = changed
    replace_payload(value, -1, record)
    reject(value)


@pytest.mark.parametrize("mode", ["omit", "swap", "duplicate", "foreign", "tamper"])
def test_local_review_cannot_drop_reorder_duplicate_or_replace_finding_evidence(mode: str) -> None:
    value = fixture(2)
    record = payload(value, -1)
    if mode == "omit":
        record["result"]["findings"].pop()
        record["finding_references"].pop()
    elif mode == "swap":
        record["finding_references"].reverse()
    elif mode == "duplicate":
        record["finding_references"][1] = record["finding_references"][0]
    elif mode == "foreign":
        record["finding_references"][0] = f"{PR}0#issuecomment-10"
    else:
        record["result"]["findings"][0]["evidence"] = "A different issue"
    replace_payload(value, -1, record)
    reject(value)


def test_local_review_cannot_claim_pass_with_p1_or_changes_without_findings() -> None:
    for count, verdict in [(1, "PASS"), (0, "CHANGES_REQUESTED")]:
        value = fixture(count)
        record = payload(value, -1)
        record["result"]["verdict"] = verdict
        replace_payload(value, -1, record)
        reject(value)


def test_local_review_ci_projection_does_not_assert_actual_ci_success() -> None:
    value = fixture()
    record = payload(value, -1)
    record["result"]["required_checks"][0]["status"] = "MISSING"
    replace_payload(value, -1, record)
    result = invoke("evaluateLocalReview", value)
    assert result["ok"] is True
    assert result["result"]["result"]["required_checks"][0]["status"] == "MISSING"


@pytest.mark.parametrize("mode,identity,accepted", [
    ("codex-native-v1", "cloud[bot]", True), ("local-review-v1", "operator", True),
    ("codex-native-v1", "operator", False), ("local-review-v1", "cloud[bot]", False),
    ("local-attested-v1", "operator", False), ("unknown", "operator", False),
])
def test_gate_evidence_preserves_distinct_historical_and_local_identity(
    mode: str, identity: str, accepted: bool,
) -> None:
    gate = {"evidence_format": mode, "reviewer_login": identity, "recorded_by": "operator"}
    assert invoke("gate", [gate, "cloud[bot]", "operator"]) == {"ok": True, "result": accepted}


@pytest.mark.parametrize("mode,suffix,accepted", [
    ("codex-native-v1", "#discussion_r123", True),
    ("local-review-v1", "#issuecomment-123", True),
    ("codex-native-v1", "#issuecomment-123", False),
    ("local-review-v1", "#discussion_r123", False),
    ("local-review-v1", "0#issuecomment-123", False),
    ("local-review-v1", "#issuecomment-123/finding", False),
    ("local-review-v1", "#issuecomment-123?extra=1", False),
    ("local-review-v1", "#issuecomment-0", False),
    ("local-review-v1", "#issuecomment-01", False),
    ("unknown", "#issuecomment-123", False),
])
def test_gate_finding_reference_is_format_specific_and_an_exact_permalink(
    mode: str, suffix: str, accepted: bool,
) -> None:
    assert invoke("reference", [{"evidence_format": mode}, PR + suffix, PR]) == {
        "ok": True, "result": accepted,
    }


@pytest.mark.parametrize("consumer", ["design", "refresh", "recovery"])
@pytest.mark.parametrize("mode,base_mode", [
    ("codex-native-v1", "codex-native-v1"),
    ("local-review-v1", "local-review-v1"),
    ("codex-native-v1", "local-review-v1"),
    ("local-review-v1", "codex-native-v1"),
])
@pytest.mark.parametrize("tamper", ["none", "reviewer", "recorder"])
def test_gate_consumers_preserve_mixed_phase_chain_and_recorder_authority(
    consumer: str, mode: str, base_mode: str, tamper: str,
) -> None:
    node = shutil.which("node")
    assert node is not None
    harness = r"""
const assert = require('node:assert/strict'), fs = require('fs');
const root = process.argv[1], consumer = process.argv[2], mode = process.argv[3];
const baseMode = process.argv[4], tamper = process.argv[5];
const approvalPath = `${root}/automation/approve_design_resume.js`;
const helper = require(`${root}/automation/local_review_evidence.js`);
const approval = require(approvalPath);
const localRequire = require('module').createRequire(approvalPath);
const pr = 'https://github.com/example/project/pull/3';
const head = 'a'.repeat(40), base = 'b'.repeat(40);
const checks = ['tests (3.12)','tests (3.14)','quality','governance-integrity'].map(
  name => ({name,status:'PASS'}));
const gate = {schema_version:'1.1',phase:'phase-0c',reviewed_sha:head,base_sha:base,
  verdict:'CHANGES_REQUESTED',summary:'Complete review.',evidence_format:mode,
  ready_reference:`${pr}#issuecomment-1`,review_trigger_reference:`${pr}#issuecomment-2`,
  review_reference:`${pr}#pullrequestreview-3`,
  reviewer_login:mode==='local-review-v1'?'operator':'cloud[bot]',recorded_by:'operator',
  finding_key:'F-1',required_checks:checks,loop_state:'BLOCKED_LIMIT',
  stop_reason:'INVARIANT_FAMILY_RECURRENCE',recurring_families:['secret-plaintext-boundary'],
  finding_references:[mode==='local-review-v1'?`${pr}#issuecomment-4`:`${pr}#discussion_r4`]};
const pass = {schema_version:'1.0',phase:'phase-0b',reviewed_sha:base,base_sha:'c'.repeat(40),
  verdict:'PASS',summary:'Prior pass.',evidence_format:baseMode,
  ready_reference:`${pr}#issuecomment-5`,review_trigger_reference:`${pr}#issuecomment-6`,
  review_reference:`${pr}#issuecomment-7`,
  reviewer_login:baseMode==='local-review-v1'?'operator':'cloud[bot]',recorded_by:'operator',
  finding_key:null,required_checks:checks,loop_state:'PASS'};
if(tamper==='reviewer') pass.reviewer_login = baseMode==='local-review-v1'?'cloud[bot]':'operator';
if(tamper==='recorder') pass.recorded_by = 'other-operator';
if(consumer==='recovery'){
  gate.schema_version='1.0';delete gate.stop_reason;
  delete gate.recurring_families;delete gate.finding_references;
}
const comments = [gate,pass].map((record,index)=>({html_url:`${pr}#issuecomment-${10+index}`,
  user:{login:'github-actions[bot]'},
  body:`<!-- redteam-phase-gate\n${JSON.stringify(record)}\n-->`}));
const core = {setFailed(message){throw new Error(message);}};
const exactKeys=(value,keys)=>value&&JSON.stringify(Object.keys(value).sort())===
  JSON.stringify([...keys].sort());
const singleMarker=(body,name)=>{
  const values=approval.markerPayloads(body,name);assert.equal(values.length,1);return values[0];};
const data={gate,pass,comments,core,exactKeys,singleMarker,head,base,pr};
const AsyncFunction=Object.getPrototypeOf(async function(){}).constructor;
let source;
if(consumer==='design'){
  const file=fs.readFileSync(approvalPath,'utf8');
  source=file.split('async function run')[0]+
    'const maximal=[{payload:data.gate}]; const phase="phase-0c";'+
    'const reviewer="cloud[bot]", approver="operator";'+
    'const phaseGates=[{payload:data.gate},{payload:data.pass}];'+
    'const isAncestor=async()=>true; const pullPrefix=data.pr;'+
    'const recurringFamilies=["secret-plaintext-boundary"];'+
    file.slice(file.indexOf('    const gate = maximal[0];'),
      file.indexOf('    const familyRecords = trustedMarkers'))+
    file.slice(file.indexOf("    if (record.schema_version === '1.1' &&"),
      file.indexOf('    if (!await isAncestor(designCommitSha'));
}else if(consumer==='refresh'){
  const file=fs.readFileSync(`${root}/.github/workflows/refresh-ai-loop-base.yml`,'utf8');
  source='const localReview=require("./local_review_evidence");'+
    'const {comments,core,exactKeys,singleMarker}=data; const authorization=data.gate;'+
    'const previousPhase="phase-0c", currentPhase="phase-0c", sourceIndex=3;'+
    'const expectedHeadSha=data.head, expectedPrPrefix=data.pr;'+
    'const labels=["ai-loop-blocked"], plan={phases:[{id:"phase-0a"},{id:"phase-0b"}]};'+
    file.slice(file.indexOf('            const passKeys = ['),
      file.indexOf('            if (isBlockedCurrentPhase) {'))+
    file.slice(file.indexOf('              const basePhase = '),
      file.indexOf('              const baseComparison = '));
}else{
  const file=fs.readFileSync(`${root}/.github/workflows/revalidate-blocked-phase.yml`,'utf8');
  source='const localReview=require("./local_review_evidence");'+
    'const {comments,core,exactKeys,singleMarker}=data;'+
    'const sourcePhase="phase-0c", priorPhase="phase-0b";'+
    'const reviewedHead=data.head,currentHead=data.head;'+
    'const review={html_url:data.gate.review_reference};'+
    'const isAncestor=async()=>true;'+
    'const hasPassingRequiredChecks=record=>JSON.stringify(record.required_checks)==='+
      'JSON.stringify(data.pass.required_checks);'+
    file.slice(file.indexOf('            const gateKeys = ['),
      file.indexOf('            const familyKeys = ['));
}
(async()=>{
  let error=null;
  try{await new AsyncFunction('require','data','process',source)(localRequire,data,{env:{
    AI_GATE_APPROVER_LOGIN:'operator',AI_REVIEWER_LOGIN:'cloud[bot]'}});}catch(caught){error=caught;}
  const expected=tamper==='none' && !(consumer==='recovery' && mode==='local-review-v1');
  assert.equal(error===null,expected,error?.stack);
})().catch(error=>{console.error(error);process.exitCode=1;});
"""
    process = subprocess.run(  # noqa: S603 - execute actual gate-selection code with fake records.
        [node, "-e", harness, str(REPO_ROOT), consumer, mode, base_mode, tamper],
        text=True, capture_output=True, check=False,
    )
    assert process.returncode == 0, process.stderr


@pytest.mark.parametrize("raw,accepted", [
    ('{"checks":[{"name":"a","status":"PASS"},{"name":"b","status":"PASS"}]}', True),
    ('{"phase":"phase-0c","phase":"phase-1"}', False),
    ('{"checks":[{"name":"a","name":"b","status":"PASS"}]}', False),
])
def test_recovery_marker_parser_rejects_duplicates_at_each_object_boundary(
    raw: str, accepted: bool,
) -> None:
    node = shutil.which("node")
    assert node is not None
    workflow = (REPO_ROOT / ".github/workflows/revalidate-blocked-phase.yml").read_text()
    source = workflow[workflow.index("            function singleMarker("):
                      workflow.index("            function exactKeys(")]
    harness = r"""
const gateParser = require(process.argv[1]);
const singleMarker = new Function('gateParser',process.argv[2]+';return singleMarker;')(gateParser);
let accepted=true;
try{singleMarker(`<!-- redteam-phase-gate\n${process.argv[3]}\n-->`,'redteam-phase-gate');}
catch(error){accepted=false;}
process.stdout.write(JSON.stringify(accepted));
"""
    process = subprocess.run(  # noqa: S603 - fixed local workflow parser and JSON fixture.
        [node, "-e", harness, str(REPO_ROOT / "automation/approve_design_resume.js"), source, raw],
        text=True, capture_output=True, check=True,
    )
    assert json.loads(process.stdout) is accepted


@pytest.mark.parametrize("scenario", [
    "pass", "findings", "recurrence", "ci-fail", "late-ci-fail", "default-drift",
    "late-default-drift", "late-stop", "late-head-drift", "late-report-edit",
    "missing-audit", "policy-tamper", "wrong-actor", "unknown-author", "native-trigger",
])
def test_local_review_workflow_uses_real_ci_and_preserves_gate_boundaries(scenario: str) -> None:
    node = shutil.which("node")
    assert node is not None
    workflow = (REPO_ROOT / ".github/workflows/ai-loop-control.yml").read_text()
    source = textwrap.dedent(workflow.split("          script: |\n", maxsplit=1)[1].split(
        "      - name: Perform marked", maxsplit=1,
    )[0])
    value = fixture(2 if scenario in {"findings", "recurrence"} else 0)
    harness = r"""
const fs = require('fs'), assert = require('node:assert/strict');
const root = process.argv[1], source = process.argv[2], scenario = process.argv[3];
const input = JSON.parse(fs.readFileSync(0, 'utf8'));
const helper = require(`${root}/automation/local_review_evidence.js`);
const plan = JSON.parse(fs.readFileSync(`${root}/automation/phase-plan.json`));
const families = JSON.parse(fs.readFileSync(`${root}/automation/invariant-families.json`));
const policy = JSON.parse(fs.readFileSync(`${root}/automation/local-execution-policy.json`));
const defaultSha = 'f'.repeat(40), phase = input.phase, head = input.headSha, base = input.baseSha;
const marker = (name, data) => `<!-- ${name}\n${helper.canonicalJson(data)}\n-->`;
const parsed = (item) => JSON.parse(item.body.split('\n')[1]);
const bot = (id, name, data) => ({html_url: `${input.pullRequestUrl}#issuecomment-${id}`,
  user: {login:'github-actions[bot]'}, body:`<!-- ${name}\n${JSON.stringify(data)}\n-->`,
  created_at:'2026-09-06T12:00:00Z', updated_at:'2026-09-06T12:00:00Z'});
const auditPath = `docs/review/${phase}-invariant-audit.json`;
const request = {schema_version:'1.0', action:'IMPLEMENT_PHASE', trigger:'PHASE_START',
  phase, head_sha:'e'.repeat(40), phase_prompt:`prompts/phases/${phase}.md`,
  invariant_audit: plan.invariant_audit};
const audit = {phase, request:{head_sha:request.head_sha,action:request.action,
  reference:`${input.pullRequestUrl}#issuecomment-5`},
  implementation_strategy:{version:'1.0',units:[{id:'example'}]}};
const auditMarker = {schema_version:'1.0',phase,head_sha:head,audit_path:auditPath,
  audit_digest:helper.canonicalDigest(audit),request_reference:audit.request.reference};
const ready = bot(1,'redteam-ready-for-review',{schema_version:'1.0',phase,head_sha:head});
if (scenario !== 'missing-audit') {
  ready.body += '\n' + marker('redteam-invariant-audit',auditMarker);
}
const binding = {audit_digest:auditMarker.audit_digest,audit_path:auditPath,
  base_sha:base,head_sha:head,phase,ready_url:input.readyReference,
  request_reference:audit.request.reference};
for (const item of [input.comments[0],input.comments.at(-1)]) {
  const data = parsed(item);
  data.policy_digest = helper.canonicalDigest(policy);
  data.source_digest = helper.canonicalDigest(binding);
  if (scenario === 'policy-tamper') data.policy_digest = '0'.repeat(64);
  item.body = marker(item === input.comments[0] ? helper.START_MARKER : helper.RESULT_MARKER,data);
}
if (scenario === 'unknown-author') input.comments.at(-1).user.login = 'untrusted';
if (scenario === 'native-trigger') {
  input.comments[0].body = `@codex review\n\nReview \`${head}\` against \`${base}\`.\n` +
    marker('redteam-local-codex-trigger', {schema_version:'1.0',kind:'review',phase,
      head_sha:head,source_digest:helper.canonicalDigest(binding)});
}
const result = parsed(input.comments.at(-1)).result;
const prior = {schema_version:'1.0',phase:'phase-0b',reviewed_sha:base,base_sha:'e'.repeat(40),
  verdict:'PASS',summary:'Historical independent PASS.',evidence_format:'codex-native-v1',
  ready_reference:`${input.pullRequestUrl}#issuecomment-8`,
  review_trigger_reference:`${input.pullRequestUrl}#issuecomment-9`,
  review_reference:`${input.pullRequestUrl}#issuecomment-7`,reviewer_login:'cloud[bot]',
  recorded_by:'operator',finding_key:null,required_checks:input.requiredCheckNames.map(
    name => ({name,status:'PASS'})),loop_state:'PASS'};
const comments = [bot(4,'redteam-phase-gate',prior),bot(5,'redteam-implementation-request',request),
  ready,...input.comments];
if (scenario === 'recurrence') comments.push(bot(6,'redteam-invariant-family-review',{
  schema_version:'1.0',phase,reviewed_sha:'e'.repeat(40),
  review_reference:`${input.pullRequestUrl}#issuecomment-77`,verdict:'CHANGES_REQUESTED',
  families:[result.findings[0].invariant_family]}));
const pr = {state:'open',head:{sha:head,repo:{full_name:'example/project'}},
  base:{ref:'main',sha:base},
  labels:[{name:'ai-loop'},{name:phase},{name:'ai-needs-review'}]};
const writes=[], failures=[], outputs={};
let pulls=0, checkReads=0, defaultReads=0, commentReads=0;
const files={'automation/phase-plan.json':plan,'automation/invariant-families.json':families,
  'automation/local-execution-policy.json':policy,[auditPath]:audit};
const github={rest:{
  pulls:{get:async()=>{const current=structuredClone(pr);pulls++;
    if(scenario==='late-stop'&&pulls>=2)current.labels.push({name:'ai-loop-blocked'});
    if(scenario==='late-head-drift'&&pulls>=2)current.head.sha='0'.repeat(40);
    return{data:current};},listReviews:'reviews',listReviewComments:'review-comments'},
  checks:{listForRef:'checks'},reactions:{listForIssue:'reactions'},
  repos:{getContent:async({path})=>{assert.ok(files[path],path);
    return{data:{type:'file',content:Buffer.from(JSON.stringify(files[path])).toString('base64')}};},
    getCommit:async()=>{defaultReads++;return{data:{sha:
      scenario==='default-drift'||(scenario==='late-default-drift'&&defaultReads>=2)
      ?'0'.repeat(40):defaultSha}};},
    createCommitStatus:async(data)=>writes.push(['status',data])},
  issues:{listComments:'comments',listEventsForTimeline:'timeline',
    createComment:async(data)=>{writes.push(['comment',data]);
      return{data:{html_url:`${input.pullRequestUrl}#issuecomment-100`}};},
    removeLabel:async(data)=>writes.push(['remove-label',data]),
    addLabels:async(data)=>writes.push(['add-label',data])},
},paginate:async(api)=>{
  if(api==='checks'){checkReads++;return input.requiredCheckNames.map(name=>({
    name,head_sha:head,conclusion:scenario==='ci-fail'||
      (scenario==='late-ci-fail'&&checkReads>=2)?'failure':'success'}));}
  if(api==='comments'){commentReads++;const items=structuredClone(comments);
    if(scenario==='late-report-edit'&&commentReads>=2){
      items.find(item=>item.html_url===input.reportReference).updated_at='2026-09-06T12:00:11Z';}
    return items;}
  return[];
},request:async(_route,{basehead})=>({data:{merge_base_commit:{sha:basehead.split('...')[0]},
  behind_by:0,status:'ahead'}})};
const context={actor:scenario==='wrong-actor'?'attacker':'operator',sha:defaultSha,
  ref:'refs/heads/main',
  repo:{owner:'example',repo:'project'},payload:{repository:{default_branch:'main'}}};
const core={setFailed:message=>failures.push(message),setOutput:(key,value)=>outputs[key]=value};
const environment={env:{GITHUB_WORKSPACE:root,AI_GATE_APPROVER_LOGIN:'operator',
  AI_REVIEWER_LOGIN:'cloud[bot]',AI_LOOP_MAX_ITERATIONS:'5',CONFIRMATION:'RECORD_PHASE_REVIEW',
  PR_NUMBER:'3',PHASE:phase,REVIEWED_SHA:head,BASE_SHA:base,VERDICT:result.verdict,
  REVIEW_REFERENCE:input.reportReference,READY_REFERENCE:input.readyReference,
  REVIEW_TRIGGER_REFERENCE:input.startReference,SUMMARY:result.summary,
  FINDING_KEY:result.findings[0]?.id||''}};
const AsyncFunction=Object.getPrototypeOf(async function(){}).constructor;
(async()=>{
  let error=null;
  try{await new AsyncFunction('github','context','core','process','require',source)(
    github,context,core,environment,require);}catch(caught){error=caught;}
  const success=['pass','findings','recurrence'].includes(scenario);
  if(!success){assert.equal(writes.length,0,JSON.stringify(writes));
    assert.ok(error||failures.length,'invalid evidence must fail closed');
    if(scenario==='native-trigger') assert.deepEqual(failures,[
      'New phase gates require local-review-v1 evidence; native reviews are historical only.']);
    return;}
  assert.equal(error,null,error?.stack);assert.deepEqual(failures,[]);
  const gateBody=writes.find(([kind,data])=>kind==='comment'&&
    data.body.includes('redteam-phase-gate'))[1].body;
  const gate=JSON.parse(gateBody.match(/<!-- redteam-phase-gate\n([\s\S]*?)\n-->/)[1]);
  assert.equal(gate.evidence_format,'local-review-v1');assert.equal(gate.reviewer_login,'operator');
  assert.equal(gate.recorded_by,'operator');assert.equal(gate.reviewed_sha,head);
  assert.deepEqual(gate.required_checks,input.requiredCheckNames.map(name=>({name,status:'PASS'})));
  const fix=writes.find(([kind,data])=>kind==='comment'&&data.body.includes('FIX_REVIEW_FINDINGS'));
  if(scenario==='findings'){
    assert.ok(fix);const request=JSON.parse(fix[1].body.match(
      /<!-- redteam-implementation-request\n([\s\S]*?)\n-->/)[1]);
    assert.equal(request.review.finding_count,2);
    assert.deepEqual(request.review.findings.map(item=>item.finding_key),result.findings.map(item=>item.id));
    assert.deepEqual(request.review.findings.map(item=>item.finding_reference),[
      `${input.pullRequestUrl}#issuecomment-10`,`${input.pullRequestUrl}#issuecomment-11`]);
  }else assert.equal(fix,undefined);
  if(scenario==='recurrence'){
    assert.equal(gate.stop_reason,'INVARIANT_FAMILY_RECURRENCE');assert.equal(gate.loop_state,'BLOCKED_LIMIT');
    assert.deepEqual(gate.recurring_families,[result.findings[0].invariant_family]);
  }
})().catch(error=>{console.error(error);process.exitCode=1;});
"""
    process = subprocess.run(  # noqa: S603 - real workflow with fixed, entirely fake GitHub APIs.
        [node, "-e", harness, str(REPO_ROOT), source, scenario],
        input=json.dumps(value), text=True, capture_output=True, check=False,
    )
    assert process.returncode == 0, process.stderr
