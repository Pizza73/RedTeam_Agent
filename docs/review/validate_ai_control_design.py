"""Read-only checks for the design document, not the application/phase gate."""

import ast
import inspect
import itertools
import re
from enum import Enum
from hashlib import sha256
from pathlib import Path

# A fixed local reference model; never execute code extracted from Markdown.
# The enum's functional form preserves the documented str/Enum semantics.
Truth = Enum('Truth', {'TRUE': 'true', 'FALSE': 'false', 'UNKNOWN': 'unknown'}, type=str)


def evaluate_goal(mode: str, values: tuple[Truth, ...]) -> str:
    if mode not in ("all", "any") or not values:
        raise ValueError("invalid_goal_model")
    if any(not isinstance(value, Truth) for value in values):
        raise ValueError("invalid_truth")
    if mode == "all":
        if all(value is Truth.TRUE for value in values):
            return "achieved"
        if any(value is Truth.FALSE for value in values):
            return "not_achieved"
    else:
        if any(value is Truth.TRUE for value in values):
            return "achieved"
        if all(value is Truth.FALSE for value in values):
            return "not_achieved"
    return "indeterminate"


def next_step(*, security_error: bool, finalization_required: bool,
              running: bool, execution_pending: bool, goal: str,
              approval_pending: bool, candidates_ready: bool,
              source_read_pending: bool) -> str:
    flags = (security_error, finalization_required, running, execution_pending,
             approval_pending, candidates_ready, source_read_pending)
    if any(type(flag) is not bool for flag in flags):
        raise ValueError("invalid_control_input")
    if goal not in ("achieved", "not_achieved", "indeterminate"):
        raise ValueError("invalid_goal_result")
    if security_error:
        return "security_stop"
    if finalization_required:
        return "finalize_or_cleanup"
    if not running:
        return "hold"
    if execution_pending:
        return "recover_existing"
    if goal == "achieved":
        return "finalize_goal"
    if approval_pending:
        return "wait_approval"
    if candidates_ready:
        return "plan"
    if source_read_pending:
        return "wait_source"
    return "pause_with_reason"


ROOT = Path(__file__).resolve().parents[2]
NEW = ROOT / 'SystemDesign_AI_Control.md'
CANONICAL = ROOT / 'SystemDesign.md'
ARCHIVE = ROOT / 'SystemDesign_update.md'
text = NEW.read_text()
canonical = CANONICAL.read_text()
archive = ARCHIVE.read_text()

REPORT = ROOT / 'docs/review/ai-control-research-review.md'
related_paths = [ROOT / name for name in (
    'docs/requirements.md', 'docs/safety-invariants.md', 'docs/acceptance-criteria.md',
    'docs/implementation-status.md', 'docs/threat-model.md',
    'docs/review/phase-0c-coherent-redesign.md',
    'docs/review/systemdesign-canonical-adoption.md',
    'docs/review/current-design-research-assessment.md',
    'docs/review/ai-control-implementation-ready.md',
    'prompts/phases/phase-0c.md', 'prompts/phases/phase-1.md', 'prompts/phases/phase-2.md',
)]
documents = [(NEW, text), (CANONICAL, canonical), (ARCHIVE, archive),
             (REPORT, REPORT.read_text())]
documents.extend((path, path.read_text()) for path in related_paths)
for path, content in documents:
    fence_lines = [line for line in content.splitlines() if line.startswith('```')]
    assert len(fence_lines) % 2 == 0, (path, 'unpaired_fence')
    for label, target in re.findall(r'\[([^\]\n]+)\]\(([^)\n]+)\)', content):
        if target.startswith(('http://', 'https://', '#')):
            continue
        # Existing examples contain illustrative placeholders, not file links.
        if '<' in target or '>' in target:
            continue
        target_path = target.split('#', 1)[0]
        assert (path.parent / target_path).is_file(), (path, label, target)

blocks = re.findall(r'```python\n(.*?)\n```', text, re.S)
assert len(blocks) == 1
assert 'ai-control-reference-model-v1' in blocks[0]
reference = ast.parse(blocks[0])
expected_prefix = ast.parse('''from enum import Enum
class Truth(str, Enum):
    TRUE = "true"
    FALSE = "false"
    UNKNOWN = "unknown"
''').body
expected_nodes = expected_prefix + [
    ast.parse(inspect.getsource(function)).body[0]
    for function in (evaluate_goal, next_step)
]
assert [ast.dump(node) for node in reference.body] == [
    ast.dump(node) for node in expected_nodes
], 'reference_model_drift_or_unexpected_code'
evaluate = evaluate_goal
choose = next_step

goal_cases = 0
for size in range(1, 5):
    for values in itertools.product(Truth, repeat=size):
        interpretations = [
            (False, True) if v is Truth.UNKNOWN else (v is Truth.TRUE,)
            for v in values
        ]
        completions = list(itertools.product(*interpretations))
        for mode, aggregate in [('all', all), ('any', any)]:
            possible_results = {aggregate(completion) for completion in completions}
            expected = (
                'achieved' if possible_results == {True}
                else 'not_achieved' if possible_results == {False}
                else 'indeterminate'
            )
            assert evaluate(mode, values) == expected, (mode, values, expected)
            assert evaluate(mode, values) == evaluate(mode, tuple(reversed(values)))
            goal_cases += 1

keys = ('security_error', 'finalization_required', 'running', 'execution_pending',
        'approval_pending', 'candidates_ready', 'source_read_pending')
routes = set()
controller_cases = 0
for flags in itertools.product((False, True), repeat=len(keys)):
    values = dict(zip(keys, flags, strict=True))
    for goal in ('achieved', 'not_achieved', 'indeterminate'):
        predicates = [
            (values['security_error'], 'security_stop'),
            (values['finalization_required'], 'finalize_or_cleanup'),
            (not values['running'], 'hold'),
            (values['execution_pending'], 'recover_existing'),
            (goal == 'achieved', 'finalize_goal'),
            (values['approval_pending'], 'wait_approval'),
            (values['candidates_ready'], 'plan'),
            (values['source_read_pending'], 'wait_source'),
            (True, 'pause_with_reason'),
        ]
        expected = next(route for matches, route in predicates if matches)
        actual = choose(**values, goal=goal)
        assert actual == expected, (values, goal, actual, expected)
        routes.add(actual)
        controller_cases += 1
    assert choose(**values, goal='not_achieved') == choose(**values, goal='indeterminate')
assert len(routes) == 9, routes

invalid_cases = 0
invalid_goal_inputs = [('', (Truth.TRUE,)), ('all', ()), ('any', ('true',)),
                       ('ALL', (Truth.FALSE,)), ('all', (None,))]
for mode, values in invalid_goal_inputs:
    try:
        evaluate(mode, values)
    except ValueError:
        invalid_cases += 1
    else:
        raise AssertionError(('accepted_invalid_goal', mode, values))
base = dict.fromkeys(keys, False)
for key in keys:
    for bad in (0, 1, None, 'false'):
        values = base | {key: bad}
        try:
            choose(**values, goal='indeterminate')
        except ValueError:
            invalid_cases += 1
        else:
            raise AssertionError(('accepted_invalid_flag', key, bad))
try:
    choose(**base, goal='success')
except ValueError:
    invalid_cases += 1
else:
    raise AssertionError('accepted_invalid_goal_result')

invariants = re.findall(r'^\| (AI-\d{2}) \|', text, re.M)
scenario_rows = re.findall(r'^\| (AC-\d{2}) \| (.+)$', text, re.M)
assert invariants == [f'AI-{n:02}' for n in range(1, 13)]
assert [key for key, _ in scenario_rows] == [f'AC-{n:02}' for n in range(1, 21)]
covered = set()
for key, row in scenario_rows:
    ids = set(re.findall(r'AI-\d{2}', row))
    assert ids and ids <= set(invariants), (key, ids)
    covered.update(ids)
assert covered == set(invariants)
assert '`NOT_EVALUATED`' in text
assert 'SystemDesign_AI_Control.md' in canonical
assert '必須の規範別冊' in canonical
assert 'system-design-v1-r1' in canonical
assert 'ai-control-v1-r1' in text
assert '比較用スナップショット' in archive.split('# 1. 目的', 1)[0]
assert 'SystemDesign.md' in archive.split('# 1. 目的', 1)[0]

# Narrow regression checks for the concrete adoption conflicts, not a semantic proof.
by_path = {str(path.relative_to(ROOT)): content for path, content in documents}
for name in ('docs/requirements.md', 'prompts/phases/phase-0c.md',
             'prompts/phases/phase-1.md', 'prompts/phases/phase-2.md'):
    assert 'SystemDesign_AI_Control.md' in by_path[name], ('missing_companion', name)
for name in ('docs/safety-invariants.md', 'docs/acceptance-criteria.md',
             'prompts/phases/phase-0c.md'):
    content = by_path[name]
    assert 'NV Extend' in content and 'local_capture' in content, name
    assert 'NOT_EVALUATED' in content and 'Activation Lock' in content, name
    for obsolete in ('TPM Current Generation', 'Provisioned NV Identity、Counter 0',
                     'Namespace別TPM 2.0 NV Monotonic Witness', 'DB/migrations'):
        assert obsolete not in content, ('obsolete_foundation_contract', name, obsolete)
assert 'Indeterminate handler' not in by_path['prompts/phases/phase-1.md']
assert 'Historical scope — superseded implementation details' in by_path[
    'docs/review/phase-0c-coherent-redesign.md']

# This is a documentation drift check, not proof of enforcement in product code.
active = canonical.split('# 41. Revision Summary', 1)[0]
obsolete_patterns = ('class GoalRoutingRecord(', 'class GoalRoutingHead(',
                 'goal_routing_head_version:', 'goal_routing_head_digest:',
                 'goal_routing_record_id:', 'planning_mode:', 'minimum_confidence:',
                 'investigation_rule_ids:', 'Indeterminate Handler',
                 'Current Routing', '| `GoalRoutingAggregate`', 'HANDLING_INDETERMINATE')
for obsolete in obsolete_patterns:
    assert obsolete not in active, ('obsolete_runtime_contract', obsolete)
assert 'generation-witness-policy-v5' in active
assert 'generation-witness-policy-v5' in text
assert '§41の改訂履歴' in text
assert '### 5.3 契約・候補の実装境界' in text


def diagrams_match_contract(content: str) -> bool:
    """Check specific diagram regressions, not arbitrary prose semantics."""
    diagrams = re.findall(r'```text\n(.*?)\n```', content, re.S)

    def ordered(start: str, markers: tuple[str, ...]) -> bool:
        matches = [block for block in diagrams if block.strip().startswith(start)]
        if len(matches) != 1:
            return False
        block = matches[0]
        if not all(marker in block for marker in markers):
            return False
        positions = [block.index(marker) for marker in markers]
        return positions == sorted(positions)

    return all((
        ordered('Operator', (
            'Unified Controller Entry Guard (§24.1)',
            'Security / Hard Limit / Mission State / Pending Execution',
            'Session Refresh', 'Current Goal Evaluation',
            'PlannerOutput', 'context_request', 'Executionなし', 'ExecutionPlanProposal',
            'Verified Source Updates (Analyzer非依存)',
            'Source Normalizer / Knowledge Service', 'Current Knowledge / Critical Witness',
            'Analyzer Context Selector',
            'NOT_ACHIEVED  INDETERMINATE  ACHIEVED',
            'Current安全状態・未完了Executionを再検証',
        )),
        ordered('START\n', (
            'Unified Controller Entry Guard', 'security error',
            'hard limit / finalization required', 'not RUNNING', 'pending execution',
            'Session Refresh', 'Current Goal / Unified Controller', 'achieved',
            'approval pending', 'Contract-based Candidate Selection',
            'PlannerOutput', 'context_request', 'Executionなし', 'ExecutionPlanProposal',
            'Verified Source Updates（Analyzer非依存）',
            'Source Normalizer / Knowledge Service', 'Current Knowledge / Critical Witness',
            'Analyzer Context Selector', 'Next Iteration -> 共通Controller Entry Guard',
        )),
        ordered('PreparePlannerInput\n', (
            'Current Mission / Epoch / Security / Limits', 'security error',
            'hard limit / finalization required', 'not RUNNING', 'pending execution',
            '許可されたSource Refresh', 'Current Goal Evaluation',
            '同じUnified Controller（上位分岐を再検証）', 'achieved', 'approval pending',
            'ActionContract候補化', 'context_request', 'Executionなし',
        )),
    ))


assert diagrams_match_contract(canonical), 'diagram_contract_drift'
diagram_mutation_cases = [
    ('PlannerOutput', 'UnconditionalAction'),
    ('context_request', 'always_execute'),
    ('Executionなし', 'Executionあり'),
    ('Verified Source Updates', 'AnalyzerOnlyUpdates'),
    ('Source Normalizer / Knowledge Service', 'AnalyzerOnlyOwner'),
    ('Current Knowledge / Critical Witness', 'UnverifiedKnowledge'),
    ('Unified Controller Entry Guard', 'NoEntryGuard'),
    ('Current安全状態・未完了Executionを再検証', 'SkipCurrentChecks'),
    ('Next Iteration -> 共通Controller Entry Guard', 'Next Iteration -> Planner'),
    ('pending execution', 'ignore_pending'),
    ('同じUnified Controller（上位分岐を再検証）', 'DirectGoalFinalization'),
    ('approval pending', 'skip_approval_wait'),
]
for old, new in diagram_mutation_cases:
    mutated = canonical.replace(old, new)
    assert mutated != canonical and not diagrams_match_contract(mutated), old
# A concrete priority inversion must fail even though both labels remain present.
priority_inversion = canonical.replace('pending execution', 'swap_priority_marker')
priority_inversion = priority_inversion.replace('security error', 'pending execution')
priority_inversion = priority_inversion.replace('swap_priority_marker', 'security error')
assert not diagrams_match_contract(priority_inversion)

preparation = by_path['docs/review/ai-control-implementation-ready.md']
task_rows = re.findall(r'^\| (T[1-8]) \| (.+)$', preparation, re.M)
assert [key for key, _ in task_rows] == [f'T{n}' for n in range(1, 9)]
explicit_ac_coverage = set()
for _, row in task_rows:
    explicit_ac_coverage.update(re.findall(r'AC-\d{2}', row))
assert explicit_ac_coverage == {f'AC-{n:02}' for n in range(1, 21)}
assert re.findall(r'^\| (TR-\d{2}) \|', preparation, re.M) == [
    f'TR-{n:02}' for n in range(1, 9)
]
assert '`NOT_EVALUATED`' in preparation
assert '実Schema / Contract / Rule / Source Capability / 独立Fixture' in preparation

required_fields = {
    'ExecutionPlan': {'action_contract_ref', 'execution_precondition_digest',
                      'goal_evaluation_id', 'goal_evaluation_digest'},
    'PlannerContextEnvelope': {'action_candidate_projection', 'action_candidate_digest'},
    'ToolDefinition': {'action_contract_ref'},
    'CandidateObservation': {'llm_confidence'},
    'GoalStatus': {'status'},
}
seen = {}
for block in re.findall(r'```python\n(.*?)\n```', active, re.S):
    for node in ast.parse(block).body:
        if isinstance(node, ast.ClassDef) and node.name in required_fields:
            assert node.name not in seen, ('duplicate_model', node.name)
            seen[node.name] = {
                item.target.id for item in node.body
                if isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name)
            }
assert set(seen) == set(required_fields)
for model, fields in required_fields.items():
    assert fields <= seen[model], ('missing_model_field', model, fields - seen[model])
assert 'confidence' not in seen['CandidateObservation']
assert 'achieved' not in seen['GoalStatus']


canonical_python_blocks = re.findall(r'```python\n(.*?)\n```', canonical, re.S)
for block in canonical_python_blocks:
    ast.parse(block)

print(f'DOC_STRUCTURE=PASS; local links/fences; invariant coverage={len(covered)}/12; scenarios=20')
print(f'GOAL_REFERENCE_MODEL=PASS; combinations={goal_cases}; lengths=1..4; possible-world oracle')
print(f'CONTROLLER_REFERENCE_MODEL=PASS; combinations={controller_cases}; branches={len(routes)}/9')
print(f'UNKNOWN_IS_NOT_GLOBAL_DENY=PASS; flag combinations={2 ** len(keys)}')
print(f'INVALID_REFERENCE_INPUTS=PASS; rejected={invalid_cases}')
print(f'CROSS_DOCUMENT_CONTRACT=PASS; obsolete runtime patterns={len(obsolete_patterns)}; '
      f'connection models={len(seen)}')
print(f'CANONICAL_ADOPTION=PASS; checked documents={len(documents)}; '
      'archive/historical boundary; foundation markers')
print('ARCHITECTURE_DIAGRAMS=PASS; diagrams=3; '
      f'rejected mutations={len(diagram_mutation_cases) + 1}; not semantic or runtime proof')
print('IMPLEMENTATION_PREPARATION=PASS; task units=8; explicit AC mapping=20/20; '
      'trace outlines=8; not executable fixtures')
print(f'PYTHON_SNIPPETS_AST=PASS; ai={len(blocks)}; canonical={len(canonical_python_blocks)}')
print('NOT_RUN: application authorization/proofs/dispatch/recovery; '
      'AC integration tests; phase gate; real LLM; TPM')
# Fingerprint only the reviewed document wording, not executable authorization.
# Future semantic changes need a new review; absence of the old rule alone cannot pass.
approved_erasure_text_sha256 = '7d50ea7f5879bc4e51fc098dcb31eed02b38c28427a3ecdb519b1a2b2c70f22f'
erasure_start = '- Caller-created receipts,'
erasure_end = '- Secret Store, raw-result quarantine,'


def matches_reviewed_erasure_text(instructions: str) -> bool:
    if instructions.count(erasure_start) != 1 or instructions.count(erasure_end) != 1:
        return False
    after_start = instructions.split(erasure_start, 1)[1]
    if erasure_end not in after_start:
        return False
    rule = after_start.split(erasure_end, 1)[0]
    normalized = ' '.join(rule.split()).encode()
    return sha256(normalized).hexdigest() == approved_erasure_text_sha256


instructions = (ROOT / 'AGENTS.md').read_text()
assert matches_reviewed_erasure_text(instructions), 'erasure_document_review_required'
assert matches_reviewed_erasure_text(instructions.replace('\n  ', '\n    '))
assert matches_reviewed_erasure_text(instructions.replace(' and ', '  and  '))
erasure_negative_cases = [
    '', instructions.replace(erasure_start, ''), instructions.replace(erasure_end, ''),
    instructions + '\n' + erasure_start,
    instructions.replace('`post_ingestion` requires', '`retention_expiry` requires'),
    instructions.replace('requires committed Collection `COMPLETE`',
                         'requires committed Collection `STREAMING`'),
    instructions.replace('no committed manifest', 'any manifest state'),
    instructions.replace('has been reached', 'need not have been reached'),
    instructions.replace('durable Collection `ABANDONED`', 'any collection state'),
    instructions.replace('partial ciphertext digest/size', 'optional ciphertext metadata'),
    instructions.replace('copy-inventory digest', 'optional inventory'),
    instructions.replace('same expected state version', 'any state version'),
    instructions.replace('OCC state transition', 'unchecked transition'),
    instructions.replace('completes the required witness', 'skips the witness'),
    instructions.replace('permits reconciliation only', 'permits another Destroy'),
    instructions.replace('read-back-verified `CONFIRMED`', 'unverified key status'),
    instructions.replace('must not fabricate a successful result', 'may fabricate a result'),
    erasure_start + ' Durable manifest verification precedes every erasure.\n' + erasure_end,
]
for case in erasure_negative_cases:
    assert case != instructions and not matches_reviewed_erasure_text(case)
print('ERASURE_RULE_DOCUMENT_ALIGNMENT=PASS; reviewed wording and whitespace variants=3; '
      f'rejected mutations={len(erasure_negative_cases)}; not runtime or PR authority')
