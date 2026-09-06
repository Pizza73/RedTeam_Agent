'use strict';

// The approved launcher/operator host is the TCB. These records are NOT signed
// by a separate reviewer identity. The worker cannot publish or authorize gates.
// All inputs here must be freshly fetched by the trusted workflow; successful
// parsing never substitutes for current PR, ancestry, CI or isolation checks.
const crypto = require('crypto');

const START_MARKER = 'redteam-local-review-start';
const RESULT_MARKER = 'redteam-local-review-result';
const FINDING_MARKER = 'redteam-local-review-finding';
const COMMON_KEYS = [
  'schema_version', 'phase', 'head_sha', 'base_sha', 'ready_reference',
  'source_digest', 'policy_digest', 'run_id', 'started_at',
];
const RESULT_KEYS = [
  ...COMMON_KEYS, 'start_reference', 'reviewer_session_id', 'completed_at',
  'result', 'finding_references',
];
const FINDING_KEYS = [
  'id', 'severity', 'invariant_family', 'requirement_id', 'evidence',
  'required_fix', 'retest',
];
const SHA = /^[0-9a-f]{40}$/;
const DIGEST = /^[0-9a-f]{64}$/;
const RUN_UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SESSION_UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const PHASE = /^phase-(0a|0b|0c|[1-5])$/;
const FINDING_ID = /^[A-Z][A-Z0-9._-]{0,63}$/;
const MAX_BYTES = 60000;

class LocalReviewEvidenceError extends Error {}

function requireCondition(condition, message) {
  if (!condition) throw new LocalReviewEvidenceError(message);
}

function exactKeys(value, keys) {
  return value !== null && typeof value === 'object' && !Array.isArray(value) &&
    JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...keys].sort());
}

function canonicalValue(value, depth = 0) {
  requireCondition(depth <= 32, 'Local review JSON exceeds maximum nesting.');
  if (Array.isArray(value)) return value.map((item) => canonicalValue(item, depth + 1));
  if (value !== null && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map(
      (key) => [key, canonicalValue(value[key], depth + 1)]
    ));
  }
  requireCondition(value === null || ['string', 'boolean'].includes(typeof value) ||
    (typeof value === 'number' && Number.isFinite(value)), 'Invalid JSON scalar.');
  return value;
}

function canonicalJson(value) {
  return JSON.stringify(canonicalValue(value));
}

function canonicalDigest(value) {
  return crypto.createHash('sha256').update(canonicalJson(value)).digest('hex');
}

function strictJsonParse(raw) {
  requireCondition(typeof raw === 'string' && Buffer.byteLength(raw, 'utf8') <= MAX_BYTES,
    'Local review JSON exceeds the byte limit.');
  let value;
  try {
    value = JSON.parse(raw);
  } catch (_) {
    throw new LocalReviewEvidenceError('Local review marker is not valid JSON.');
  }
  // Closed canonical decoding rejects duplicate keys at ANY depth: JSON.parse
  // discards a duplicate, so the result can never round-trip to that input.
  // Repeated keys in distinct finding objects are valid and remain unchanged.
  requireCondition(canonicalJson(value) === raw,
    'Local review JSON is noncanonical or contains duplicate keys.');
  return value;
}

function marker(body, name) {
  requireCondition(typeof body === 'string' && Buffer.byteLength(body, 'utf8') <= MAX_BYTES,
    'Local review comment exceeds the byte limit.');
  const matches = [...body.matchAll(new RegExp(`<!--\\s*${name}\\s*([\\s\\S]*?)-->`, 'g'))];
  requireCondition(matches.length === 1, 'Local review comment must contain exactly one marker.');
  return strictJsonParse(matches[0][1].trim());
}

function timestamp(value) {
  requireCondition(typeof value === 'string' &&
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/.test(value),
  'Local review timestamp is not an exact UTC timestamp.');
  const parsed = Date.parse(value);
  requireCondition(Number.isFinite(parsed) &&
    new Date(parsed).toISOString() === value.replace(/(?<!\.\d{3})Z$/, '.000Z'),
  'Local review timestamp is invalid.');
  return parsed;
}

function nonempty(value, maximum = 4000) {
  return typeof value === 'string' && value.trim().length > 0 && value.length <= maximum;
}

function requireReference(reference, pullRequestUrl) {
  requireCondition(typeof pullRequestUrl === 'string' &&
    /^https:\/\/github\.com\/[^/?#]+\/[^/?#]+\/pull\/[1-9][0-9]*$/.test(pullRequestUrl),
  'Expected pull request URL is invalid.');
  requireCondition(typeof reference === 'string' &&
    reference.startsWith(`${pullRequestUrl}#issuecomment-`) &&
    /^[1-9][0-9]*$/.test(reference.slice(`${pullRequestUrl}#issuecomment-`.length)),
  'Local review reference is not an exact comment permalink on this PR.');
}

function validateEnvelopeShared(envelope, expected) {
  requireCondition(envelope !== null && typeof envelope === 'object' &&
    envelope.schema_version === '1.0' && PHASE.test(envelope.phase) &&
    SHA.test(envelope.head_sha) && SHA.test(envelope.base_sha) &&
    DIGEST.test(envelope.source_digest) && DIGEST.test(envelope.policy_digest) &&
    RUN_UUID.test(envelope.run_id), 'Local review envelope binding is malformed.');
  const bindings = {
    phase: expected.phase, head_sha: expected.headSha, base_sha: expected.baseSha,
    ready_reference: expected.readyReference, source_digest: expected.sourceDigest,
    policy_digest: expected.policyDigest,
  };
  for (const [key, value] of Object.entries(bindings)) {
    requireCondition(envelope[key] === value, `Local review ${key} binding is stale.`);
  }
  requireReference(envelope.ready_reference, expected.pullRequestUrl);
  timestamp(envelope.started_at);
  return envelope;
}

function commentByReference(comments, reference, expected) {
  requireReference(reference, expected.pullRequestUrl);
  const matching = comments.filter((item) => item?.html_url === reference);
  requireCondition(matching.length === 1, 'Local review comment is missing or ambiguous.');
  const comment = matching[0];
  requireCondition(nonempty(expected.operatorLogin, 100) &&
    comment.user?.login === expected.operatorLogin, 'Local review comment author is untrusted.');
  requireCondition(timestamp(comment.created_at) === timestamp(comment.updated_at),
    'Edited local review comments are not authority.');
  return comment;
}

function validateFinding(finding, familyIds) {
  requireCondition(exactKeys(finding, FINDING_KEYS) && FINDING_ID.test(finding.id) &&
    ['HIGH', 'BLOCKER'].includes(finding.severity) &&
    familyIds.includes(finding.invariant_family) &&
    nonempty(finding.requirement_id, 200) && nonempty(finding.evidence) &&
    nonempty(finding.required_fix) && Array.isArray(finding.retest) &&
    finding.retest.length > 0 && finding.retest.length <= 20 &&
    finding.retest.every((item) => nonempty(item, 1000)),
  'Local review finding is malformed, incomplete or not P0/P1.');
}

function validateResult(result, expected) {
  requireCondition(exactKeys(result, [
    'schema_version', 'phase', 'reviewed_sha', 'base_sha', 'verdict', 'summary',
    'findings', 'required_checks',
  ]) && result.schema_version === '1.0' && result.phase === expected.phase &&
    result.reviewed_sha === expected.headSha && result.base_sha === expected.baseSha &&
    ['PASS', 'CHANGES_REQUESTED', 'BLOCKED'].includes(result.verdict) &&
    nonempty(result.summary, 500) && Array.isArray(result.findings) &&
    result.findings.length <= 100, 'Local review result is malformed or stale.');
  requireCondition(Array.isArray(expected.familyIds) && expected.familyIds.length > 0 &&
    new Set(expected.familyIds).size === expected.familyIds.length &&
    expected.familyIds.every((value) => typeof value === 'string' &&
      /^[a-z][a-z0-9-]{2,63}$/.test(value)), 'Trusted local review family policy is invalid.');
  for (const finding of result.findings) validateFinding(finding, expected.familyIds);
  requireCondition(new Set(result.findings.map((item) => item.id)).size === result.findings.length,
    'Local review finding identities are duplicated.');
  requireCondition((result.verdict !== 'PASS' || result.findings.length === 0) &&
    (result.verdict !== 'CHANGES_REQUESTED' || result.findings.length > 0),
  'Local review verdict contradicts its findings.');
  const checks = result.required_checks;
  requireCondition(Array.isArray(expected.requiredCheckNames) &&
    expected.requiredCheckNames.length > 0 &&
    new Set(expected.requiredCheckNames).size === expected.requiredCheckNames.length &&
    Array.isArray(checks) && checks.length === expected.requiredCheckNames.length &&
    checks.every((item, index) => exactKeys(item, ['name', 'status']) &&
      item.name === expected.requiredCheckNames[index] &&
      ['PASS', 'FAIL', 'MISSING'].includes(item.status)),
  'Local review check projection is malformed.');
  // These statuses are reporting only. The caller MUST freshly verify real CI.
  return result;
}

function isTrustedGateEvidence(record, cloudReviewer, operator) {
  // This is only the format/identity discriminator. Consumers independently
  // verify the bot author, recorded_by, exact closed gate shape and all bindings.
  if (!record || !nonempty(operator, 100)) return false;
  if (record.evidence_format === 'codex-native-v1') {
    return nonempty(cloudReviewer, 100) && record.reviewer_login === cloudReviewer;
  }
  return record.evidence_format === 'local-review-v1' && record.reviewer_login === operator;
}

function isGateFindingReference(record, reference, pullRequestUrl) {
  if (!record || typeof reference !== 'string' || typeof pullRequestUrl !== 'string' ||
      !/^https:\/\/github\.com\/[^/?#]+\/[^/?#]+\/pull\/[1-9][0-9]*$/.test(pullRequestUrl)) {
    return false;
  }
  const suffix = record.evidence_format === 'local-review-v1' ? '#issuecomment-' :
    record.evidence_format === 'codex-native-v1' ? '#discussion_r' : null;
  if (suffix === null || !reference.startsWith(pullRequestUrl + suffix)) return false;
  return /^[1-9][0-9]*$/.test(reference.slice((pullRequestUrl + suffix).length));
}

function evaluateLocalReview(expected) {
  const {comments, timeline} = expected;
  requireCondition(Array.isArray(comments) && Array.isArray(timeline),
    'Local review requires complete comments and timeline.');
  const startComment = commentByReference(comments, expected.startReference, expected);
  const reportComment = commentByReference(comments, expected.reportReference, expected);
  const start = marker(startComment.body, START_MARKER);
  const report = marker(reportComment.body, RESULT_MARKER);
  requireCondition(exactKeys(start, COMMON_KEYS) && exactKeys(report, RESULT_KEYS),
    'Local review envelope has missing or unknown fields.');
  validateEnvelopeShared(start, expected);
  validateEnvelopeShared(report, expected);
  requireCondition(COMMON_KEYS.every((key) => report[key] === start[key]) &&
    report.start_reference === expected.startReference && SESSION_UUID.test(report.reviewer_session_id) &&
    report.reviewer_session_id !== start.run_id,
  'Local review result is not bound to its fresh reviewer run.');
  const readyTime = timestamp(expected.readyCreatedAt);
  const startTime = timestamp(startComment.created_at);
  const reportTime = timestamp(reportComment.created_at);
  const completedTime = timestamp(report.completed_at);
  requireCondition(readyTime <= timestamp(start.started_at) &&
    timestamp(start.started_at) <= startTime && startTime < reportTime &&
    startTime <= completedTime && completedTime <= reportTime,
  'Local review evidence order is invalid.');

  let startCount = 0;
  let reportCount = 0;
  const publishedFindingReferences = [];
  for (const comment of comments) {
    if (comment?.user?.login !== expected.operatorLogin || typeof comment.body !== 'string') continue;
    for (const [name, kind] of [[START_MARKER, 'start'], [RESULT_MARKER, 'result']]) {
      if (!comment.body.includes(name)) continue;
      const payload = marker(comment.body, name);
      if (payload.run_id === start.run_id ||
          (payload.phase === expected.phase && payload.head_sha === expected.headSha)) {
        requireCondition(payload.run_id === start.run_id &&
          (kind === 'start' ? comment.html_url === expected.startReference :
            comment.html_url === expected.reportReference),
        'Local review run or current-HEAD request has competing evidence.');
        if (kind === 'start') startCount += 1;
        else reportCount += 1;
      }
    }
    if (comment.body.includes(FINDING_MARKER)) {
      const payload = marker(comment.body, FINDING_MARKER);
      if (payload.run_id === start.run_id) publishedFindingReferences.push(comment.html_url);
    }
  }
  requireCondition(startCount === 1 && reportCount === 1,
    'Local review run must have exactly one start and result.');
  for (const event of timeline) {
    if (event?.event !== 'synchronize') continue;
    const at = timestamp(event.created_at);
    requireCondition(!(startTime < at && at <= reportTime),
      'PR head changed while local review was running.');
  }
  const result = validateResult(report.result, expected);
  const references = report.finding_references;
  requireCondition(Array.isArray(references) && references.length === result.findings.length &&
    new Set(references).size === references.length &&
    JSON.stringify([...references].sort()) ===
      JSON.stringify([...publishedFindingReferences].sort()),
  'Local review must retain every published finding exactly once.');
  const currentFindings = result.findings.map((finding, index) => {
    const reference = references[index];
    const comment = commentByReference(comments, reference, expected);
    const payload = marker(comment.body, FINDING_MARKER);
    requireCondition(exactKeys(payload, [
      'schema_version', 'run_id', 'phase', 'head_sha', 'base_sha', 'finding',
    ]) && payload.schema_version === '1.0' && payload.run_id === start.run_id &&
      payload.phase === expected.phase && payload.head_sha === expected.headSha &&
      payload.base_sha === expected.baseSha &&
      canonicalJson(payload.finding) === canonicalJson(finding),
    'Local review finding comment differs from the complete report.');
    const findingTime = timestamp(comment.created_at);
    requireCondition(startTime < findingTime && findingTime <= reportTime,
      'Local review finding publication is outside its run.');
    return {
      ...finding, finding_key: finding.id, html_url: reference,
      body: `${finding.evidence}\n\nInvariant family: \`${finding.invariant_family}\``,
    };
  });
  return {
    result, start, report, currentFindings,
    currentFamilies: [...new Set(result.findings.map((item) => item.invariant_family))].sort(),
    completedTime, reviewerLogin: expected.operatorLogin, evidenceFormat: 'local-review-v1',
  };
}

module.exports = {
  LocalReviewEvidenceError, START_MARKER, RESULT_MARKER, FINDING_MARKER,
  canonicalJson, canonicalDigest, strictJsonParse, validateEnvelopeShared,
  isTrustedGateEvidence, isGateFindingReference, evaluateLocalReview,
};
