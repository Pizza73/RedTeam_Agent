'use strict';

const crypto = require('crypto');
const loopControl = require('./loop_control_state');
const localReview = require('./local_review_evidence');

const PHASES = [
  'phase-0a', 'phase-0b', 'phase-0c', 'phase-1',
  'phase-2', 'phase-3', 'phase-4', 'phase-5',
];
const REQUIRED_CHECKS = [
  'tests (3.12)', 'tests (3.14)', 'quality', 'governance-integrity',
];
const BASE_GATE_KEYS = [
  'schema_version', 'phase', 'reviewed_sha', 'base_sha', 'verdict', 'summary',
  'evidence_format', 'ready_reference', 'review_trigger_reference',
  'review_reference', 'reviewer_login', 'recorded_by', 'finding_key',
  'required_checks', 'loop_state',
];
const DESIGN_GATE_KEYS = [
  ...BASE_GATE_KEYS, 'stop_reason', 'recurring_families', 'finding_references',
];
const FAMILY_KEYS = [
  'schema_version', 'phase', 'reviewed_sha', 'review_reference', 'verdict',
  'families',
];
const APPROVAL_KEYS = [
  'schema_version', 'phase', 'head_sha', 'blocked_gate_reference',
  'design_commit_sha', 'design_reference', 'policy_digest', 'approved_by',
];

function strictJsonParse(raw, markerName = 'JSON') {
  let offset = 0;
  function fail(message) {
    throw new Error(`${markerName} ${message}.`);
  }
  function skipWhitespace() {
    while (/\s/.test(raw[offset] || '')) offset += 1;
  }
  function parseString() {
    const start = offset;
    if (raw[offset] !== '"') fail('is not valid JSON');
    offset += 1;
    while (offset < raw.length) {
      if (raw[offset] === '"') {
        offset += 1;
        try {
          return JSON.parse(raw.slice(start, offset));
        } catch (_) {
          fail('is not valid JSON');
        }
      }
      if (raw[offset] === '\\') offset += 2;
      else offset += 1;
    }
    fail('is not valid JSON');
  }
  function parseArray() {
    const result = [];
    offset += 1;
    skipWhitespace();
    if (raw[offset] === ']') {
      offset += 1;
      return result;
    }
    while (offset < raw.length) {
      result.push(parseValue());
      skipWhitespace();
      if (raw[offset] === ']') {
        offset += 1;
        return result;
      }
      if (raw[offset] !== ',') fail('is not valid JSON');
      offset += 1;
      skipWhitespace();
    }
    fail('is not valid JSON');
  }
  function parseObject() {
    const result = Object.create(null);
    const keys = new Set();
    offset += 1;
    skipWhitespace();
    if (raw[offset] === '}') {
      offset += 1;
      return result;
    }
    while (offset < raw.length) {
      const key = parseString();
      if (keys.has(key)) fail('contains a duplicate JSON key');
      keys.add(key);
      skipWhitespace();
      if (raw[offset] !== ':') fail('is not valid JSON');
      offset += 1;
      result[key] = parseValue();
      skipWhitespace();
      if (raw[offset] === '}') {
        offset += 1;
        return result;
      }
      if (raw[offset] !== ',') fail('is not valid JSON');
      offset += 1;
      skipWhitespace();
    }
    fail('is not valid JSON');
  }
  function parseValue() {
    skipWhitespace();
    if (raw[offset] === '{') return parseObject();
    if (raw[offset] === '[') return parseArray();
    if (raw[offset] === '"') return parseString();
    const start = offset;
    while (offset < raw.length && !/[\s,}\]]/.test(raw[offset])) offset += 1;
    if (start === offset) fail('is not valid JSON');
    try {
      return JSON.parse(raw.slice(start, offset));
    } catch (_) {
      fail('is not valid JSON');
    }
  }
  const value = parseValue();
  skipWhitespace();
  if (offset !== raw.length) fail('is not valid JSON');
  return value;
}

function markerPayloads(body, markerName) {
  const pattern = new RegExp(`<!--\\s*${markerName}\\s*([\\s\\S]*?)-->`, 'g');
  return [...(body || '').matchAll(pattern)].map((match) => {
    const value = strictJsonParse(match[1].trim(), `${markerName} marker`);
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
      throw new Error(`${markerName} marker must contain one JSON object.`);
    }
    return value;
  });
}

function exactKeys(value, expected) {
  return value && typeof value === 'object' && !Array.isArray(value) &&
    JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...expected].sort());
}

function canonicalValue(value) {
  if (Array.isArray(value)) return value.map(canonicalValue);
  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.keys(value).sort().map((key) => [key, canonicalValue(value[key])])
    );
  }
  return value;
}

function canonicalDigest(value) {
  return crypto.createHash('sha256')
    .update(JSON.stringify(canonicalValue(value)))
    .digest('hex');
}

function trustedMarkers(comments, markerName) {
  const result = [];
  for (const comment of comments) {
    if (comment.user?.login !== 'github-actions[bot]') continue;
    for (const payload of markerPayloads(comment.body, markerName)) {
      result.push({payload, url: comment.html_url, comment});
    }
  }
  return result;
}

function hasPassingChecks(record) {
  return JSON.stringify(record.required_checks) === JSON.stringify(
    REQUIRED_CHECKS.map((name) => ({name, status: 'PASS'}))
  );
}

async function run({github, context, core}) {
  const owner = context.repo.owner;
  const repo = context.repo.repo;
  const repositoryPrefix = `https://github.com/${owner}/${repo}`;
  const pullNumber = Number.parseInt(process.env.PR_NUMBER, 10);
  const phase = process.env.PHASE.trim();
  const headSha = process.env.HEAD_SHA.trim();
  const blockedGateReference = process.env.BLOCKED_GATE_REFERENCE.trim();
  const designCommitSha = process.env.DESIGN_COMMIT_SHA.trim();
  const designReference = process.env.DESIGN_REFERENCE.trim();
  const approver = process.env.AI_GATE_APPROVER_LOGIN;
  const reviewer = process.env.AI_REVIEWER_LOGIN;
  const defaultBranch = context.payload.repository.default_branch;

  if (process.env.CONFIRMATION !== 'APPROVE_DESIGN_RESUME') {
    throw new Error('Confirmation text does not match.');
  }
  if (!approver || context.actor !== approver) {
    throw new Error(`Untrusted design-resume actor: ${context.actor}`);
  }
  if (!reviewer) throw new Error('AI_REVIEWER_LOGIN is not configured.');
  if (context.ref !== `refs/heads/${defaultBranch}`) {
    throw new Error('Design Resume must execute from the current default branch.');
  }
  if (!Number.isInteger(pullNumber) || pullNumber < 1 ||
      !PHASES.slice(1, 6).includes(phase) ||
      !/^[0-9a-f]{40}$/.test(headSha) ||
      !/^[0-9a-f]{40}$/.test(designCommitSha)) {
    throw new Error('Pull request, Phase, or full SHA input is invalid.');
  }
  const pullPrefix = `${repositoryPrefix}/pull/${pullNumber}`;
  if (!blockedGateReference.startsWith(`${pullPrefix}#issuecomment-`) ||
      !designReference.startsWith(`${repositoryPrefix}/`)) {
    throw new Error('Gate and design references must be permalinks in this repository.');
  }

  const ancestry = new Map();
  async function isAncestor(ancestorSha, descendantSha) {
    if (ancestorSha === descendantSha) return true;
    const key = `${ancestorSha}:${descendantSha}`;
    if (!ancestry.has(key)) {
      ancestry.set(key, (async () => {
        const comparison = await github.request(
          'GET /repos/{owner}/{repo}/compare/{basehead}',
          {owner, repo, basehead: `${ancestorSha}...${descendantSha}`}
        );
        return comparison.data.merge_base_commit?.sha === ancestorSha &&
          comparison.data.behind_by === 0 &&
          ['ahead', 'identical'].includes(comparison.data.status);
      })());
    }
    return await ancestry.get(key);
  }

  async function loadJson(path, ref) {
    const {data} = await github.rest.repos.getContent({owner, repo, path, ref});
    if (Array.isArray(data) || data.type !== 'file' || !data.content) {
      throw new Error(`Trusted JSON is unavailable: ${path}`);
    }
    return strictJsonParse(
      Buffer.from(data.content, 'base64').toString('utf8'), path
    );
  }

  const initialDefault = await github.rest.repos.getCommit({
    owner, repo, ref: defaultBranch,
  });
  const authorizedDefaultSha = initialDefault.data.sha;
  if (context.sha !== authorizedDefaultSha) {
    throw new Error('Design Resume workflow code is not the current default-branch revision.');
  }
  const [policy, plan] = await Promise.all([
    loadJson('automation/invariant-families.json', authorizedDefaultSha),
    loadJson('automation/phase-plan.json', authorizedDefaultSha),
  ]);
  const familyIds = policy.families?.map((item) => item.id) || [];
  if (policy.schema_version !== '1.0' || policy.semantic_recurrence_limit !== 2 ||
      familyIds.length !== 7 || new Set(familyIds).size !== familyIds.length ||
      !Array.isArray(policy.phases?.[phase]) ||
      !policy.phases[phase].every((item) => familyIds.includes(item))) {
    throw new Error('Trusted invariant-family policy is malformed.');
  }
  const policyDigest = canonicalDigest(policy);
  const phaseConfig = plan.phases?.find((item) => item.id === phase);
  if (plan.schema_version !== '1.0' || phaseConfig?.label !== phase ||
      typeof phaseConfig.prompt !== 'string' || plan.invariant_audit?.required !== true) {
    throw new Error('Trusted Phase plan is malformed.');
  }

  async function validateDesignReference() {
    const pullMatch = designReference.match(
      new RegExp(`^${repositoryPrefix.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}/pull/(\\d+)$`)
    );
    const blobMatch = designReference.match(
      new RegExp(`^${repositoryPrefix.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}/blob/([0-9a-f]{40})/`)
    );
    if (pullMatch) {
      const {data: designPr} = await github.rest.pulls.get({
        owner, repo, pull_number: Number.parseInt(pullMatch[1], 10),
      });
      const labels = designPr.labels.map((item) => item.name);
      if (!designPr.merged_at || designPr.base.ref !== defaultBranch ||
          !labels.includes('governance-change') ||
          ![designPr.head.sha, designPr.merge_commit_sha].includes(designCommitSha)) {
        throw new Error('Design PR is not a merged governance change for the supplied commit.');
      }
      return;
    }
    if (!blobMatch || blobMatch[1] !== designCommitSha) {
      throw new Error('Design reference is not bound to the supplied design commit.');
    }
  }
  await validateDesignReference();

  async function snapshot({requireStop, requireRequest}) {
    const [{data: defaultCommit}, {data: pr}, comments, checkRuns] = await Promise.all([
      github.rest.repos.getCommit({owner, repo, ref: defaultBranch}),
      github.rest.pulls.get({owner, repo, pull_number: pullNumber}),
      github.paginate(github.rest.issues.listComments, {
        owner, repo, issue_number: pullNumber, per_page: 100,
      }),
      github.paginate(github.rest.checks.listForRef, {
        owner, repo, ref: headSha, filter: 'latest', per_page: 100,
      }),
    ]);
    const labels = pr.labels.map((item) => item.name);
    if (defaultCommit.sha !== authorizedDefaultSha || pr.state !== 'open' ||
        pr.head.repo.full_name !== `${owner}/${repo}` || pr.base.ref !== defaultBranch ||
        pr.head.sha !== headSha) {
      throw new Error('PR, default branch, or complete managed label state changed.');
    }
    try {
      loopControl.assertDesignApprovalProjection(labels, phase, requireStop);
    } catch (_) {
      throw new Error('PR, default branch, or complete managed label state changed.');
    }
    for (const name of REQUIRED_CHECKS) {
      const matches = checkRuns.filter(
        (item) => item.name === name && item.app?.slug === 'github-actions'
      );
      if (matches.length !== 1 || matches[0].status !== 'completed' ||
          matches[0].conclusion !== 'success') {
        throw new Error(`Required current-HEAD check is not uniquely successful: ${name}`);
      }
    }

    const phaseGates = trustedMarkers(comments, 'redteam-phase-gate');
    const candidates = [];
    for (const gate of phaseGates) {
      const record = gate.payload;
      if (record.phase !== phase || !/^[0-9a-f]{40}$/.test(record.reviewed_sha || '') ||
          !await isAncestor(record.reviewed_sha, headSha)) continue;
      const baseShape = exactKeys(record, BASE_GATE_KEYS) && record.schema_version === '1.0';
      const designShape = exactKeys(record, DESIGN_GATE_KEYS) && record.schema_version === '1.1';
      if (!baseShape && !designShape) {
        throw new Error('Incorporated current-Phase gate has missing or unknown fields.');
      }
      candidates.push(gate);
    }
    const maximal = [];
    for (const candidate of candidates) {
      let dominated = false;
      for (const other of candidates) {
        if (candidate.payload.reviewed_sha !== other.payload.reviewed_sha &&
            await isAncestor(candidate.payload.reviewed_sha, other.payload.reviewed_sha)) {
          dominated = true;
          break;
        }
      }
      if (!dominated) maximal.push(candidate);
    }
    if (maximal.length !== 1 || maximal[0].url !== blockedGateReference) {
      throw new Error('Blocking gate is not the unique latest incorporated current-Phase gate.');
    }
    const gate = maximal[0];
    const record = gate.payload;
    if (record.verdict !== 'CHANGES_REQUESTED' || record.loop_state !== 'BLOCKED_LIMIT' ||
        !localReview.isTrustedGateEvidence(record, reviewer, approver) ||
        record.recorded_by !== approver ||
        !/^[A-Z0-9][A-Z0-9._-]{0,63}$/.test(record.finding_key || '') ||
        !/^[0-9a-f]{40}$/.test(record.base_sha || '') || !hasPassingChecks(record)) {
      throw new Error('Latest blocking gate is malformed or untrusted.');
    }
    const phaseIndex = PHASES.indexOf(phase);
    const priorPhase = PHASES[phaseIndex - 1];
    const basePasses = phaseGates.filter((item) => {
      const value = item.payload;
      return exactKeys(value, BASE_GATE_KEYS) && value.schema_version === '1.0' &&
        value.phase === priorPhase && value.reviewed_sha === record.base_sha &&
        value.verdict === 'PASS' && value.loop_state === 'PASS' &&
        value.finding_key === null &&
        localReview.isTrustedGateEvidence(value, reviewer, approver) &&
        value.recorded_by === approver &&
        hasPassingChecks(value);
    });
    if (basePasses.length !== 1 || !await isAncestor(record.base_sha, record.reviewed_sha)) {
      throw new Error('Design stop lacks one incorporated adjacent Phase PASS.');
    }

    const familyRecords = trustedMarkers(comments, 'redteam-invariant-family-review');
    for (const item of familyRecords.filter((entry) => entry.payload.phase === phase)) {
      const value = item.payload;
      if (!exactKeys(value, FAMILY_KEYS) || value.schema_version !== '1.0' ||
          !/^[0-9a-f]{40}$/.test(value.reviewed_sha || '') ||
          !['PASS', 'CHANGES_REQUESTED'].includes(value.verdict) ||
          !Array.isArray(value.families) || value.families.length !== new Set(value.families).size ||
          !value.families.every((family) => familyIds.includes(family)) ||
          !String(value.review_reference || '').startsWith(pullPrefix)) {
        throw new Error('Trusted invariant-family review marker is malformed.');
      }
    }
    const currentFamilies = familyRecords.filter((item) =>
      item.payload.phase === phase && item.payload.reviewed_sha === record.reviewed_sha &&
      item.payload.review_reference === record.review_reference &&
      item.payload.verdict === 'CHANGES_REQUESTED'
    );
    const currentFamilyIdentities = new Set(
      currentFamilies.map((item) => canonicalDigest(item.payload))
    );
    if (currentFamilyIdentities.size !== 1) {
      throw new Error('Current design-stop family evidence is missing or ambiguous.');
    }
    const currentSet = new Set(currentFamilies[0].payload.families);
    const recurring = new Set();
    for (const item of familyRecords) {
      const value = item.payload;
      if (value.phase !== phase || value.verdict !== 'CHANGES_REQUESTED' ||
          value.reviewed_sha === record.reviewed_sha ||
          !await isAncestor(value.reviewed_sha, record.reviewed_sha)) continue;
      for (const family of value.families) {
        if (currentSet.has(family)) recurring.add(family);
      }
    }
    const recurringFamilies = [...recurring].sort();
    if (recurringFamilies.length === 0) {
      throw new Error('Latest BLOCKED_LIMIT gate is not an invariant-family recurrence stop.');
    }
    if (record.schema_version === '1.1' &&
        (record.stop_reason !== 'INVARIANT_FAMILY_RECURRENCE' ||
         JSON.stringify(record.recurring_families) !== JSON.stringify(recurringFamilies) ||
         !Array.isArray(record.finding_references) || record.finding_references.length < 1 ||
         record.finding_references.length !== new Set(record.finding_references).size ||
         !record.finding_references.every((url) =>
           localReview.isGateFindingReference(record, url, pullPrefix)))) {
      throw new Error('Design-stop Gate extension does not match recurrence evidence.');
    }
    if (!await isAncestor(designCommitSha, defaultCommit.sha) ||
        !await isAncestor(designCommitSha, headSha)) {
      throw new Error('Approved design commit is not incorporated in main and current PR HEAD.');
    }

    const approvals = trustedMarkers(comments, 'redteam-design-approval');
    const relatedApprovals = approvals.filter((item) =>
      item.payload.phase === phase && item.payload.head_sha === headSha
    );
    for (const item of relatedApprovals) {
      if (!exactKeys(item.payload, APPROVAL_KEYS)) {
        throw new Error('Design approval has missing or unknown fields.');
      }
    }
    const requests = trustedMarkers(comments, 'redteam-implementation-request');
    if (requireRequest) {
      const consumptions = requests.filter((item) =>
        item.payload.design_approval_reference === requireRequest
      );
      if (consumptions.length !== 1) {
        throw new Error('Design approval consumption is missing or ambiguous.');
      }
    }
    return {pr, labels, comments, gate, relatedApprovals, requests, recurringFamilies};
  }

  let live = await snapshot({requireStop: true, requireRequest: null});
  const approvalPayload = {
    schema_version: '1.0',
    phase,
    head_sha: headSha,
    blocked_gate_reference: blockedGateReference,
    design_commit_sha: designCommitSha,
    design_reference: designReference,
    policy_digest: policyDigest,
    approved_by: context.actor,
  };
  const conflictingApprovals = live.relatedApprovals.filter(
    (item) => JSON.stringify(item.payload) !== JSON.stringify(approvalPayload)
  );
  if (conflictingApprovals.length > 0 || live.relatedApprovals.length > 1) {
    throw new Error('A conflicting or ambiguous Design Approval already exists.');
  }
  let approvalReference = live.relatedApprovals[0]?.url;
  if (!approvalReference) {
    const marker = `<!-- redteam-design-approval\n${JSON.stringify(approvalPayload)}\n-->`;
    const {data: comment} = await github.rest.issues.createComment({
      owner, repo, issue_number: pullNumber,
      body: `Human design approval recorded for \`${phase}\` at \`${headSha}\`.\n\nBlocking gate: ${blockedGateReference}\nApproved design: ${designReference}\n\n${marker}`,
    });
    approvalReference = comment.html_url;
  }

  live = await snapshot({requireStop: true, requireRequest: null});
  const approvalsAtReference = live.relatedApprovals.filter(
    (item) => item.url === approvalReference &&
      JSON.stringify(item.payload) === JSON.stringify(approvalPayload)
  );
  if (approvalsAtReference.length !== 1) {
    throw new Error('Design Approval changed after publication.');
  }
  const requestPayload = {
    schema_version: '1.0',
    action: 'IMPLEMENT_PHASE',
    trigger: 'RESUME_AFTER_DESIGN_APPROVAL',
    phase,
    head_sha: headSha,
    phase_prompt: phaseConfig.prompt,
    invariant_audit: plan.invariant_audit,
    design_approval_reference: approvalReference,
  };
  const existingConsumptions = live.requests.filter((item) =>
    item.payload.design_approval_reference === approvalReference
  );
  if (existingConsumptions.some(
    (item) => JSON.stringify(item.payload) !== JSON.stringify(requestPayload)
  ) || existingConsumptions.length > 1) {
    throw new Error('Design Approval was already consumed by a different request.');
  }
  if (existingConsumptions.length === 0) {
    const marker = `<!-- redteam-implementation-request\n${JSON.stringify(requestPayload)}\n-->`;
    await github.rest.issues.createComment({
      owner, repo, issue_number: pullNumber,
      body: `The approved coherent redesign authorizes one exact-HEAD implementation request.\n\n${marker}`,
    });
  }

  live = await snapshot({requireStop: true, requireRequest: approvalReference});
  await github.rest.repos.createCommitStatus({
    owner, repo, sha: headSha, state: 'pending', context: 'redteam/phase-review',
    description: `${phase}: design-approved implementation pending`.slice(0, 140),
    target_url: approvalReference,
  });
  live = await snapshot({requireStop: true, requireRequest: approvalReference});
  const managed = new Set([
    'ai-loop', 'ai-needs-implementation', 'ai-needs-fix', 'ai-needs-review',
    'ai-review-passed', 'ai-loop-blocked', 'ai-human-gate', 'ai-project-complete',
  ]);
  const desiredLabels = live.labels.filter(
    (name) => !managed.has(name) && !/^phase-(0a|0b|0c|[1-5])$/.test(name)
  );
  desiredLabels.push('ai-loop', phase, 'ai-needs-implementation');
  desiredLabels.sort();
  await github.rest.issues.setLabels({
    owner, repo, issue_number: pullNumber, labels: desiredLabels,
  });
  await snapshot({requireStop: false, requireRequest: approvalReference});
  core.info(`DESIGN_APPROVED ${phase} ${headSha} ${approvalReference}`);
}

module.exports = {canonicalDigest, markerPayloads, run, strictJsonParse};
