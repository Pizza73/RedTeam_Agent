'use strict';

const crypto = require('crypto');

const AUTHORIZATION_STATUS_DESCRIPTION = 'trusted exact-SHA base refresh authorization';
const AUTHORIZATION_STATUS_PATTERN =
  /^redteam\/base-refresh\/(phase-(?:0a|0b|0c|[1-5]))\/(phase-(?:0a|0b|0c|[1-5]))\/([0-9a-f]{40})$/;
const CHECKPOINT_STATUS_DESCRIPTION = 'trusted current-HEAD base refresh checkpoint';
const CHECKPOINT_STATUS_PREFIX = 'redteam/base-refresh-applied/';
const CHECKPOINT_STATUS_PATTERN = /^redteam\/base-refresh-applied\/([0-9a-f]{64})$/;
const SHA_PATTERN = /^[0-9a-f]{40}$/;
const TRUSTED_WORKFLOW_LOGIN = 'github-actions[bot]';

function requireSha(value, field) {
  if (typeof value !== 'string' || !SHA_PATTERN.test(value)) {
    throw new Error(`Base-refresh checkpoint has an invalid ${field}.`);
  }
}

function checkpointPayload({
  headSha,
  previousHeadSha,
  targetBaseSha,
  sourcePhase,
  revalidationPhase,
  authorizationReference,
}) {
  requireSha(headSha, 'current HEAD');
  requireSha(previousHeadSha, 'previous HEAD');
  requireSha(targetBaseSha, 'target base');
  if (typeof authorizationReference !== 'string' ||
      !authorizationReference.startsWith('https://github.com/')) {
    throw new Error('Base-refresh checkpoint has an invalid authorization reference.');
  }
  return {
    action: 'BASE_REFRESH_APPLIED',
    authorization_reference: authorizationReference,
    head_sha: headSha,
    previous_head_sha: previousHeadSha,
    revalidate_phase: revalidationPhase,
    schema_version: '1.0',
    source_phase: sourcePhase,
    target_base_sha: targetBaseSha,
  };
}

function checkpointDigest(payload) {
  const canonical = JSON.stringify(payload, Object.keys(payload).sort());
  return crypto.createHash('sha256').update(canonical).digest('hex');
}

async function commitParents({github, owner, repo, headSha}) {
  requireSha(headSha, 'commit HEAD');
  const {data: commit} = await github.rest.git.getCommit({
    owner, repo, commit_sha: headSha,
  });
  const parents = commit.parents;
  if (commit.sha !== headSha || !Array.isArray(parents) || parents.length !== 2 ||
      !parents.every((item) => item && SHA_PATTERN.test(item.sha)) ||
      parents[0].sha === parents[1].sha) {
    throw new Error('Base-refresh checkpoint requires one exact two-parent merge.');
  }
  return [parents[0].sha, parents[1].sha];
}

async function statusesFor({github, owner, repo, sha}) {
  return github.paginate(
    github.rest.repos.listCommitStatusesForRef,
    {owner, repo, ref: sha, per_page: 100}
  );
}

function matchingAuthorizations({
  statuses,
  sourcePhase,
  revalidationPhase,
  targetBaseSha,
  authorizationReference,
}) {
  const matches = [];
  for (const status of statuses) {
    if (status.creator?.login !== TRUSTED_WORKFLOW_LOGIN ||
        !status.context?.startsWith('redteam/base-refresh/')) continue;
    const match = status.context.match(AUTHORIZATION_STATUS_PATTERN);
    if (!match || status.state !== 'success' ||
        status.description !== AUTHORIZATION_STATUS_DESCRIPTION ||
        typeof status.target_url !== 'string' ||
        !status.target_url.startsWith('https://github.com/')) {
      throw new Error('Base-refresh edge contains malformed trusted authorization.');
    }
    if (match[1] === sourcePhase && match[2] === revalidationPhase &&
        match[3] === targetBaseSha && status.target_url === authorizationReference) {
      matches.push(status.context);
    }
  }
  return new Set(matches).size;
}

async function verifyPreparedRefreshEdge({
  github,
  owner,
  repo,
  headSha,
  previousHeadSha,
  targetBaseSha,
  sourcePhase,
  revalidationPhase,
  authorizationReference,
}) {
  const parents = await commitParents({github, owner, repo, headSha});
  if (parents[0] !== previousHeadSha || parents[1] !== targetBaseSha) {
    throw new Error('Base-refresh merge parents do not match the authorized transition.');
  }
  const statuses = await statusesFor({github, owner, repo, sha: previousHeadSha});
  if (matchingAuthorizations({
    statuses,
    sourcePhase,
    revalidationPhase,
    targetBaseSha,
    authorizationReference,
  }) !== 1) {
    throw new Error('Base-refresh merge lacks one trusted previous-HEAD authorization.');
  }
  return checkpointPayload({
    headSha,
    previousHeadSha,
    targetBaseSha,
    sourcePhase,
    revalidationPhase,
    authorizationReference,
  });
}

async function verifyAppliedCheckpoint({
  github,
  owner,
  repo,
  headSha,
  sourcePhase,
  revalidationPhase,
  authorizationReference,
}) {
  const [previousHeadSha, targetBaseSha] = await commitParents({
    github, owner, repo, headSha,
  });
  const payload = checkpointPayload({
    headSha,
    previousHeadSha,
    targetBaseSha,
    sourcePhase,
    revalidationPhase,
    authorizationReference,
  });
  const expectedContext = `${CHECKPOINT_STATUS_PREFIX}${checkpointDigest(payload)}`;
  const statuses = await statusesFor({github, owner, repo, sha: headSha});
  const matches = [];
  for (const status of statuses) {
    if (status.creator?.login !== TRUSTED_WORKFLOW_LOGIN ||
        !status.context?.startsWith(CHECKPOINT_STATUS_PREFIX)) continue;
    const match = status.context.match(CHECKPOINT_STATUS_PATTERN);
    if (!match || status.state !== 'success' ||
        status.description !== CHECKPOINT_STATUS_DESCRIPTION ||
        status.target_url !== authorizationReference ||
        status.context !== expectedContext) {
      throw new Error('Current HEAD contains a malformed base-refresh checkpoint.');
    }
    matches.push(status.context);
  }
  if (new Set(matches).size !== 1) {
    throw new Error('Current HEAD lacks one trusted base-refresh checkpoint.');
  }
  return payload;
}

module.exports = {
  AUTHORIZATION_STATUS_DESCRIPTION,
  CHECKPOINT_STATUS_DESCRIPTION,
  CHECKPOINT_STATUS_PREFIX,
  checkpointDigest,
  checkpointPayload,
  verifyAppliedCheckpoint,
  verifyPreparedRefreshEdge,
};
