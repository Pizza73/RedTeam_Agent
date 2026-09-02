'use strict';

const REFRESH_STATUS_DESCRIPTION = 'trusted exact-SHA base refresh authorization';
const REFRESH_STATUS_PATTERN =
  /^redteam\/base-refresh\/(phase-(?:0a|0b|0c|[1-5]))\/(phase-(?:0a|0b|0c|[1-5]))\/([0-9a-f]{40})$/;
const SHA_PATTERN = /^[0-9a-f]{40}$/;
const TRUSTED_WORKFLOW_LOGIN = 'github-actions[bot]';
const MAX_REFRESH_CHAIN_DEPTH = 32;

function requireSha(value, field) {
  if (typeof value !== 'string' || !SHA_PATTERN.test(value)) {
    throw new Error(`Blocked refresh chain has an invalid ${field}.`);
  }
}

async function verifyBlockedRefreshChain({
  github,
  owner,
  repo,
  currentHeadSha,
  gateHeadSha,
  gateReference,
  sourcePhase,
  revalidationPhase,
}) {
  requireSha(currentHeadSha, 'current HEAD');
  requireSha(gateHeadSha, 'gate HEAD');
  if (typeof gateReference !== 'string' || !gateReference.startsWith('https://github.com/')) {
    throw new Error('Blocked refresh chain has an invalid gate reference.');
  }

  const edges = [];
  let cursor = currentHeadSha;
  while (cursor !== gateHeadSha) {
    if (edges.length >= MAX_REFRESH_CHAIN_DEPTH) {
      throw new Error('Blocked refresh chain exceeds its bounded depth.');
    }
    const {data: commit} = await github.rest.git.getCommit({
      owner, repo, commit_sha: cursor,
    });
    const parents = commit.parents;
    if (commit.sha !== cursor || !Array.isArray(parents) || parents.length !== 2 ||
        !parents.every((item) => item && SHA_PATTERN.test(item.sha)) ||
        parents[0].sha === parents[1].sha) {
      throw new Error('Blocked refresh chain contains a non-refresh commit.');
    }
    const previousHeadSha = parents[0].sha;
    const incorporatedBaseSha = parents[1].sha;
    const statuses = await github.paginate(
      github.rest.repos.listCommitStatusesForRef,
      {owner, repo, ref: previousHeadSha, per_page: 100}
    );
    const matching = [];
    for (const status of statuses) {
      if (status.creator?.login !== TRUSTED_WORKFLOW_LOGIN ||
          !status.context?.startsWith('redteam/base-refresh/')) continue;
      const match = status.context.match(REFRESH_STATUS_PATTERN);
      if (!match || status.state !== 'success' ||
          status.description !== REFRESH_STATUS_DESCRIPTION ||
          typeof status.target_url !== 'string' ||
          !status.target_url.startsWith('https://github.com/')) {
        throw new Error('Blocked refresh chain contains malformed trusted status.');
      }
      if (match[1] === sourcePhase && match[2] === revalidationPhase &&
          match[3] === incorporatedBaseSha && status.target_url === gateReference) {
        matching.push(status.context);
      }
    }
    if (new Set(matching).size !== 1) {
      throw new Error('Blocked refresh chain lacks one trusted status for its merge edge.');
    }
    edges.push({previousHeadSha, incorporatedBaseSha});
    cursor = previousHeadSha;
  }
  return edges;
}

module.exports = {
  MAX_REFRESH_CHAIN_DEPTH,
  REFRESH_STATUS_DESCRIPTION,
  REFRESH_STATUS_PATTERN,
  verifyBlockedRefreshChain,
};
