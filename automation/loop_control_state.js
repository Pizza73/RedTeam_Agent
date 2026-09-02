'use strict';

const PHASE_PATTERN = /^phase-(0a|0b|0c|[1-5])$/;
const TRANSIENT_LABELS = new Set([
  'ai-needs-implementation',
  'ai-needs-fix',
  'ai-needs-review',
  'ai-review-passed',
  'ai-human-gate',
  'ai-project-complete',
]);

function normalizedLabels(labels) {
  if (!Array.isArray(labels) || labels.some((item) => typeof item !== 'string')) {
    throw new Error('Loop-control labels must be an array of strings.');
  }
  return new Set(labels);
}

function requireRoutingLabels(labels, phase = null) {
  const current = normalizedLabels(labels);
  const phases = [...current].filter((name) => PHASE_PATTERN.test(name));
  if (!current.has('ai-loop') || phases.length !== 1 || (phase && phases[0] !== phase)) {
    throw new Error('Loop-control routing labels are invalid.');
  }
  return current;
}

function shouldPublishReviewReady(labels) {
  const current = requireRoutingLabels(labels);
  return !current.has('ai-loop-blocked');
}

function assertDesignApprovalProjection(labels, phase, requireStop) {
  const current = requireRoutingLabels(labels, phase);
  const forbidden = new Set([
    'governance-change',
    'ai-needs-fix',
    'ai-review-passed',
    'ai-human-gate',
    'ai-project-complete',
  ]);
  if (requireStop) {
    if (!current.has('ai-loop-blocked') || current.has('ai-needs-implementation')) {
      throw new Error('Design approval requires the blocked control state.');
    }
    // ai-needs-review is a legacy/transient UI projection. It is not authority and
    // is removed by the approved transition after all SHA-bound evidence is checked.
  } else {
    forbidden.add('ai-needs-review');
    if (current.has('ai-loop-blocked') || !current.has('ai-needs-implementation')) {
      throw new Error('Design approval consumption state is invalid.');
    }
  }
  if ([...forbidden].some((name) => current.has(name))) {
    throw new Error('Design approval projection contains a conflicting state.');
  }
  return current;
}

module.exports = {
  PHASE_PATTERN,
  TRANSIENT_LABELS,
  assertDesignApprovalProjection,
  requireRoutingLabels,
  shouldPublishReviewReady,
};
