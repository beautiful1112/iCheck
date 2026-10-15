export type ReplacementIntent = { requestId: string; executionKey: string; reason: string };
export type ReplacementSummary = { request_id: string; new_source_id: string; review_id: string | null; retirement_id: string | null;
  prior_retirement_id: string | null; author_subject: string; reviewer_subject: string | null; expires_at: string; revoked: boolean };
export type ReplacementDetail = { request: { id: string; old_source_id: string; new_source_id: string; author_principal_id: string; author_subject: string;
  prior_retirement_id: string | null; evidence_environment: string; expires_at: string; validation_reference: string; snapshot: Record<string, unknown> };
  review: { id: string; reviewer_principal_id: string; reviewer_subject: string; acceptance_reference: string } | null;
  revocation: { reason: string } | null; retirement_id: string | null; producer_cutover_performed: boolean };

export function rememberReplacement(rows: ReplacementSummary[], detail: ReplacementDetail) {
  const request = detail.request;
  const summary: ReplacementSummary = { request_id: request.id, new_source_id: request.new_source_id,
    review_id: detail.review?.id ?? null, retirement_id: detail.retirement_id, prior_retirement_id: request.prior_retirement_id,
    author_subject: request.author_subject, reviewer_subject: detail.review?.reviewer_subject ?? null,
    expires_at: request.expires_at, revoked: detail.revocation !== null };
  const requests = [summary, ...rows.filter(row => row.request_id !== request.id)];
  return { requests: requests.slice(0, 100), truncated: requests.length > 100 };
}

export function replacementCanReview(value: {
  canReview: boolean; principalId: string | null; authorPrincipalId: string; expiresAt: string;
}, now = Date.now()): boolean {
  return value.canReview === true && Boolean(value.principalId) && value.principalId !== value.authorPrincipalId
    && Number.isFinite(Date.parse(value.expiresAt)) && Date.parse(value.expiresAt) > now;
}

export function replacementCanApply(value: {
  hostEnabled: boolean; canApply: boolean; reviewId: string | null; revoked: boolean;
  retirementId: string | null; priorRetirementId: string | null; expiresAt: string; executorIndependent: boolean;
}, now = Date.now()): boolean {
  return value.hostEnabled === true && value.canApply === true && value.executorIndependent === true && Boolean(value.reviewId)
    && value.revoked === false && value.retirementId === null && value.priorRetirementId === null
    && Number.isFinite(Date.parse(value.expiresAt)) && Date.parse(value.expiresAt) > now;
}

export function replacementIntentMatches(intent: ReplacementIntent, requestId: string, reason: string): boolean {
  return intent.requestId === requestId && intent.reason === reason.trim();
}
