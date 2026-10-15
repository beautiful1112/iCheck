export type ClosureReceipt = {
  id: string; request_id: string; grant_id: string; epoch: number; committed_at: string;
  summary_only?: boolean;
  proof_summary?: { proof_basis: string; owner_subject: string; reviewer_subject: string; evidence_environment: string;
    member_count: number; source_count: number; related_action_count: number };
  proof?: { proof_basis: string; owner_subject: string; reviewer_subject: string; evidence_environment: string;
    recovery: { member_count: number; evaluated_at: string; source_evidence: { source_id: string; quiet_observed_at: string }[] };
    related_actions: { proposal_id: string; outcome: string }[] };
};
export type ClosureLease = {
  request_id: string; attempt_id: string | null; epoch: number; state: string; lease_expires_at: string | null;
};
export function closureLeaseMetadata(value: ClosureLease): ClosureLease {
  // Whitelist, rather than spreading a response containing a transient token.
  return { request_id: value.request_id, attempt_id: value.attempt_id, epoch: value.epoch,
    state: value.state, lease_expires_at: value.lease_expires_at };
}
export function closureDeadlineFresh(value: string | null | undefined, now: number): boolean {
  return Boolean(value && Number.isFinite(Date.parse(value)) && Number.isFinite(now) && now < Date.parse(value));
}
export function closureVersionEnabled(version: unknown, replacementEnabled: boolean | undefined): boolean {
  return version === 1 || (version === 2 && replacementEnabled === true);
}
