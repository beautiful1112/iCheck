export type AuthoringHeadroom = {
  actor_available: number | null;
  namespace_available: number | null;
};

// This is a display of both admission ceilings, not permission to call a model.
// Unavailable/invalid data cannot be presented as unlimited capacity.
export function formatAuthoringHeadroom(
  quota: AuthoringHeadroom | null | undefined,
  locale?: string,
): string {
  if (!quota) return "unavailable";
  const limits = [quota.actor_available, quota.namespace_available];
  if (limits.some((value) => value !== null &&
    (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0))) {
    return "unavailable";
  }
  const bounded = limits.filter((value): value is number => value !== null);
  return bounded.length ? Math.min(...bounded).toLocaleString(locale) : "unbounded";
}
