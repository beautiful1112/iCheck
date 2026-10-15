type Receipt = {
  generation: string;
  vault_version: number;
  token_expires_at: string;
  observed_at: string;
  received_at: string;
  coordination_state: "ready" | "refreshing" | "revoking" | "uncertain";
  source: "attestor" | "agent" | "control_plane";
};

export type OAuthSummary = {
  oauth_status: string;
  oauth_generation: string | null;
  oauth_bundle_version: number | null;
  oauth_credential_observation: Receipt | null;
};

export function oauthObservationSummary(server: OAuthSummary, now = Date.now()) {
  const value = server.oauth_credential_observation;
  if (server.oauth_status !== "connected" || !value || !server.oauth_generation
    || value.generation !== server.oauth_generation) {
    return { state: "unavailable", label: "No current-generation observation", expiry: null, detail: "Awaiting a current worker or control-plane receipt" };
  }
  const observed = Date.parse(value.observed_at);
  const received = Date.parse(value.received_at);
  const expiry = Date.parse(value.token_expires_at);
  const states = ["ready", "refreshing", "revoking", "uncertain"];
  const sources = { attestor: "Attestor", agent: "Agent worker", control_plane: "Control plane" };
  if (!Number.isFinite(now) || !Number.isFinite(observed) || !Number.isFinite(received)
    || !Number.isFinite(expiry) || observed > now + 30_000 || received > now + 30_000
    || !Number.isSafeInteger(value.vault_version) || value.vault_version < 1
    || value.vault_version < (server.oauth_bundle_version || 0)
    || !states.includes(value.coordination_state) || !(value.source in sources)) {
    return { state: "uncertain", label: "Credential observation unavailable", expiry: null, detail: "Refresh to obtain validated credential metadata" };
  }
  const stale = observed <= now - 300_000 || received <= now - 300_000;
  const state = stale ? "stale" : value.coordination_state === "ready" && expiry <= now ? "expired" : value.coordination_state;
  return {
    state,
    label: stale ? "Stale credential observation" : state === "ready" ? "Credential observed ready" : `Credential observation: ${state}`,
    expiry: value.token_expires_at,
    detail: `${sources[value.source]} · Vault v${value.vault_version} · observed ${new Date(observed).toLocaleString()} (not an execution grant)`,
  };
}
