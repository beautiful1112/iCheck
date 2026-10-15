export type MCPAttestationAuthority = {
  server_id: string;
  artifact_version_id: string;
  status: string;
  expires_at: string | null;
};

export function mcpAttestationIsFresh(
  attestation: MCPAttestationAuthority | undefined,
  serverId: string,
  artifactVersionId: string,
  now = Date.now(),
): boolean {
  if (!attestation || !serverId || !artifactVersionId || !Number.isFinite(now)) return false;
  const expiry = attestation.expires_at === null ? NaN : Date.parse(attestation.expires_at);
  return attestation.server_id === serverId && attestation.artifact_version_id === artifactVersionId
    && attestation.status === "passed" && Number.isFinite(expiry) && expiry > now;
}
