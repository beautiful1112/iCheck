export type OnboardingCredentialProfile = {
  id: string;
  name: string;
  enabled: boolean;
  allowed_adapters: string[];
  worker_selector: Record<string, string>;
};

export type DeviceLocation = {
  zone?: string | null;
  building?: string | null;
  floor?: string | null;
  room?: string | null;
  rack?: string | null;
  height?: number | null;
};

export type OnboardingWorker = {
  site: string | null;
  state: string;
  capabilities: readonly string[];
  labels?: Record<string, unknown>;
};

// Capability discovery is an availability hint, not target/credential authority.
// null is unknown (for example, the caller cannot read the worker registry).
export function verificationMethodAvailable(workers: readonly OnboardingWorker[] | null,
  adapter: string, site: string): boolean | null {
  if (workers === null) return null;
  return workers.some(worker => worker.state === "online" && worker.capabilities.includes(adapter) &&
    (!site.trim() || (worker.site || worker.labels?.site) === site.trim()));
}

export function deviceDisplayName(device: { name: string; management_ip: string | null; discovered_name?: string | null }): string {
  return device.name === device.management_ip ? device.discovered_name || device.name : device.name;
}

export function formatDeviceLocation(location: DeviceLocation = {}): string {
  return [location.zone, location.building, location.floor, location.room, location.rack,
    location.height != null ? `U${location.height}` : null].filter(Boolean).join(" / ");
}

export function eligibleCredentialProfiles<T extends OnboardingCredentialProfile>(
  profiles: readonly T[],
  adapter: string,
  site: string,
): T[] {
  const connectionSelector: Record<string, string> = { site: site.trim() };
  return profiles.filter((profile) =>
    profile.enabled &&
    profile.allowed_adapters.includes(adapter) &&
    (!site.trim() || Object.entries(profile.worker_selector).every(
      ([key, expected]) => connectionSelector[key] === expected,
    )),
  );
}

export function credentialReferenceEligible(
  profiles: readonly OnboardingCredentialProfile[],
  adapter: string,
  site: string,
  reference: string,
): boolean {
  if (!reference) return true;
  return eligibleCredentialProfiles(profiles, adapter, site).some(
    (profile) => profile.id === reference || profile.name === reference,
  );
}
