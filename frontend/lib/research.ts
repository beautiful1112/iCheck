export type PublicSource = {title: string; url: string; sha256?: string; retrieved_at?: string};

export function publicSource(value: unknown): PublicSource | null {
  if (!value || typeof value !== "object") return null;
  const row = value as Record<string, unknown>;
  if (typeof row.url !== "string") return null;
  try {
    const url = new URL(row.url);
    if (url.protocol !== "https:" || url.username || url.password) return null;
    return {title: typeof row.title === "string" && row.title ? row.title : typeof row.module === "string" ? row.module : url.hostname,
      url: url.href, sha256: typeof row.sha256 === "string" ? row.sha256 : undefined,
      retrieved_at: typeof row.retrieved_at === "string" ? row.retrieved_at : undefined};
  } catch {return null;}
}

export function researchSources(content: Record<string, unknown>): PublicSource[] {
  const research = content.public_research as {sources?: unknown[]}|undefined;
  const snmp = content.snmp_monitoring_input as {research_sources?: unknown[]}|undefined;
  const documents = Array.isArray(content.research_documents) ? content.research_documents : [];
  const values = [...(Array.isArray(research?.sources) ? research.sources : []),
    ...(Array.isArray(snmp?.research_sources) ? snmp.research_sources : []), ...documents];
  const sources = new Map<string, PublicSource>();
  for (const value of values) {
    const source = publicSource(value);
    if (source) sources.set(source.url, {...sources.get(source.url), ...source});
  }
  return [...sources.values()];
}
