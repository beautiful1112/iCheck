export type ReportProofReference = {
  reference_kind: "source_replacement_request" | "source_retirement" | "situation_closure_receipt";
  reference_id: string;
};

export function reportProofReferences(value: unknown): ReportProofReference[] {
  if (!Array.isArray(value) || value.length < 1 || value.length > 20) throw new Error("Select 1 to 20 exact retained records");
  const seen = new Set<string>();
  return value.map((item) => {
    if (!item || typeof item !== "object" || Array.isArray(item)) throw new Error("Invalid retained reference");
    const row = item as Record<string, unknown>;
    if (typeof row.reference_kind !== "string" || !["source_replacement_request", "source_retirement", "situation_closure_receipt"].includes(row.reference_kind) ||
      typeof row.reference_id !== "string" || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(row.reference_id)) {
      throw new Error("Retained records require a supported kind and an exact UUID");
    }
    const result = { reference_kind: row.reference_kind, reference_id: row.reference_id.toLowerCase() } as ReportProofReference;
    const key = `${result.reference_kind}:${result.reference_id}`;
    if (seen.has(key)) throw new Error("Each retained reference can be selected only once");
    seen.add(key);
    return result;
  });
}
