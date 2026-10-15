export type SafeProviderDiagnostic = {
  code: string; summary: string; cause: string; recommendation: string; upstream_status?: number | null;
  root_cause_known?: boolean; evidence_source?: string;
  validation_errors?: { path: string; rule: string; line?: number; column?: number }[];
  validation_stage?: string; finish_reason?: string; timeout_seconds?: number;
  provider_error?: { provider_name?: string; error_type?: string; provider_code?: string; parameter?: string; constraint?: string; schema_keyword?: string };
};

export function AIProviderDiagnosticDetails({ diagnostic }: { diagnostic: SafeProviderDiagnostic }) {
  if (diagnostic.validation_errors?.length) return <section aria-label="Safe Agent validation details" className="mt-3 rounded-md border border-red-200 bg-red-50 p-3 text-sm text-red-900">
    <p className="font-medium">Rejected Agent decision · {diagnostic.validation_stage ?? "local validation"}</p>
    <ul className="mt-2 space-y-1">{diagnostic.validation_errors.map((issue, index) => <li key={index} className="break-all font-mono text-xs">
      {issue.path}: {issue.rule}{issue.line !== undefined ? ` · line ${issue.line}, column ${issue.column}` : ""}
    </li>)}</ul>
    {diagnostic.finish_reason && <p className="mt-2">Model finish reason: {diagnostic.finish_reason}</p>}
    <p className="mt-2 text-xs">Only safe schema paths and validation rules are retained. Raw model output, input values and secrets are withheld.</p>
  </section>;
  if (diagnostic.timeout_seconds !== undefined) return <p className="mt-2 text-xs">Elapsed-time limit: {diagnostic.timeout_seconds}s. Keep-alive traffic does not extend this limit.</p>;
  if (!diagnostic.provider_error && diagnostic.root_cause_known === undefined) return null;
  const error = diagnostic.provider_error ?? {};
  const fields = [
    ["Provider", error.provider_name], ["Error type", error.error_type], ["Provider code", error.provider_code],
    ["Rejected parameter", error.parameter], ["Validation constraint", error.constraint], ["Schema keyword", error.schema_keyword],
  ].filter(([, value]) => value);
  return <section aria-label="Safe provider validation details" className="mt-3 rounded-md border border-red-200 bg-red-50 p-3 text-sm text-red-900">
    <p className="font-medium">{diagnostic.root_cause_known ? (diagnostic.evidence_source === "local_timeout" ? "Specific runtime cause" : "Specific provider validation cause") : "Exact validation constraint unavailable"}{diagnostic.upstream_status ? ` · HTTP ${diagnostic.upstream_status}` : ""}</p>
    {fields.length > 0 && <dl className="mt-2 grid gap-2 sm:grid-cols-2">
      {fields.map(([label, value]) => <div key={label}><dt className="font-medium">{label}</dt><dd className="break-all font-mono text-xs">{value}</dd></div>)}
    </dl>}
    {diagnostic.root_cause_known === false && <p className="mt-2">The exact constraint was not returned or safely recognized. No specific rejected value is assumed.</p>}
    <p className="mt-2 text-xs">Provider metadata is allowlisted. Raw responses, prompts, credentials and arbitrary field values are withheld.</p>
  </section>;
}
