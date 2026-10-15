export type HTTPMetric = {name: string; help?: string; type: "gauge" | "counter"; value_pointer: string;
  records_pointer?: string | null; labels?: Record<string, string>};
export type HTTPMonitorSpec = {contract?: "icheck.http-monitor/v1"; mode: "api" | "probe"; scheme: "http" | "https";
  method: "GET" | "HEAD"; path: string; server_name?: string | null; auth_mode: "none" | "bearer" | "basic" | "api_key";
  credential_header?: string; expected_statuses?: number[]; metrics: HTTPMetric[]};

export function templateSummary(spec: HTTPMonitorSpec) {
  return {request: `${spec.method} ${spec.scheme.toUpperCase()} ${spec.path}`, authentication: spec.auth_mode,
    metrics: spec.mode === "probe" ? ["Request success", "Status code", "Latency", ...(spec.scheme === "https" ? ["TLS certificate expiry"] : [])]
      : spec.metrics.map(metric => `${metric.name}: ${metric.records_pointer || ""}${metric.value_pointer}`)};
}

export function testedTemplate(status: string, proof: Record<string, unknown>, spec?: HTTPMonitorSpec) {
  return Boolean(spec && status === "verified" && proof.check === "http_metric_query" && proof.success === true
    && (spec.mode === "probe" || (Number(proof.metric_samples) > 0 && Array.isArray(proof.metric_names)
      && spec.metrics.every(metric => (proof.metric_names as unknown[]).includes(metric.name)))));
}
