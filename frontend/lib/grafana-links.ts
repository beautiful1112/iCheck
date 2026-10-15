/** Full-page Grafana links. Variables filter data; they do not grant isolation. */
export const grafanaOverviewHref = "/grafana/d/icheck-collection";

export function networkDashboardHref(
  deviceId: string,
  from = "now-1h",
  to = "now",
): string {
  if (!deviceId || deviceId.length > 160 || /[\u0000-\u001f\u007f]/.test(deviceId)) {
    throw new Error("A valid device ID is required for dashboard context");
  }
  const time = /^(?:now(?:-\d+(?:s|m|h|d|w))?|\d{10,16})$/;
  if (!time.test(from) || !time.test(to)) {
    throw new Error("Use a relative or epoch-millisecond dashboard time range");
  }
  const query = new URLSearchParams({ "var-device": deviceId, from, to, timezone: "browser" });
  return `/grafana/d/icheck-network?${query.toString()}`;
}
