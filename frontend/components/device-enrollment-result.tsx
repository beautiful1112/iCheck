import Link from "next/link";

export function DeviceEnrollmentResult({ result }: { result: Record<string, unknown> }) {
  if (result.contract !== "icheck.device-enrollment-receipt/v1" || !Array.isArray(result.device_ids) || !result.device_ids.length) return null;
  return <section className="mt-3 rounded-xl border border-emerald-200 bg-emerald-50 p-4" aria-label="Device enrollment receipt">
    <h4 className="font-semibold">Added to Device inventory</h4>
    <p className="mt-2 text-sm">{result.device_ids.length} device(s) registered. Collector verification is pending; live monitoring is not yet confirmed.</p>
    <p className="mt-2 text-sm">{String(result.monitoring || "")}</p>
    <Link href="/assets/devices" className="mt-3 inline-block text-sm font-medium text-emerald-800 underline">Open device inventory</Link>
  </section>;
}
