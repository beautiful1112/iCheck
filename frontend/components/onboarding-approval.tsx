"use client";
import Link from "next/link";
import { useState } from "react";
import { apiFetch } from "@/lib/icheck-api";

type Preview = { contract: string; preview_hash?: string; input?: Record<string, unknown>; credential_name?: string;
  blockers?: string[]; warnings?: string[]; approved_device_ids?: string[]; device_id?: string; connection_id?: string;
  plan?: Record<string, unknown> };

export function OnboardingApproval({ result }: { result: unknown }) {
  const [reason, setReason] = useState(""); const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false); const [approved, setApproved] = useState(false);
  if (!result || typeof result !== "object" || !("contract" in result)) return null;
  const preview = result as Preview;
  const onboarding = preview.contract === "icheck.device-onboarding-preview/v1";
  if (!onboarding && preview.contract !== "icheck.device-activation-preview/v1") return null;
  const devices = (Array.isArray(preview.input?.devices) ? preview.input.devices : []) as Array<{ name: string; management_ip: string; kind: string }>;
  async function approve() {
    setBusy(true); setMessage("");
    try {
      if (onboarding) {
        const receipt = await apiFetch<{ device_ids: string[] }>("/assets/onboarding/approve", { method: "POST",
          headers: { "content-type": "application/json" }, body: JSON.stringify({ ...preview.input, preview_hash: preview.preview_hash, reason }) });
        setMessage(`Enrolled ${receipt.device_ids.length} device(s). Collector preflight is pending; monitoring is not activated.`);
      } else {
        await apiFetch(`/assets/devices/${preview.device_id}/connections/${preview.connection_id}/activation/approve`, {
          method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({
            policy_id: preview.plan?.policy_id, expected_plan_hash: preview.plan?.plan_hash, actor: "web.operator", reason }) });
        setMessage("Collection activation approved. Check run history for actual collection success.");
      }
      setApproved(true);
    } catch (error) { setMessage(error instanceof Error ? error.message : "Approval failed; request a fresh preview"); }
    finally { setBusy(false); }
  }
  return <section className="mt-5 rounded-xl border border-violet-200 bg-violet-50 p-4">
    <h3 className="font-semibold">{onboarding ? "AI device onboarding proposal" : "AI collection activation proposal"}</h3>
    {onboarding && <p className="mt-2 text-sm">Credential: {preview.credential_name}. Approval adds only the listed devices and starts bounded preflight.</p>}
    {onboarding ? <><p className="mt-2 text-sm">Site: {preview.input?.site ? String(preview.input.site) : "Not assigned (optional)"} · Method: {String(preview.input?.protocol).replaceAll("_", " ")}</p>
      <div className="my-3 overflow-x-auto rounded-md bg-white"><table className="w-full text-left text-sm"><thead><tr className="border-b"><th className="p-2">Device</th><th className="p-2">IP address</th><th className="p-2">Type</th></tr></thead>
        <tbody>{devices.map(device => <tr key={device.management_ip} className="border-b last:border-0"><td className="p-2">{device.name}</td><td className="p-2 font-mono">{device.management_ip}</td><td className="p-2">{device.kind.replaceAll("_", " ")}</td></tr>)}</tbody></table></div></>
      : <p className="my-3 text-sm">Collector: {String(preview.plan?.artifact_name)} · Interval: {String(preview.plan?.schedule_seconds)} seconds</p>}
    <details className="my-3 text-xs"><summary className="cursor-pointer text-violet-700">Exact technical plan</summary><pre className="mt-2 max-h-64 overflow-auto whitespace-pre-wrap break-all rounded-md bg-white p-3">{JSON.stringify(onboarding ? preview.input : preview.plan, null, 2)}</pre></details>
    {preview.warnings?.map(item => <p key={item} className="mt-1 text-xs text-slate-600">{item}</p>)}
    {preview.blockers?.map(item => <p key={item} role="alert" className="mt-2 text-sm text-red-700">{item}</p>)}
    {message && <p role="status" className="my-3 text-sm">{message}</p>}
    {!approved && !preview.approved_device_ids?.length && <div className="mt-3 flex flex-wrap gap-3">
      <input aria-label="Onboarding approval reason" placeholder="Reason for approving this exact plan" value={reason} onChange={e => setReason(e.target.value)} className="min-w-0 flex-1 rounded-md border bg-white px-3 py-2 text-sm" />
      <button type="button" disabled={busy || !reason.trim() || !!preview.blockers?.length} onClick={() => void approve()} className="rounded-md bg-violet-600 px-4 py-2 text-sm text-white disabled:opacity-50">{onboarding ? "Approve enrollment" : "Approve collection"}</button>
    </div>}
    <Link href="/assets/devices" className="mt-3 inline-block text-sm text-violet-700 underline">Open Devices: preflight, monitoring plans and run history</Link>
  </section>;
}
