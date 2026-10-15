"use client";
import Link from "next/link";
import { ChangeEvent, Dispatch, SetStateAction, useCallback, useEffect, useState } from "react";
import { ArrowLeft, RefreshCw, ShieldAlert } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { NativeSelect, NativeSelectOption } from "@/components/ui/native-select";
import { Textarea } from "@/components/ui/textarea";
import { apiFetch } from "@/lib/icheck-api";

type Source = { id: string; name: string; enabled: boolean; trust_key_id: string };
type Key = { id: string; name: string; enabled: boolean; trust_source: string; purposes: string[]; fingerprint_sha256: string };
type Witness = { id: string; name: string; enabled: boolean; key_fingerprint_sha256: string };
type Policy = { id: string; source_id: string; version: number; signed_policy_snapshot: Record<string, unknown>; accepted_by: string };
type Ceremony = { id: string; source_id: string; status: "pending" | "executed" | "cancelled";
  signed_recovery_snapshot: Record<string, unknown>; execute_after: string; proposed_by: string };
type RecoveryEvent = { id: string; ceremony_id: string | null; recovery_policy_id: string; source_id: string;
  event_type: string; actor: string; occurred_at: string };
type Preview = { eligible: boolean; trustee_count: number; witness_count: number; required_approvals: number;
  required_witnesses: number; delay_hours: number; authorizes_execution: false };
const LIMIT = 262_144;
function json(text: string) {
  if (new TextEncoder().encode(text).length > LIMIT) throw new Error("Public JSON document exceeds 256 KiB");
  const value: unknown = JSON.parse(text);
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Use a JSON object");
  return value;
}
function download(value: unknown, name: string) {
  const url = URL.createObjectURL(new Blob([JSON.stringify(value, null, 2)], { type: "application/json" }));
  const anchor = document.createElement("a"); anchor.href = url; anchor.download = name; anchor.click();
  setTimeout(() => URL.revokeObjectURL(url), 0);
}
export default function PromotionRecoveryPage() {
  const [sources, setSources] = useState<Source[]>([]), [keys, setKeys] = useState<Key[]>([]);
  const [witnesses, setWitnesses] = useState<Witness[]>([]), [policies, setPolicies] = useState<Policy[]>([]);
  const [ceremonies, setCeremonies] = useState<Ceremony[]>([]), [events, setEvents] = useState<RecoveryEvent[]>([]);
  const [sourceId, setSourceId] = useState(""), [successor, setSuccessor] = useState("");
  const [trustees, setTrustees] = useState<string[]>([]), [witnessIds, setWitnessIds] = useState<string[]>([]);
  const [approvals, setApprovals] = useState("2"), [quorum, setQuorum] = useState("2");
  const [delay, setDelay] = useState("24"), [age, setAge] = useState("24"), [validity, setValidity] = useState("48");
  const [reason, setReason] = useState(""), [policyText, setPolicyText] = useState("");
  const [ceremonyText, setCeremonyText] = useState(""), [checkpointText, setCheckpointText] = useState("");
  const [preview, setPreview] = useState<Preview | null>(null), [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null), [message, setMessage] = useState<string | null>(null);
  const [recoveryClock, setRecoveryClock] = useState<number | null>(null);
  const load = useCallback(async () => {
    const [s, k, w, p, c, e] = await Promise.all([
      apiFetch<Source[]>("/capability-promotions/sources?limit=500"), apiFetch<Key[]>("/artifact-trust-keys"),
      apiFetch<Witness[]>("/transparency-witnessing/witnesses?limit=500"), apiFetch<Policy[]>("/capability-promotions/recovery-policies"),
      apiFetch<Ceremony[]>("/capability-promotions/key-recoveries"), apiFetch<RecoveryEvent[]>("/capability-promotions/recovery-events"),
    ]);
    setSources(s); setKeys(k); setWitnesses(w); setPolicies(p); setCeremonies(c); setEvents(e);
  }, []);
  useEffect(() => {
    const timer = window.setTimeout(() => {
      void load().catch((cause) => setError(cause instanceof Error ? cause.message : "Recovery load failed"));
    }, 0);
    return () => window.clearTimeout(timer);
  }, [load]);
  useEffect(() => {
    const tick = () => setRecoveryClock(Date.now());
    const timer = window.setTimeout(tick, 0);
    const interval = window.setInterval(tick, 1000);
    return () => { window.clearTimeout(timer); window.clearInterval(interval); };
  }, []);
  async function run(name: string, operation: () => Promise<void>) {
    setBusy(name); setError(null); setMessage(null);
    try { await operation(); await load(); } catch (cause) { setError(cause instanceof Error ? cause.message : "Recovery operation failed"); }
    finally { setBusy(null); }
  }
  async function post<T>(path: string, body: unknown) {
    const encoded = JSON.stringify(body);
    if (new TextEncoder().encode(encoded).length > LIMIT) throw new Error("Combined recovery request exceeds 256 KiB");
    return apiFetch<T>(path, { method: "POST", body: encoded });
  }
  const source = sources.find((item) => item.id === sourceId);
  const integer = (value: string, min: number, max: number) => value.trim() !== "" && Number.isInteger(Number(value)) && Number(value) >= min && Number(value) <= max;
  const reviewed = reason.trim().length >= 3;
  const policyReady = source?.enabled && trustees.length >= 2 && witnessIds.length >= 2
    && integer(approvals, 2, Math.min(8, trustees.length)) && integer(quorum, 2, Math.min(8, witnessIds.length))
    && integer(delay, 1, 72) && integer(age, 1, 168) && reviewed;
  const successorKey = keys.find((key) => key.id === successor && key.enabled
    && key.purposes.includes("environment_promotion") && key.id !== source?.trust_key_id);
  const incidentReady = Boolean(source && !source.enabled && successorKey && checkpointText.trim() && reviewed);
  const policyBody = { trustee_trust_key_ids: trustees, witness_ids: witnessIds, required_approvals: Number(approvals),
    required_witnesses: Number(quorum), delay_hours: Number(delay), max_evidence_age_hours: Number(age),
    validity_hours: 24, reason: reason.trim(), actor: "platform.admin" };
  const proposalBody = () => ({ new_trust_key_id: successor, signed_recovery: json(ceremonyText),
    checkpoint_evidence: json(checkpointText), reason: reason.trim(), actor: "platform.admin" });
  const selection = (value: string, checked: boolean, setter: Dispatch<SetStateAction<string[]>>) =>
    setter((current) => checked ? [...current, value] : current.filter((item) => item !== value));
  async function upload(event: ChangeEvent<HTMLInputElement>, setter: (value: string) => void) {
    const file = event.target.files?.[0]; if (!file) return;
    try { if (file.size > LIMIT) throw new Error("Public JSON file exceeds 256 KiB"); const text = await file.text(); json(text); setter(text); setPreview(null); setError(null); }
    catch (cause) { setError(cause instanceof Error ? cause.message : "Public document upload failed"); }
    finally { event.target.value = ""; }
  }
  return <main className="min-h-screen bg-[#eef0f4] p-5 lg:p-8">
    <header className="mb-5 flex flex-wrap items-center gap-3">
      <Link href="/studio/catalog/promotions" className="text-sm"><ArrowLeft className="mr-1 inline h-4 w-4" />Environment promotion</Link>
      <ShieldAlert className="h-6 w-6 shrink-0" /><div className="min-w-0 basis-full sm:basis-0 sm:flex-1"><h1 className="text-xl font-semibold">Emergency environment-key recovery</h1>
        <p className="text-sm text-[#59677b]">Pre-authorize → contain → review → wait → recover → witness restoration</p></div>
      <Button variant="outline" disabled={busy !== null} onClick={() => void run("refresh", async () => {})}><RefreshCw className="h-4 w-4" />Refresh</Button>
    </header>
    <p className="mb-4 text-sm">Private keys stay outside iCheck. Recovery changes only a disabled source&apos;s pin;
      it never publishes, deploys, executes capabilities or reenables the source automatically.</p>
    {error && <div role="alert" className="mb-4 break-words rounded border border-red-200 bg-red-50 p-3 text-sm">{error}</div>}
    {message && <div role="status" className="mb-4 break-words rounded border bg-white p-3 text-sm">{message}</div>}
    <div className="mb-4 grid gap-3 md:grid-cols-2">
      <label className="text-sm">Exact source<NativeSelect aria-label="Recovery source" value={sourceId} onChange={(event) => {
        setSourceId(event.target.value); setSuccessor(""); setPolicyText(""); setCeremonyText(""); setCheckpointText(""); setPreview(null);
      }}><NativeSelectOption value="">Select source</NativeSelectOption>{sources.map((item) => <NativeSelectOption key={item.id} value={item.id}>
        {item.name} · {item.enabled ? "enabled" : "contained"}</NativeSelectOption>)}</NativeSelect></label>
      <label className="text-sm">Review reason<Input aria-label="Recovery review reason" maxLength={4000} value={reason}
        onChange={(event) => setReason(event.target.value)} placeholder="Why approve this exact recovery decision?" /></label>
    </div>
    <section className="grid grid-cols-1 gap-4 xl:grid-cols-2 [&_button]:max-w-full [&_button]:whitespace-normal [&_button]:h-auto [&_button]:min-h-9 [&_button]:py-2" aria-label="Recovery configuration">
      <Card className="min-w-0"><CardHeader><CardTitle>Pre-incident authorization</CardTitle><CardDescription>
        The enabled current authority must sign this policy before compromise. Planned handover retires it.</CardDescription></CardHeader>
        <CardContent className="space-y-3">
          <Link className="text-sm underline" href="/studio/catalog/trust">Manage purpose-scoped public keys</Link>
          <p className="text-sm">Locally pinned recovery trustees</p>
          {keys.filter((key) => key.trust_source === "local" && key.purposes.includes("trust_recovery")).map((key) => <label key={key.id} className="flex items-center gap-2 text-xs">
            <input type="checkbox" disabled={busy !== null} aria-label={`Recovery trustee ${key.name}`} checked={trustees.includes(key.id)}
              onChange={(event) => selection(key.id, event.target.checked, setTrustees)} />
            <span className="break-all">{key.name} · {key.fingerprint_sha256.slice(0, 12)} · {key.enabled ? "enabled" : "disabled"}</span></label>)}
          <Link className="text-sm underline" href="/studio/catalog/transparency/witnesses">Manage independent witness pins</Link>
          {witnesses.map((witness) => <label key={witness.id} className="flex items-center gap-2 text-xs">
            <input type="checkbox" disabled={busy !== null} aria-label={`Recovery witness ${witness.name}`} checked={witnessIds.includes(witness.id)}
              onChange={(event) => selection(witness.id, event.target.checked, setWitnessIds)} />
            <span className="break-all">{witness.name} · {witness.key_fingerprint_sha256.slice(0, 12)} · {witness.enabled ? "enabled" : "disabled"}</span></label>)}
          <div className="grid grid-cols-2 gap-3">
            <label className="text-xs">Trustee quorum<Input aria-label="Recovery trustee quorum" type="number" min={2} max={8} value={approvals} onChange={(event) => setApprovals(event.target.value)} /></label>
            <label className="text-xs">Witness quorum<Input aria-label="Recovery witness quorum" type="number" min={2} max={8} value={quorum} onChange={(event) => setQuorum(event.target.value)} /></label>
            <label className="text-xs">Mandatory delay hours<Input aria-label="Recovery delay hours" type="number" min={1} max={72} value={delay} onChange={(event) => setDelay(event.target.value)} /></label>
            <label className="text-xs">Evidence age hours<Input aria-label="Recovery evidence age hours" type="number" min={1} max={168} value={age} onChange={(event) => setAge(event.target.value)} /></label>
          </div>
          <Button disabled={busy !== null || !policyReady} onClick={() => void run("policy-template", async () => {
            const statement = await post(`/capability-promotions/sources/${sourceId}/recovery-policy-statements`, policyBody);
            download(statement, "icheck-promotion-recovery-policy-statement.json"); setMessage("Sign this policy with the current authority outside iCheck.");
          })}>Export recovery policy statement</Button>
          <Input type="file" aria-label="Upload signed recovery policy" accept=".json,application/json" disabled={busy !== null} onChange={(event) => void upload(event, setPolicyText)} />
          <Textarea aria-label="Signed recovery policy" className="min-h-28 font-mono text-xs" placeholder="Paste the externally signed policy JSON, never a private key"
            value={policyText} onChange={(event) => setPolicyText(event.target.value)} />
          <Button disabled={busy !== null || !source?.enabled || !reviewed || !policyText.trim()} onClick={() => void run("policy", async () => {
            await post(`/capability-promotions/sources/${sourceId}/recovery-policies`, { trustee_trust_key_ids: trustees, witness_ids: witnessIds,
              signed_policy: json(policyText), reason: reason.trim(), actor: "platform.admin" }); setMessage("Signed pre-incident recovery policy accepted. No key pin changed.");
          })}>Authorize signed recovery policy</Button>
          {policies.filter((policy) => policy.source_id === sourceId).slice(0, 5).map((policy) => <div key={policy.id} className="break-words rounded border p-3 text-xs">
            Policy {policy.version} · {policy.accepted_by} · {events.some((event) => event.recovery_policy_id === policy.id && event.event_type === "policy_retired") ? "retired" : "recorded"}
            <Button size="sm" variant="outline" className="mt-2" onClick={() => download(policy.signed_policy_snapshot, `icheck-recovery-policy-${policy.id}.json`)}>Export recorded policy</Button></div>)}
        </CardContent></Card>
      <Card className="min-w-0"><CardHeader><CardTitle>Contained incident ceremony</CardTitle><CardDescription>
        Disable the source first. The successor and pre-authorized trustee quorum sign the same statement.</CardDescription></CardHeader>
        <CardContent className="space-y-3">
          <NativeSelect aria-label="Recovery successor" value={successor} onChange={(event) => { setSuccessor(event.target.value); setPreview(null); setCeremonyText(""); }}>
            <NativeSelectOption value="">Select independent successor</NativeSelectOption>{keys.filter((key) => key.enabled && key.purposes.includes("environment_promotion") && key.id !== source?.trust_key_id)
              .map((key) => <NativeSelectOption key={key.id} value={key.id}>{key.name} · {key.fingerprint_sha256.slice(0, 12)}</NativeSelectOption>)}</NativeSelect>
          <Button variant="outline" disabled={busy !== null || !source?.enabled || !reviewed} onClick={() => void run("contain", async () => {
            await post(`/capability-promotions/sources/${sourceId}/state`, { enabled: false, reason: reason.trim(), actor: "platform.admin" });
            setMessage("Source contained. Obtain independently witnessed checkpoint evidence before recovery."); setPreview(null);
          })}>Contain selected source</Button>
          <Input type="file" aria-label="Upload recovery checkpoint evidence" accept=".json,application/json" disabled={busy !== null} onChange={(event) => void upload(event, setCheckpointText)} />
          <Textarea aria-label="Recovery checkpoint evidence" className="min-h-28 font-mono text-xs" placeholder="Current local checkpoint gossip exported by independent witnesses"
            value={checkpointText} onChange={(event) => { setCheckpointText(event.target.value); setPreview(null); }} />
          <label className="block text-xs">Ceremony lifetime hours<Input aria-label="Recovery ceremony lifetime hours" type="number" min={2} max={168}
            value={validity} onChange={(event) => setValidity(event.target.value)} /></label>
          <Button disabled={busy !== null || !incidentReady || !integer(validity, 2, 168)} onClick={() => void run("ceremony-template", async () => {
            const statement = await post(`/capability-promotions/sources/${sourceId}/key-recovery-statements`, {
              new_trust_key_id: successor, checkpoint_evidence: json(checkpointText), validity_hours: Number(validity), reason: reason.trim(), actor: "platform.admin" });
            download(statement, "icheck-promotion-key-recovery-statement.json"); setMessage("Obtain the successor and trustee signatures outside iCheck.");
          })}>Export incident recovery statement</Button>
          <Input type="file" aria-label="Upload signed recovery ceremony" accept=".json,application/json" disabled={busy !== null} onChange={(event) => void upload(event, setCeremonyText)} />
          <Textarea aria-label="Signed recovery ceremony" className="min-h-28 font-mono text-xs" placeholder="Externally signed successor and trustee ceremony JSON"
            value={ceremonyText} onChange={(event) => { setCeremonyText(event.target.value); setPreview(null); }} />
          <div className="flex flex-wrap gap-2">
            <Button variant="outline" disabled={busy !== null || !incidentReady || !ceremonyText.trim()} onClick={() => void run("preview", async () => {
              setPreview(await post<Preview>(`/capability-promotions/sources/${sourceId}/key-recoveries/preview`, proposalBody()));
              setMessage("Proposal preview verified. It grants no execution authority.");
            })}>Verify proposal</Button>
            <Button disabled={busy !== null || !incidentReady || !preview?.eligible} onClick={() => void run("propose", async () => {
              await post(`/capability-promotions/sources/${sourceId}/key-recoveries`, proposalBody()); setPreview(null);
              setMessage("Recovery proposed. Wait for the mandatory delay and obtain a new witnessed checkpoint for a different executor.");
            })}>Propose reviewed recovery</Button>
          </div>
          {preview && <p className="text-xs">Trustees {preview.trustee_count}/{preview.required_approvals} · Witnesses {preview.witness_count}/{preview.required_witnesses}
            {" · "}Mandatory delay {preview.delay_hours} {preview.delay_hours === 1 ? "hour" : "hours"} · No execution authorized</p>}
        </CardContent></Card>
    </section>
    <Card className="mt-4"><CardHeader><CardTitle>Recovery ceremony ledger</CardTitle><CardDescription>
      Execution needs a different authenticated operator and a fresh checkpoint covering proposal. Restoration needs another checkpoint covering execution.</CardDescription></CardHeader>
      <CardContent className="space-y-3">
        {ceremonies.filter((ceremony) => !sourceId || ceremony.source_id === sourceId).map((ceremony) => <div key={ceremony.id} className="rounded border p-3 text-sm">
          <p className="break-all">{sources.find((item) => item.id === ceremony.source_id)?.name || ceremony.source_id} · {ceremony.status} · {ceremony.proposed_by}</p>
          <p className="text-xs">Earliest execution {new Date(ceremony.execute_after).toLocaleString()}</p>
          <div className="mt-2 flex flex-wrap gap-2">
            <Button size="sm" variant="outline" onClick={() => download(ceremony.signed_recovery_snapshot, `icheck-recovery-${ceremony.id}.json`)}>Export recorded ceremony</Button>
            <Button size="sm" variant="outline" onClick={() => download(events.filter((item) => item.ceremony_id === ceremony.id), `icheck-recovery-events-${ceremony.id}.json`)}>Export lifecycle evidence</Button>
            {ceremony.status === "pending" && <>
              <Button size="sm" disabled={busy !== null || !reviewed || !checkpointText.trim() || recoveryClock === null || !Number.isFinite(Date.parse(ceremony.execute_after)) || recoveryClock < Date.parse(ceremony.execute_after)} onClick={() => void run("execute", async () => {
                await post(`/capability-promotions/key-recoveries/${ceremony.id}/execute`, { checkpoint_evidence: json(checkpointText), reason: reason.trim(), actor: "platform.admin" });
                setMessage("Key pin recovered. Source remains contained; obtain a checkpoint covering execution before restoration.");
              })}>Execute delayed recovery</Button>
              <Button size="sm" variant="outline" disabled={busy !== null || !reviewed} onClick={() => void run("cancel", async () => {
                await post(`/capability-promotions/key-recoveries/${ceremony.id}/cancel`, { reason: reason.trim(), actor: "platform.admin" }); setMessage("Recovery cancelled; original signed evidence remains sealed.");
              })}>Cancel ceremony</Button>
            </>}
            {ceremony.status === "executed" && !sources.find((item) => item.id === ceremony.source_id)?.enabled && <Button size="sm" disabled={busy !== null || !reviewed || !checkpointText.trim()}
              onClick={() => void run("restore", async () => { await post(`/capability-promotions/sources/${ceremony.source_id}/state`, {
                enabled: true, checkpoint_evidence: json(checkpointText), reason: reason.trim(), actor: "platform.admin" });
                setMessage("Independently witnessed source restoration completed. No capability was published or executed.");
              })}>Restore witnessed source</Button>}
          </div>
          {events.filter((item) => item.ceremony_id === ceremony.id).map((event) => <p key={event.id} className="mt-2 break-all text-xs">{event.event_type} · {event.actor} · {new Date(event.occurred_at).toLocaleString()}</p>)}
        </div>)}
        {ceremonies.length === 0 && <p className="text-sm">No recovery ceremonies proposed.</p>}
      </CardContent></Card>
  </main>;
}
