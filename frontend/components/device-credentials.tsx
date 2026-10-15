"use client";
import { FormEvent, useCallback, useEffect, useRef, useState } from "react";
import { apiFetch, NAMESPACE_KEY, SESSION_CHANGE_KEY } from "@/lib/icheck-api";

type Kind = "snmp_v2c" | "windows_password" | "https_token" | "http_basic" | "ssh_password" | "ssh_key";
type Profile = { id: string; name: string; kind: Kind; site: string; revision: number; enabled: boolean };
const kinds: Array<[Kind, string]> = [["snmp_v2c", "SNMPv2c community"], ["windows_password", "Windows / WMI (WinRM HTTPS)"],
  ["https_token", "HTTPS bearer / API token"], ["http_basic", "HTTPS API username / password"], ["ssh_password", "SSH username / password"], ["ssh_key", "SSH private key"]];
const control = "w-full rounded-md border border-slate-300 bg-white px-3 py-2 text-sm disabled:bg-slate-100";

export function DeviceCredentials({ onSaved }: { onSaved?: () => void }) {
  const [profiles, setProfiles] = useState<Profile[]>([]);
  const [ready, setReady] = useState(false);
  const [kind, setKind] = useState<Kind>("snmp_v2c");
  const [name, setName] = useState(""); const [site, setSite] = useState("LAB");
  const [username, setUsername] = useState(""); const [secret, setSecret] = useState("");
  const [passphrase, setPassphrase] = useState(""); const [reason, setReason] = useState("");
  const [editing, setEditing] = useState<Profile | null>(null);
  const [busy, setBusy] = useState(false); const [message, setMessage] = useState("");
  const [secure, setSecure] = useState(false);
  const epoch = useRef(0);
  const clearSecrets = useCallback(() => { setSecret(""); setPassphrase(""); setUsername(""); }, []);
  const load = useCallback(async () => {
    const current = epoch.current;
    try {
      const [status, rows] = await Promise.all([apiFetch<{ storage_ready: boolean }>("/device-credentials/status"), apiFetch<Profile[]>("/device-credentials")]);
      if (current !== epoch.current) return;
      setReady(status.storage_ready); setProfiles(rows);
    } catch (error) { setMessage(error instanceof Error ? error.message : "Unable to load credentials"); }
  }, []);
  useEffect(() => {
    const initial = window.setTimeout(() => {
      setSecure(window.location.protocol === "https:" || ["localhost", "127.0.0.1", "[::1]"].includes(window.location.hostname));
      void load();
    }, 0);
    const reset = () => { epoch.current += 1; clearSecrets(); setProfiles([]); setEditing(null); setName(""); setMessage(""); setBusy(false); setReason(""); setReady(false); void load(); };
    const storage = (event: StorageEvent) => { if (event.key === NAMESPACE_KEY || event.key === SESSION_CHANGE_KEY || event.key === null) reset(); };
    window.addEventListener("icheck:namespace-changed", reset);
    window.addEventListener("storage", storage);
    return () => { epoch.current += 1; window.clearTimeout(initial); window.removeEventListener("icheck:namespace-changed", reset); window.removeEventListener("storage", storage); };
  }, [clearSecrets, load]);
  async function save(event: FormEvent) {
    event.preventDefault();
    if (!secure || !ready) { clearSecrets(); setMessage("Use HTTPS and provisioned managed credential storage."); return; }
    const current = epoch.current;
    setBusy(true); setMessage("");
    const field = kind === "snmp_v2c" ? "community" : kind === "https_token" ? "token" : kind === "ssh_key" ? "private_key" : "password";
    const payload = { name, site, kind, [field]: secret,
      ...(["windows_password", "http_basic", "ssh_password", "ssh_key"].includes(kind) ? { username } : {}),
      ...(kind === "ssh_key" && passphrase ? { private_key_passphrase: passphrase } : {}),
      ...(editing ? { expected_revision: editing.revision, enabled: true, reason } : {}) };
    clearSecrets(); // Never retain submitted secrets for a retry or in browser storage.
    try {
      await apiFetch(editing ? `/device-credentials/${editing.id}` : "/device-credentials", {
        method: editing ? "PUT" : "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(payload) });
      if (current !== epoch.current) return;
      setEditing(null); setName(""); setReason(""); setMessage("Credential saved securely. Use its profile name in AI conversations or select it on Devices.");
      await load(); onSaved?.();
    } catch (error) { setMessage(error instanceof Error ? error.message : "Credential save failed; enter the secret again"); }
    finally { if (current === epoch.current) setBusy(false); }
  }
  async function revoke(p: Profile) {
    if (!reason.trim()) { setMessage("Enter a reason before revoking a credential."); return; }
    setBusy(true); clearSecrets();
    try {
      await apiFetch(`/device-credentials/${p.id}/revoke`, { method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ expected_revision: p.revision, reason }) });
      setMessage("Credential revoked. Future credential leases are denied."); await load(); onSaved?.();
    } catch (error) { setMessage(error instanceof Error ? error.message : "Unable to revoke credential"); }
    finally { setBusy(false); }
  }
  return <section className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
    <h2 className="text-lg font-semibold">Secure device credentials</h2>
    <p className="mt-2 text-sm text-slate-600">Enter secrets here, never in AI chat. Values are encrypted, write-only and site-scoped. AI sees profile names and IDs only.</p>
    {!ready && <p role="status" className="mt-3 text-sm text-amber-800">Managed storage is unavailable or still loading. No credentials can be saved.</p>}
    {message && <p role="status" className="mt-3 text-sm">{message}</p>}
    <form onSubmit={save} autoComplete="off" className="mt-5 grid gap-4 sm:grid-cols-2">
      <label className="space-y-1 text-sm">Credential type<select className={control} value={kind} disabled={!!editing || busy}
        onChange={e => { setKind(e.target.value as Kind); clearSecrets(); }}>{kinds.map(([value, label]) => <option key={value} value={value}>{label}</option>)}</select></label>
      <label className="space-y-1 text-sm">Profile name<input required className={control} value={name} disabled={!!editing || busy} placeholder="lab-snmp-ro" onChange={e => setName(e.target.value)} pattern={"[A-Za-z0-9][A-Za-z0-9_.\\-]*"} /></label>
      <label className="space-y-1 text-sm">Site scope<input required className={control} value={site} disabled={!!editing || busy} onChange={e => setSite(e.target.value)} /></label>
      {["windows_password", "http_basic", "ssh_password", "ssh_key"].includes(kind) && <label className="space-y-1 text-sm">Username<input required className={control} value={username} disabled={busy} autoComplete="off" onChange={e => setUsername(e.target.value)} placeholder={kind === "windows_password" ? "DOMAIN\\monitoring" : "monitoring"} /></label>}
      <label className="space-y-1 text-sm sm:col-span-2">{kind === "snmp_v2c" ? "SNMP community" : kind === "https_token" ? "API token" : kind === "ssh_key" ? "Private key (never displayed after saving)" : "Password"}
        {kind === "ssh_key" ? <textarea required className={control} rows={5} value={secret} disabled={busy} spellCheck={false} onChange={e => setSecret(e.target.value)} />
          : <input required type="password" autoComplete="new-password" className={control} value={secret} disabled={busy} onChange={e => setSecret(e.target.value)} />}</label>
      {kind === "ssh_key" && <label className="space-y-1 text-sm">Key passphrase (optional)<input type="password" autoComplete="new-password" className={control} value={passphrase} disabled={busy} onChange={e => setPassphrase(e.target.value)} /></label>}
      <label className="space-y-1 text-sm sm:col-span-2">Rotation / revocation reason<input required={!!editing} className={control} value={reason} onChange={e => setReason(e.target.value)} /></label>
      <div className="flex flex-wrap gap-3 sm:col-span-2"><button disabled={busy || !ready || !secure} className="rounded-md bg-violet-600 px-4 py-2 text-sm font-medium text-white disabled:opacity-50">{editing ? "Replace credential and enable" : "Save secure credential"}</button>
        {editing && <button type="button" className="text-sm underline" onClick={() => { setEditing(null); setName(""); clearSecrets(); }}>Cancel rotation</button>}</div>
    </form>
    <p className="mt-4 text-xs text-slate-500">SNMPv2c community authentication is supported here. Windows credentials are for fixed read-only WMI/CIM queries over WinRM HTTPS, not legacy DCOM. SSH host-key verification and HTTPS certificate validation remain required. Saving a credential does not configure the device or activate collection.</p>
    <div className="mt-5 space-y-3">{profiles.map(p => <div key={p.id} className="flex flex-wrap items-center justify-between gap-3 rounded-lg border p-3">
      <div><p className="font-medium">{p.name}</p><p className="text-xs text-slate-500">{p.kind} · {p.site} · revision {p.revision} · {p.enabled ? "enabled" : "revoked"}</p></div>
      <div className="flex gap-3"><button type="button" disabled={busy} className="text-sm text-violet-700 underline" onClick={() => { clearSecrets(); setEditing(p); setName(p.name); setSite(p.site); setKind(p.kind); }}>Rotate</button>
        <button type="button" disabled={busy || !p.enabled} className="text-sm text-red-700 underline disabled:opacity-40" onClick={() => void revoke(p)}>Revoke</button></div>
    </div>)}</div>
  </section>;
}
