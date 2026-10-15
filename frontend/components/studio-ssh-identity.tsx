"use client";

import {useEffect, useRef, useState} from "react";
import {apiFetch} from "@/lib/icheck-api";
import {Button} from "@/components/ui/button";

type Identity = {state: "confirmed" | "unconfirmed" | "target_changed" | "first_use" | "matches" | "changed";
  host: string; port: number; fingerprint: string | null; saved_fingerprint: string | null;
  host_public_key: string | null; binding_hash: string;
  ssh_profile: "modern" | "legacy_cisco_v1"; ssh_profile_current: boolean};

export function StudioSSHIdentity({connection, disabled, onConfirmed}: {connection: string; disabled: boolean;
  onConfirmed: (key: string, invalidateTests?: boolean, bindingHash?: string) => void}) {
  const [identity, setIdentity] = useState<Identity | null>(null);
  const [profile, setProfile] = useState<Identity["ssh_profile"]>("modern"), [legacyApproved, setLegacyApproved] = useState(false);
  const [busy, setBusy] = useState(false), [approved, setApproved] = useState(false), [error, setError] = useState("");
  const epoch = useRef(0);
  const base = `/capability-studio/extensions/targets/${encodeURIComponent(connection)}/identity`;
  const accept = (result: Identity) => {
    setIdentity(result); setApproved(false); setProfile(result.ssh_profile); setLegacyApproved(false);
    onConfirmed(result.ssh_profile_current && ["confirmed", "matches"].includes(result.state) ? result.host_public_key || "" : "", false, result.binding_hash);
  };
  useEffect(() => {
    const current = ++epoch.current;
    if (!connection) return;
    void apiFetch<Identity>(base).then(result => {
      if (epoch.current === current) {setIdentity(result); setProfile(result.ssh_profile); onConfirmed(result.ssh_profile_current && result.state === "confirmed" ? result.host_public_key || "" : "", false, result.binding_hash);}
    }).catch(cause => {if (epoch.current === current) setError(cause instanceof Error ? cause.message : "Unable to read saved SSH identity");});
    return () => {epoch.current++;};
  }, [base, connection, onConfirmed]);
  async function request(confirm: boolean) {
    if (busy || disabled || !connection || (confirm && (!approved || !identity?.host_public_key))) return;
    const current = ++epoch.current;
    setBusy(true); setError(""); onConfirmed("");
    try {
      const result = await apiFetch<Identity>(base + (confirm ? "/confirm" : "/probe"), {method: "POST",
        body: JSON.stringify(confirm ? {binding_hash: identity!.binding_hash, host_public_key: identity!.host_public_key,
          accept_changed: identity!.state === "changed"} : {})});
      if (current === epoch.current) {
        if (confirm) onConfirmed(result.host_public_key || "", true);
        accept(result);
      }
    } catch (cause) {if (current === epoch.current) {setApproved(false); setError(cause instanceof Error ? cause.message : "Unable to review SSH identity");}}
    finally {if (current === epoch.current) setBusy(false);}
  }
  async function saveProfile() {
    if (disabled || busy || !identity || (profile === "legacy_cisco_v1" && !legacyApproved)) return;
    const current = ++epoch.current;
    setBusy(true); setError(""); onConfirmed("", true); setApproved(false);
    try {
      const result = await apiFetch<Identity>(base + "/compatibility", {method: "POST", body: JSON.stringify({
        binding_hash: identity.binding_hash, profile, accept_legacy_risk: profile === "legacy_cisco_v1" && legacyApproved})});
      if (current === epoch.current) accept(result);
    } catch (cause) {if (current === epoch.current) setError(cause instanceof Error ? cause.message : "Unable to save SSH profile");}
    finally {if (current === epoch.current) setBusy(false);}
  }
  const profilePending = !!identity && (profile !== identity.ssh_profile || !identity.ssh_profile_current);
  const changed = identity?.state === "changed" || identity?.state === "target_changed";
  const needsConfirmation = identity?.state === "first_use" || identity?.state === "changed";
  return <div className="space-y-3">
    <p className="text-slate-500">Your saved credential handles login. First, confirm the device’s identity once. Reading its fingerprint performs an SSH handshake only: no username, password or command is sent.</p>
    {!connection && <p>Choose a device above to review its identity.</p>}
    {identity && <fieldset disabled={disabled || busy} className="space-y-3 rounded-lg border p-3">
      <legend className="px-1 font-medium">SSH compatibility for this device</legend>
      <label className="block text-sm" htmlFor={`ssh-profile-${connection}`}>Connection profile</label>
      <select id={`ssh-profile-${connection}`} value={profile} className="w-full min-w-0 rounded border p-2" onChange={event => {
        setProfile(event.target.value as Identity["ssh_profile"]); setLegacyApproved(false); setApproved(false); onConfirmed("", true);
      }}>
        <option value="modern">Modern SSH (default)</option>
        <option value="legacy_cisco_v1">Legacy Cisco — group14 / SHA-1</option>
      </select>
      <p className="text-xs">Saved: {identity.ssh_profile === "legacy_cisco_v1" ? "Legacy Cisco" : "Modern SSH"}. Applies only to this device’s native MCP SSH connection, not other devices or collectors.</p>
      {!identity.ssh_profile_current && <p role="alert" className="text-amber-900">The target changed. Review and save this profile again before connecting.</p>}
      {profile === "legacy_cisco_v1" && <div className="space-y-2 rounded bg-amber-50 p-3 text-sm text-amber-950">
        <p>For older Cisco switches: allows DH group14/SHA-1, RSA/SHA-1 host signatures, AES-CBC and HMAC-SHA1. These offer weaker protection. Modern algorithms are preferred when available. Group1, DSA, 3DES and MD5 are not enabled.</p>
        <p>Host-key verification remains required. This does not change the switch or relax other devices.</p>
        {profilePending && <label className="flex items-start gap-2"><input type="checkbox" checked={legacyApproved} onChange={event => setLegacyApproved(event.target.checked)} />I accept legacy SSH risk for this device only.</label>}
      </div>}
      {profilePending && <><p className="text-xs">Saving invalidates earlier tool tests and installation bindings. Test both tools again before installing or updating this server.</p>
        <Button disabled={disabled || busy || (profile === "legacy_cisco_v1" && !legacyApproved)} onClick={() => void saveProfile()}>Save SSH profile</Button></>}
    </fieldset>}
    {identity && <div className={`space-y-2 rounded-lg p-3 ${changed ? "bg-amber-50 text-amber-950" : "bg-slate-50"}`}>
      <p className="font-medium">{changed ? "SSH identity changed — review required" : ["confirmed", "matches"].includes(identity.state) ? "Saved device identity" : "First connection — identity not yet trusted"}</p>
      <p>{identity.host}:{identity.port}</p>
      {changed && identity.saved_fingerprint && <p className="break-all text-xs">Previously saved: {identity.saved_fingerprint}</p>}
      {identity.fingerprint && <p className="break-all font-mono text-xs">{identity.fingerprint}</p>}
      {changed && <p>The key or target changed. Do not accept a replacement unless you recognize the change. Existing tests and installations may need to be reviewed again.</p>}
      {identity.state === "confirmed" && <p className="text-xs">This identity will be checked on every tool connection. You do not need to paste a public key.</p>}
    </div>}
    <Button variant="outline" disabled={disabled || busy || !connection || profilePending} onClick={() => void request(false)}>{busy ? "Checking identity…" : "Read device fingerprint"}</Button>
    {needsConfirmation && <><p className="text-xs">A first-use fingerprint is not independent proof of ownership. Compare it with a trusted device record when available; only confirm if you trust this first connection to the selected device.</p>
      <label className="flex items-start gap-2"><input type="checkbox" checked={approved} disabled={disabled || busy} onChange={event => setApproved(event.target.checked)} />{changed ? "I recognize this identity change and trust the replacement fingerprint." : "I recognize this device and trust the displayed fingerprint for this first connection."}</label>
      <Button disabled={disabled || busy || !approved || profilePending || !!error} onClick={() => void request(true)}>Confirm and save fingerprint</Button></>}
    {error && <p role="alert" className="text-red-700">{error}</p>}
  </div>;
}
