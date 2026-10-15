"use client";
import {FormEvent, useEffect, useState} from "react";
import Link from "next/link";
import {apiFetch} from "@/lib/icheck-api";
import {Button} from "@/components/ui/button";
import {Input} from "@/components/ui/input";

type Credential = {id: string; name: string; site: string; kind: string; enabled: boolean};

export function DeviceNativeSSH({device, onSaved}: {device: {id: string; revision: number; site: string | null; enabled: boolean};
  onSaved: () => Promise<void>}) {
  const [profiles, setProfiles] = useState<Credential[]>([]), [reference, setReference] = useState("");
  const [port, setPort] = useState(22), [approved, setApproved] = useState(false), [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  useEffect(() => {
    let cancelled = false;
    void apiFetch<Credential[]>("/device-credentials").then(rows => {
      if (!cancelled) setProfiles(rows.filter(row => row.enabled && row.kind === "ssh_password" && (!device.site || row.site === device.site)));
    }).catch(() => {if (!cancelled) setMessage("Credential references could not be loaded. Check access to Device credentials.");});
    return () => {cancelled = true;};
  }, [device.id, device.site]);
  async function save(event: FormEvent) {
    event.preventDefault(); if (busy || !approved || !reference) return;
    setBusy(true); setMessage("");
    try {
      await apiFetch(`/assets/devices/${device.id}/native-ssh`, {method: "POST", body: JSON.stringify({
        expected_revision: device.revision, port, credential_profile_ref: reference})});
      await onSaved();
    } catch (cause) {setMessage(cause instanceof Error ? cause.message : "SSH registration failed. Refresh the device before retrying.");}
    finally {setBusy(false); setApproved(false);}
  }
  return <details className="mb-4 rounded border p-4 text-sm"><summary className="cursor-pointer font-semibold">Add SSH for native MCP tools</summary>
    <p className="mt-3">Save shared device access without contacting this device or queueing a Collector check. MCP tools reuse this connection when called.</p>
    <p className="mt-2 text-xs">{device.site ? `Choose a saved SSH credential for ${device.site}.` : "Choose a saved SSH credential. Its connection scope is retained without assigning a physical site to this device."} <Link className="text-violet-700 underline" href="/settings/credentials">Manage credentials</Link>; no need to re-enter a saved password.</p>
    <form onSubmit={event => void save(event)} className="mt-3 space-y-3" aria-label="Register native SSH">
      <fieldset disabled={busy || !device.enabled} className="grid gap-3 sm:grid-cols-2">
        <label>SSH port<Input required type="number" min={1} max={65535} value={port} onChange={event => {setPort(Number(event.target.value)); setApproved(false);}} /></label>
        <label>SSH credential<select required className="mt-1 block w-full rounded border bg-white p-2" value={reference}
          onChange={event => {setReference(event.target.value); setApproved(false);}}><option value="">Choose a saved SSH password</option>
          {profiles.map(row => <option key={row.id} value={row.id}>{row.name} · {row.site}</option>)}</select></label>
      </fieldset>
      <label className="flex items-start gap-2"><input type="checkbox" checked={approved} disabled={busy || !reference || !device.enabled} onChange={event => setApproved(event.target.checked)} />Save this SSH connection. Review its fingerprint in device settings before first use.</label>
      <Button type="submit" disabled={busy || !approved || !reference || !device.enabled}>{busy ? "Registering…" : "Register SSH without connecting"}</Button>
    </form>
    {message && <p role="alert" className="mt-3 text-red-700">{message}</p>}
  </details>;
}
