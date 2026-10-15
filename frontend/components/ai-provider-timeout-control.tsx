"use client";

import { FormEvent, useEffect, useRef, useState } from "react";
import { apiFetch, NAMESPACE_KEY, SESSION_CHANGE_KEY } from "@/lib/icheck-api";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";

export function AIProviderTimeoutControl({ providerId, timeoutSeconds, connectionRevision, disabled = false, onChanged }: {
  providerId: string; timeoutSeconds: number; connectionRevision?: number; disabled?: boolean; onChanged: () => Promise<void>;
}) {
  const [edit, setEdit] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [failed, setFailed] = useState(false);
  const epoch = useRef(0);
  const value = edit ?? String(timeoutSeconds);
  const parsed = Number(value);
  const valid = Number.isInteger(parsed) && parsed >= 1 && parsed <= 120;
  useEffect(() => {
    const invalidate = () => { epoch.current++; };
    const reset = () => { invalidate(); setEdit(null); setBusy(false); setMessage(""); };
    const storage = (event: StorageEvent) => { if (event.key === NAMESPACE_KEY || event.key === SESSION_CHANGE_KEY || event.key === null) reset(); };
    window.addEventListener("icheck:namespace-changed", reset); window.addEventListener("storage", storage);
    return () => { invalidate(); window.removeEventListener("icheck:namespace-changed", reset); window.removeEventListener("storage", storage); };
  }, []);
  async function save(event: FormEvent) {
    event.preventDefault();
    if (busy || disabled || !valid || parsed === timeoutSeconds) return;
    const current = epoch.current;
    setBusy(true); setMessage("");
    try {
      await apiFetch(`/ai/providers/${providerId}/runtime-settings`, {
        method: "PUT", headers: { "content-type": "application/json" },
        body: JSON.stringify({ expected_request_timeout_seconds: timeoutSeconds, request_timeout_seconds: parsed,
          ...(connectionRevision !== undefined ? { expected_connection_revision: connectionRevision } : {}) }),
      });
      if (current !== epoch.current) return;
      setEdit(null); setFailed(false);
      setMessage(`Model-call timeout saved: ${parsed}s. Keys, outbound approval and routes are unchanged; no AI call was made.`);
      await onChanged();
    } catch (error) {
      if (current === epoch.current) { setFailed(true); setMessage(error instanceof Error ? error.message : "Unable to save provider timeout"); }
    } finally { if (current === epoch.current) setBusy(false); }
  }
  return <form onSubmit={event => void save(event)} className="mt-3 space-y-2">
    <label className="grid gap-1.5 text-sm font-medium">Model-call timeout (seconds)
      <Input type="number" required min={1} max={120} step={1} value={value} disabled={busy || disabled}
        onChange={event => { setEdit(event.target.value); setMessage(""); }} />
    </label>
    <p className="text-xs leading-5 text-muted-foreground">1–120 seconds per model attempt. The task budget and worker lease may shorten it. A longer task budget does not change this setting; 120s is the guided default for external reasoning models.</p>
    <Button type="submit" variant="outline" className="h-auto min-h-9 max-w-full whitespace-normal border-[#b1b7c1] bg-white py-2 text-[#2c384a]" disabled={busy || disabled || !valid || parsed === timeoutSeconds}>Save model-call timeout</Button>
    {message && <p role={failed ? "alert" : "status"} className={`text-sm ${failed ? "text-red-800" : "text-green-800"}`}>{message}</p>}
  </form>;
}
