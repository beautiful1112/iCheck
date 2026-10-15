"use client";

import {useEffect, useRef, useState} from "react";
import {apiBlob} from "@/lib/icheck-api";
import {backupDownloadPath, investigationBackups, type BackupReceipt} from "@/lib/configuration-backups";
import {Button} from "@/components/ui/button";

export function ProtectedBackupDownload({receipt, canDownload}: {receipt: BackupReceipt; canDownload: boolean}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const epoch = useRef(0);
  useEffect(() => {epoch.current++; return () => {epoch.current++;};}, [receipt.backup_id, canDownload]);
  async function download() {
    if (busy || !canDownload) return;
    const current = epoch.current;
    setBusy(true); setError(null);
    try {
      const {blob} = await apiBlob(backupDownloadPath(receipt));
      if (current !== epoch.current) return;
      if (blob.size !== receipt.bytes) throw new Error("Backup receipt size mismatch");
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = `configuration-${receipt.backup_id}.txt`;
      anchor.click();
      window.setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch {
      if (current === epoch.current) setError("Backup could not be downloaded. Check your current workspace and device access, then retry.");
    } finally {setBusy(false);}
  }
  return <div className="mt-2 space-y-2">
    <Button size="sm" variant="outline" disabled={!canDownload || busy} onClick={() => void download()}>
      {busy ? "Downloading…" : "Download protected backup"}
    </Button>
    {!canDownload ? <p className="text-xs text-muted-foreground">Download requires device-read and capability-management permission.</p> : null}
    {error ? <p role="alert" className="text-xs text-red-700">{error}</p> : null}
  </div>;
}

export function ConfigurationBackups({investigationId, calls, evidence, canDownload}: {
  investigationId: string; calls: Parameters<typeof investigationBackups>[1];
  evidence: Parameters<typeof investigationBackups>[2]; canDownload: boolean;
}) {
  const backups = investigationBackups(investigationId, calls, evidence);
  if (!backups.length) return null;
  return <aside aria-label="Configuration backups" className="mt-4 rounded-xl border border-sky-200 bg-sky-50 p-4 text-sm">
    <h4 className="font-semibold">Configuration backups</h4>
    <p className="mt-1 text-xs text-muted-foreground">Recorded snapshots, not current device state. Contents stay out of chat; each download checks your current access. Downloading does not restore a device.</p>
    <ul className="mt-3 space-y-3">{backups.map(({receipt, deviceId, toolName}) => <li key={receipt.backup_id} className="rounded border border-sky-200 bg-white p-3">
      <p className="break-all font-medium">{toolName}</p>
      <p className="mt-1 text-xs">Saved <time dateTime={receipt.created_at}>{new Date(receipt.created_at).toLocaleString()}</time> · {receipt.bytes.toLocaleString()} bytes</p>
      <p className="mt-1 break-all text-xs">Device: {deviceId}</p>
      <ProtectedBackupDownload receipt={receipt} canDownload={canDownload} />
      <details className="mt-2 text-xs"><summary className="cursor-pointer">Backup receipt</summary>
        <p className="mt-1 break-all">ID: {receipt.backup_id}</p><p className="break-all">SHA-256: {receipt.sha256}</p></details>
    </li>)}</ul>
  </aside>;
}
