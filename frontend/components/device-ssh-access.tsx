"use client";
import {useCallback} from "react";
import {StudioSSHIdentity} from "@/components/studio-ssh-identity";

export function DeviceSSHAccess({connection}: {connection: string}) {
  const confirmed = useCallback(() => {}, []);
  return <details className="mt-3 rounded border p-3 text-sm"><summary className="cursor-pointer font-medium">Device access · SSH identity and compatibility</summary>
    <p className="my-3 text-xs text-slate-500">Shared by all tools that use this device. This is independent of installing an MCP server.</p>
    <StudioSSHIdentity key={connection} connection={connection} disabled={false} onConfirmed={confirmed} />
  </details>;
}
